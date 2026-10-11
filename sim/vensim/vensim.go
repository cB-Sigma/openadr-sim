// Package vensim is an in-process OpenADR VEN for tests. As a 2.0b VEN
// it registers with a VTN over simple HTTP (mutual TLS with the OpenADR
// cipher suites when given a certificate), announces telemetry reports,
// polls or receives pushed messages (events, report requests, registration
// changes), opts in, and sends telemetry and opt schedules. As a 2.0a VEN
// (Config.Profile "2.0a") it has no registration: it asks for events with
// oadrRequestEvent on the 2.0a path or receives them pushed, and answers
// with oadrCreatedEvent.
package vensim

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/openadr/oadr2b"
)

// Config configures a simulated VEN.
type Config struct {
	// VTN is the VTN's base URL, including any prefix
	// ("https://127.0.0.1:8443").
	VTN string
	// Profile is "2.0b" (default) or "2.0a".
	Profile string
	VenID   string
	VenName string
	// Certificate is the VEN's client (and push server) certificate; nil
	// means plain HTTP.
	Certificate *tls.Certificate
	// RootCAs verify the VTN (and, in push mode, sign the VTN's client
	// certificate).
	RootCAs *x509.CertPool
	// MinTLS and MaxTLS bound the TLS versions offered (0: TLS 1.2 with
	// the OpenADR cipher suites).
	MinTLS, MaxTLS uint16
	// CipherSuites overrides the suites offered (default: the two the
	// 2.0b profile mandates).
	CipherSuites []uint16
	// PushListen, when set, runs the VEN's own endpoint there and
	// registers in push mode (2.0b) or serves pushed events (2.0a).
	PushListen string
	// OptType answers events ("optIn" by default).
	OptType string
	// SignWith, when set, signs every payload the VEN sends (XML
	// signature with ReplayProtect).
	SignWith *tls.Certificate
	// Tamper, when set, rewrites each outgoing payload after signing.
	Tamper func([]byte) []byte
	// RequireSigned refuses answers and pushes from the VTN that are not
	// signed by VTNFingerprint (default: the VTN's TLS certificate).
	RequireSigned  bool
	VTNFingerprint string
	// Check, when set, is applied to every payload sent and received
	// (a schema validator); a failure fails the exchange.
	Check func([]byte) error
}

// VEN is a simulated VEN.
type VEN struct {
	cfg    Config
	client *http.Client

	// Push behaviour switches (SetPush*): failPushes answers that many
	// pushes with HTTP 503; pushCode answers pushes with an
	// oadrResponse of that code (as a busy VEN answers 463); holdPush,
	// when set, is waited on before a push is handled; eventCode answers
	// every event of an oadrCreatedEvent with that responseCode.
	failPushes int
	pushCode   string
	holdPush   chan struct{}
	eventCode  string

	mu        sync.Mutex
	regID     string
	venID     string
	pollFreq  string
	events    map[string]oadr2b.EiEvent
	requests  map[string]string // reportSpecifierID → reportRequestID
	received  []string
	pushURL   string
	srv       *http.Server
	pushCount int
	signer    *oadr2b.Signer
	guard     oadr2b.ReplayGuard
	lastSvc   string
	lastBody  []byte
	checkErrs []error
	tlsState  *tls.ConnectionState
}

// New creates a VEN (no I/O).
func New(cfg Config) *VEN {
	if cfg.OptType == "" {
		cfg.OptType = "optIn"
	}
	if cfg.Profile == "" {
		cfg.Profile = oadr2b.Profile20b
	}
	tc := &tls.Config{RootCAs: cfg.RootCAs, MinVersion: cfg.MinTLS, MaxVersion: cfg.MaxTLS}
	if cfg.MinTLS == 0 && cfg.MaxTLS == 0 {
		tc.MinVersion, tc.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
		tc.CipherSuites = oadr2b.MandatedCipherSuites
	}
	if cfg.CipherSuites != nil {
		tc.CipherSuites = cfg.CipherSuites
	}
	tr := &http.Transport{TLSClientConfig: tc}
	if cfg.Certificate != nil {
		tr.TLSClientConfig.Certificates = []tls.Certificate{*cfg.Certificate}
	}
	v := &VEN{cfg: cfg, venID: cfg.VenID, client: &http.Client{Timeout: 10 * time.Second, Transport: tr},
		events: map[string]oadr2b.EiEvent{}, requests: map[string]string{}}
	if cfg.SignWith != nil {
		s, err := oadr2b.NewSigner(*cfg.SignWith)
		if err != nil {
			panic("vensim: " + err.Error())
		}
		v.signer = s
	}
	return v
}

func (v *VEN) a() bool { return v.cfg.Profile == oadr2b.Profile20a }

// check applies Config.Check and remembers failures.
func (v *VEN) check(b []byte) error {
	if v.cfg.Check == nil {
		return nil
	}
	if err := v.cfg.Check(b); err != nil {
		v.mu.Lock()
		v.checkErrs = append(v.checkErrs, err)
		v.mu.Unlock()
		return err
	}
	return nil
}

// CheckErrors are the Config.Check failures so far.
func (v *VEN) CheckErrors() []error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]error(nil), v.checkErrs...)
}

// TLS is the connection state of the last answer received.
func (v *VEN) TLS() *tls.ConnectionState {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.tlsState
}

// encode marshals and, when configured, signs and tampers a message.
func (v *VEN) encode(so oadr2b.SignedObject) ([]byte, error) {
	b, err := oadr2b.Marshal(so)
	if err != nil {
		return nil, err
	}
	if v.signer != nil {
		if b, err = v.signer.Sign(b); err != nil {
			return nil, err
		}
	}
	if v.cfg.Tamper != nil {
		b = v.cfg.Tamper(b)
	}
	return b, v.check(b)
}

// verify applies RequireSigned to a payload from the VTN.
func (v *VEN) verify(b []byte, tlsState *tls.ConnectionState) error {
	if !v.cfg.RequireSigned {
		return nil
	}
	got, err := oadr2b.VerifyPayload(b)
	if err != nil {
		return err
	}
	want := v.cfg.VTNFingerprint
	if want == "" && tlsState != nil && len(tlsState.PeerCertificates) > 0 {
		want = oadr2b.Fingerprint(tlsState.PeerCertificates[0].Raw)
	}
	if fp := oadr2b.Fingerprint(got.Cert.Raw); fp != want {
		return fmt.Errorf("signed by %s, want %s", fp, want)
	}
	return v.guard.Check(got)
}

// LastSent is the service and exact bytes of the last payload sent.
func (v *VEN) LastSent() (string, []byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.lastSvc, append([]byte(nil), v.lastBody...)
}

func id(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// Send posts one message to a VTN service and returns the answer.
func (v *VEN) Send(ctx context.Context, service string, so oadr2b.SignedObject) (*oadr2b.SignedObject, error) {
	b, err := v.encode(so)
	if err != nil {
		return nil, err
	}
	return v.SendRaw(ctx, service, b)
}

// Post sends raw bytes to a path under the VTN URL with a content type
// and returns the HTTP status and body.
func (v *VEN) Post(ctx context.Context, method, path, contentType string, b []byte, header http.Header) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(v.cfg.VTN, "/")+path, bytes.NewReader(b))
	if err != nil {
		return 0, nil, nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, vs := range header {
		for _, x := range vs {
			req.Header.Add(k, x)
		}
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	v.mu.Lock()
	v.tlsState = resp.TLS
	v.mu.Unlock()
	return resp.StatusCode, resp.Header, body, nil
}

// SendRaw posts a payload as is (a replay, a hand-made document) and
// returns the answer.
func (v *VEN) SendRaw(ctx context.Context, service string, b []byte) (*oadr2b.SignedObject, error) {
	v.mu.Lock()
	v.lastSvc, v.lastBody = service, append([]byte(nil), b...)
	v.mu.Unlock()
	status, _, body, err := v.Post(ctx, http.MethodPost, oadr2b.PathBase+service, oadr2b.ContentType, b, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", status, strings.TrimSpace(string(body)))
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, nil
	}
	if err := v.check(body); err != nil {
		return nil, fmt.Errorf("the VTN's answer: %w", err)
	}
	if err := v.verify(body, v.TLS()); err != nil {
		return nil, fmt.Errorf("the VTN's answer: XML signature: %w", err)
	}
	return oadr2b.Unmarshal(body)
}

// SendA posts a 2.0a message to the VTN's 2.0a EiEvent endpoint.
func (v *VEN) SendA(ctx context.Context, m oadr2b.MessageA) (*oadr2b.MessageA, error) {
	b, err := oadr2b.MarshalA(m)
	if err != nil {
		return nil, err
	}
	if err := v.check(b); err != nil {
		return nil, err
	}
	status, _, body, err := v.Post(ctx, http.MethodPost, oadr2b.PathBaseA+oadr2b.ServiceEvent, oadr2b.ContentType, b, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", status, strings.TrimSpace(string(body)))
	}
	if err := v.check(body); err != nil {
		return nil, fmt.Errorf("the VTN's answer: %w", err)
	}
	return oadr2b.UnmarshalA(body)
}

// VenID is the venID in use (from the VTN once registered).
func (v *VEN) VenID() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.venID
}

// RegistrationID is the current registration, or "".
func (v *VEN) RegistrationID() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.regID
}

// Requests maps reportSpecifierID to the reportRequestID the VTN used.
func (v *VEN) Requests() map[string]string {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := map[string]string{}
	for k, x := range v.requests {
		out[k] = x
	}
	return out
}

// Events returns the events received so far, by eventID.
func (v *VEN) Events() map[string]oadr2b.EiEvent {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make(map[string]oadr2b.EiEvent, len(v.events))
	for k, e := range v.events {
		out[k] = e
	}
	return out
}

// Received lists the names of messages received through polls and pushes.
func (v *VEN) Received() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.received...)
}

// Pushes counts oadrDistributeEvent messages pushed to the VEN.
func (v *VEN) Pushes() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.pushCount
}

// Register runs query, create registration, and report registration.
func (v *VEN) Register(ctx context.Context) error {
	return v.register(ctx, false)
}

// Reregister registers again with the current registrationID and venID.
func (v *VEN) Reregister(ctx context.Context) error {
	return v.register(ctx, true)
}

func (v *VEN) register(ctx context.Context, again bool) error {
	if v.a() {
		return errors.New("a 2.0a VEN does not register")
	}
	ans, err := v.Send(ctx, oadr2b.ServiceRegisterParty, oadr2b.SignedObject{QueryRegistration: &oadr2b.QueryRegistration{RequestID: id("q-")}})
	if err != nil {
		return fmt.Errorf("query registration: %w", err)
	}
	if ans == nil || ans.CreatedPartyRegistration == nil || ans.CreatedPartyRegistration.EiResponse.ResponseCode != oadr2b.CodeOK {
		return fmt.Errorf("query registration answered %v", describe(ans))
	}
	if err := v.startPush(); err != nil {
		return err
	}
	v.mu.Lock()
	cpr := &oadr2b.CreatePartyRegistration{
		RequestID: id("r-"), VenID: v.venID, ProfileName: oadr2b.ProfileName, TransportName: oadr2b.TransportName,
		VenName: v.cfg.VenName, XMLSignature: v.signer != nil,
	}
	if again {
		cpr.RegistrationID = v.regID
	}
	pull := v.pushURL == ""
	cpr.HTTPPullModel = &pull
	if !pull {
		cpr.TransportAddress = v.pushURL
	}
	v.mu.Unlock()
	ans, err = v.Send(ctx, oadr2b.ServiceRegisterParty, oadr2b.SignedObject{CreatePartyRegistration: cpr})
	if err != nil {
		return fmt.Errorf("create registration: %w", err)
	}
	if ans == nil || ans.CreatedPartyRegistration == nil || ans.CreatedPartyRegistration.EiResponse.ResponseCode != oadr2b.CodeOK {
		return fmt.Errorf("create registration answered %v", describe(ans))
	}
	c := ans.CreatedPartyRegistration
	v.mu.Lock()
	v.regID, v.venID = c.RegistrationID, c.VenID
	if c.PollFreq != nil {
		v.pollFreq = c.PollFreq.Duration
	}
	v.mu.Unlock()
	return v.registerReports(ctx)
}

// Metadata of the reports this VEN offers.
func (v *VEN) metadata() []oadr2b.Report {
	now := oadr2b.FormatTime(time.Now())
	rate := &oadr2b.SamplingRate{MinPeriod: "PT1S", MaxPeriod: "PT1H", OnChange: false}
	src := &oadr2b.Target{ResourceID: []string{"resource-1"}}
	return []oadr2b.Report{
		{
			Duration: &oadr2b.DurationProp{Duration: "PT1H"}, ReportRequestID: "0", ReportSpecifierID: "usage-1",
			ReportName: "METADATA_TELEMETRY_USAGE", CreatedDateTime: now,
			Descriptions: []oadr2b.ReportDescription{
				{RID: "energy", ReportDataSource: src, ReportType: "usage", ReadingType: "Direct Read", SamplingRate: rate,
					ItemBase: &oadr2b.ItemBase{XMLName: xmlName(oadr2b.NSPower, "energyReal"), ItemDescription: "RealEnergy", ItemUnits: "Wh", SiScaleCode: "k"}},
				{RID: "power", ReportDataSource: src, ReportType: "usage", ReadingType: "Direct Read", SamplingRate: rate,
					ItemBase: &oadr2b.ItemBase{XMLName: xmlName(oadr2b.NSPower, "powerReal"), ItemDescription: "RealPower", ItemUnits: "W", SiScaleCode: "none"}},
			},
		},
		{
			Duration: &oadr2b.DurationProp{Duration: "PT1H"}, ReportRequestID: "0", ReportSpecifierID: "status-1",
			ReportName: "METADATA_TELEMETRY_STATUS", CreatedDateTime: now,
			Descriptions: []oadr2b.ReportDescription{{RID: "status", ReportDataSource: src, ReportType: "x-resourceStatus", ReadingType: "x-notApplicable", SamplingRate: rate}},
		},
	}
}

func (v *VEN) registerReports(ctx context.Context) error {
	ans, err := v.Send(ctx, oadr2b.ServiceReport, oadr2b.SignedObject{RegisterReport: &oadr2b.RegisterReport{
		RequestID: id("rr-"), Reports: v.metadata(), VenID: v.VenID(),
	}})
	if err != nil {
		return fmt.Errorf("register report: %w", err)
	}
	if ans == nil || ans.RegisteredReport == nil || ans.RegisteredReport.EiResponse.ResponseCode != oadr2b.CodeOK {
		return fmt.Errorf("register report answered %v", describe(ans))
	}
	return v.acceptRequests(ctx, ans.RegisteredReport.EiResponse.RequestID, ans.RegisteredReport.ReportRequests)
}

// acceptRequests records report requests and answers oadrCreatedReport.
func (v *VEN) acceptRequests(ctx context.Context, requestID string, reqs []oadr2b.ReportRequest) error {
	var pending []string
	v.mu.Lock()
	for _, r := range reqs {
		v.requests[r.ReportSpecifier.ReportSpecifierID] = r.ReportRequestID
		pending = append(pending, r.ReportRequestID)
	}
	v.mu.Unlock()
	if len(pending) == 0 {
		return nil
	}
	_, err := v.Send(ctx, oadr2b.ServiceReport, oadr2b.SignedObject{CreatedReport: &oadr2b.CreatedReport{
		EiResponse:     oadr2b.EiResponse{ResponseCode: oadr2b.CodeOK, RequestID: requestID},
		PendingReports: oadr2b.PendingReports{ReportRequestID: pending}, VenID: v.VenID(),
	}})
	return err
}

// Poll sends one oadrPoll, handles the answer and returns its name.
func (v *VEN) Poll(ctx context.Context) (string, error) {
	ans, err := v.Send(ctx, oadr2b.ServicePoll, oadr2b.SignedObject{Poll: &oadr2b.Poll{VenID: v.VenID()}})
	if err != nil {
		return "", err
	}
	if ans == nil {
		return "", errors.New("empty answer to a poll")
	}
	name := oadr2b.MessageName(ans)
	v.mu.Lock()
	v.received = append(v.received, name)
	v.mu.Unlock()
	reply := v.answer(ans)
	if reply != nil {
		if _, err := v.Send(ctx, serviceFor(reply), *reply); err != nil {
			return name, fmt.Errorf("answering %s: %w", name, err)
		}
	}
	if ans.RequestReregistration != nil {
		err = v.Reregister(ctx)
	}
	return name, err
}

// serviceFor is the endpoint of a VEN's answer.
func serviceFor(so *oadr2b.SignedObject) string {
	switch {
	case so.CreatedEvent != nil:
		return oadr2b.ServiceEvent
	case so.RegisteredReport != nil, so.CreatedReport != nil, so.CanceledReport != nil, so.UpdatedReport != nil:
		return oadr2b.ServiceReport
	}
	return oadr2b.ServiceRegisterParty
}

// answer is the VEN's reply to a message from the VTN (nil: none).
func (v *VEN) answer(so *oadr2b.SignedObject) *oadr2b.SignedObject {
	venID := v.VenID()
	ok := func(req string) oadr2b.EiResponse {
		return oadr2b.EiResponse{ResponseCode: oadr2b.CodeOK, ResponseDescription: "OK", RequestID: req}
	}
	switch {
	case so.DistributeEvent != nil:
		return v.onEvents(so.DistributeEvent)
	case so.RegisterReport != nil:
		return &oadr2b.SignedObject{RegisteredReport: &oadr2b.RegisteredReport{EiResponse: ok(so.RegisterReport.RequestID), VenID: venID}}
	case so.CreateReport != nil:
		var pending []string
		v.mu.Lock()
		for _, r := range so.CreateReport.ReportRequests {
			v.requests[r.ReportSpecifier.ReportSpecifierID] = r.ReportRequestID
			pending = append(pending, r.ReportRequestID)
		}
		v.mu.Unlock()
		return &oadr2b.SignedObject{CreatedReport: &oadr2b.CreatedReport{EiResponse: ok(so.CreateReport.RequestID),
			PendingReports: oadr2b.PendingReports{ReportRequestID: pending}, VenID: venID}}
	case so.CancelReport != nil:
		v.mu.Lock()
		for spec, rr := range v.requests {
			for _, c := range so.CancelReport.ReportRequestID {
				if rr == c {
					delete(v.requests, spec)
				}
			}
		}
		v.mu.Unlock()
		return &oadr2b.SignedObject{CanceledReport: &oadr2b.CanceledReport{EiResponse: ok(so.CancelReport.RequestID), VenID: venID}}
	case so.CancelPartyRegistration != nil:
		v.mu.Lock()
		v.regID = ""
		v.mu.Unlock()
		return &oadr2b.SignedObject{CanceledPartyRegistration: &oadr2b.CanceledPartyRegistration{EiResponse: ok(so.CancelPartyRegistration.RequestID),
			RegistrationID: so.CancelPartyRegistration.RegistrationID, VenID: venID}}
	case so.RequestReregistration != nil:
		return &oadr2b.SignedObject{Response: &oadr2b.Response{EiResponse: ok(""), VenID: venID}}
	}
	return nil
}

// RequestEvents asks for the event list with oadrRequestEvent (on the 2.0a
// path for a 2.0a VEN).
func (v *VEN) RequestEvents(ctx context.Context) error {
	if v.a() {
		ans, err := v.SendA(ctx, oadr2b.MessageA{RequestEvent: &oadr2b.RequestEventA{EiRequestEvent: oadr2b.EiRequestEvent{RequestID: id("re-"), VenID: v.VenID()}}})
		if err != nil {
			return err
		}
		if ans.DistributeEvent == nil {
			return fmt.Errorf("request event answered %s", ans.NameA())
		}
		if resp := v.onEvents(fromA(ans.DistributeEvent)); resp != nil {
			r, err := v.SendA(ctx, oadr2b.MessageA{CreatedEvent: &oadr2b.CreatedEventA{EiCreatedEvent: resp.CreatedEvent.EiCreatedEvent}})
			if err != nil {
				return err
			}
			if r.Response == nil || r.Response.EiResponse.ResponseCode != oadr2b.CodeOK {
				return fmt.Errorf("created event answered %s", r.NameA())
			}
		}
		return nil
	}
	ans, err := v.Send(ctx, oadr2b.ServiceEvent, oadr2b.SignedObject{RequestEvent: &oadr2b.RequestEvent{
		EiRequestEvent: oadr2b.EiRequestEvent{RequestID: id("re-"), VenID: v.VenID()},
	}})
	if err != nil {
		return err
	}
	if ans == nil || ans.DistributeEvent == nil {
		return fmt.Errorf("request event answered %v", describe(ans))
	}
	if resp := v.onEvents(ans.DistributeEvent); resp != nil {
		_, err = v.Send(ctx, oadr2b.ServiceEvent, *resp)
	}
	return err
}

func fromA(a *oadr2b.DistributeEventA) *oadr2b.DistributeEvent {
	de := &oadr2b.DistributeEvent{EiResponse: a.EiResponse, RequestID: a.RequestID, VtnID: a.VtnID}
	for _, e := range a.Events {
		de.Events = append(de.Events, oadr2b.OadrEvent{EiEvent: e.EiEvent, ResponseRequired: e.ResponseRequired})
	}
	return de
}

// onEvents stores the events and builds the opt answer, or nil when no
// event asks for one. Rule 42: eiResponse's requestID stays empty and
// each eventResponse carries the distribution's requestID.
func (v *VEN) onEvents(de *oadr2b.DistributeEvent) *oadr2b.SignedObject {
	v.mu.Lock()
	defer v.mu.Unlock()
	var rs []oadr2b.EventResponse
	for _, e := range de.Events {
		v.events[e.EiEvent.Descriptor.EventID] = e.EiEvent
		if e.ResponseRequired == "always" {
			code := oadr2b.CodeOK
			if v.eventCode != "" {
				code = v.eventCode
			}
			rs = append(rs, oadr2b.EventResponse{
				ResponseCode: code, RequestID: de.RequestID, OptType: v.cfg.OptType,
				QualifiedEventID: oadr2b.QualifiedEventID{EventID: e.EiEvent.Descriptor.EventID, ModificationNumber: e.EiEvent.Descriptor.ModificationNumber},
			})
		}
	}
	if len(rs) == 0 {
		return nil
	}
	return &oadr2b.SignedObject{CreatedEvent: &oadr2b.CreatedEvent{EiCreatedEvent: oadr2b.EiCreatedEvent{
		EiResponse:     oadr2b.EiResponse{ResponseCode: oadr2b.CodeOK},
		EventResponses: &oadr2b.EventResponses{Response: rs}, VenID: v.venID,
	}}}
}

// SendTelemetry sends a TELEMETRY_USAGE report with energy and power and
// a TELEMETRY_STATUS report, for the reports the VTN requested.
func (v *VEN) SendTelemetry(ctx context.Context, at time.Time, energyKWh, powerW float64, online bool) error {
	v.mu.Lock()
	usageReq, statusReq := v.requests["usage-1"], v.requests["status-1"]
	v.mu.Unlock()
	if usageReq == "" || statusReq == "" {
		return errors.New("the VTN did not request the telemetry reports")
	}
	start := &oadr2b.DtStart{DateTime: oadr2b.FormatTime(at)}
	min1 := &oadr2b.DurationProp{Duration: "PT1M"}
	now := oadr2b.FormatTime(time.Now())
	ur := &oadr2b.UpdateReport{RequestID: id("ur-"), VenID: v.VenID(), Reports: []oadr2b.Report{
		{DtStart: start, Duration: min1, ReportRequestID: usageReq, ReportSpecifierID: "usage-1", ReportName: "TELEMETRY_USAGE", CreatedDateTime: now,
			Intervals: &oadr2b.Intervals{Interval: []oadr2b.Interval{{DtStart: start, Duration: min1, ReportPayload: []oadr2b.ReportPayload{
				{RID: "energy", PayloadFloat: &oadr2b.PayloadFloat{Value: energyKWh}, DataQuality: "Quality Good - Non Specific"},
				{RID: "power", PayloadFloat: &oadr2b.PayloadFloat{Value: powerW}},
			}}}}},
		{DtStart: start, Duration: min1, ReportRequestID: statusReq, ReportSpecifierID: "status-1", ReportName: "TELEMETRY_STATUS", CreatedDateTime: now,
			Intervals: &oadr2b.Intervals{Interval: []oadr2b.Interval{{DtStart: start, Duration: min1, ReportPayload: []oadr2b.ReportPayload{
				{RID: "status", ResourceStatus: &oadr2b.ResourceStatus{Online: online, ManualOverride: false}},
			}}}}},
	}}
	ans, err := v.Send(ctx, oadr2b.ServiceReport, oadr2b.SignedObject{UpdateReport: ur})
	if err != nil {
		return err
	}
	if ans == nil || ans.UpdatedReport == nil || ans.UpdatedReport.EiResponse.ResponseCode != oadr2b.CodeOK {
		return fmt.Errorf("update report answered %v", describe(ans))
	}
	return nil
}

// CreateOpt sends an opt for one event.
func (v *VEN) CreateOpt(ctx context.Context, optID, optType, eventID string, mod uint32) error {
	ans, err := v.Send(ctx, oadr2b.ServiceOpt, oadr2b.SignedObject{CreateOpt: &oadr2b.CreateOpt{
		OptID: optID, OptType: optType, OptReason: "participating", VenID: v.VenID(), CreatedDateTime: oadr2b.FormatTime(time.Now()),
		RequestID: id("o-"), QualifiedEventID: &oadr2b.QualifiedEventID{EventID: eventID, ModificationNumber: mod},
		Target: oadr2b.Target{VenID: []string{v.VenID()}},
	}})
	if err != nil {
		return err
	}
	if ans == nil || ans.CreatedOpt == nil || ans.CreatedOpt.EiResponse.ResponseCode != oadr2b.CodeOK || ans.CreatedOpt.OptID != optID {
		return fmt.Errorf("create opt answered %v", describe(ans))
	}
	return nil
}

// CancelOpt withdraws an opt.
func (v *VEN) CancelOpt(ctx context.Context, optID string) error {
	ans, err := v.Send(ctx, oadr2b.ServiceOpt, oadr2b.SignedObject{CancelOpt: &oadr2b.CancelOpt{RequestID: id("co-"), OptID: optID, VenID: v.VenID()}})
	if err != nil {
		return err
	}
	if ans == nil || ans.CanceledOpt == nil || ans.CanceledOpt.EiResponse.ResponseCode != oadr2b.CodeOK {
		return fmt.Errorf("cancel opt answered %v", describe(ans))
	}
	return nil
}

// CancelRegistration ends the registration.
func (v *VEN) CancelRegistration(ctx context.Context) error {
	ans, err := v.Send(ctx, oadr2b.ServiceRegisterParty, oadr2b.SignedObject{CancelPartyRegistration: &oadr2b.CancelPartyRegistration{
		RequestID: id("c-"), RegistrationID: v.RegistrationID(), VenID: v.VenID(),
	}})
	if err != nil {
		return err
	}
	if ans == nil || ans.CanceledPartyRegistration == nil || ans.CanceledPartyRegistration.EiResponse.ResponseCode != oadr2b.CodeOK {
		return fmt.Errorf("cancel registration answered %v", describe(ans))
	}
	v.mu.Lock()
	v.regID = ""
	v.mu.Unlock()
	return nil
}

// Close stops the push endpoint.
func (v *VEN) Close() {
	v.mu.Lock()
	srv := v.srv
	v.srv = nil
	v.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

// StartPush starts the push endpoint (Register does it for 2.0b) and
// returns its base URL.
func (v *VEN) StartPush() (string, error) {
	if err := v.startPush(); err != nil {
		return "", err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.pushURL, nil
}

func (v *VEN) startPush() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.cfg.PushListen == "" || v.srv != nil {
		return nil
	}
	ln, err := net.Listen("tcp", v.cfg.PushListen)
	if err != nil {
		return err
	}
	scheme := "http"
	if v.cfg.Certificate != nil {
		// Rule 67: the VEN server selects one of the mandated suites.
		ln = tls.NewListener(ln, &tls.Config{
			MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: oadr2b.MandatedCipherSuites,
			Certificates: []tls.Certificate{*v.cfg.Certificate},
			ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: v.cfg.RootCAs,
		})
		scheme = "https"
	}
	mux := http.NewServeMux()
	if v.a() {
		mux.HandleFunc("POST "+oadr2b.PathBaseA+oadr2b.ServiceEvent, v.servePushA)
	} else {
		for _, svc := range []string{oadr2b.ServiceEvent, oadr2b.ServiceReport, oadr2b.ServiceRegisterParty, oadr2b.ServiceOpt} {
			mux.HandleFunc("POST "+oadr2b.PathBase+svc, v.servePush)
		}
	}
	v.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	v.pushURL = scheme + "://" + ln.Addr().String()
	go func() { _ = v.srv.Serve(ln) }()
	return nil
}

func (v *VEN) writeAnswer(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", oadr2b.ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	_, _ = w.Write(b)
}

// SetPushFailures makes the next n pushes fail with HTTP 503.
func (v *VEN) SetPushFailures(n int) { v.mu.Lock(); v.failPushes = n; v.mu.Unlock() }

// SetPushCode answers pushes with an oadrResponse of code ("" normally).
func (v *VEN) SetPushCode(code string) { v.mu.Lock(); v.pushCode = code; v.mu.Unlock() }

// HoldPushes makes pushes wait until the returned function is called.
func (v *VEN) HoldPushes() (release func()) {
	ch := make(chan struct{})
	v.mu.Lock()
	v.holdPush = ch
	v.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			v.mu.Lock()
			v.holdPush = nil
			v.mu.Unlock()
			close(ch)
		})
	}
}

// SetEventResponseCode answers each event in oadrCreatedEvent with this
// responseCode ("" is 200), still with optIn.
func (v *VEN) SetEventResponseCode(code string) { v.mu.Lock(); v.eventCode = code; v.mu.Unlock() }

func (v *VEN) servePush(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	hold, fail, code := v.holdPush, v.failPushes > 0, v.pushCode
	if fail {
		v.failPushes--
	}
	v.mu.Unlock()
	if hold != nil {
		<-hold
	}
	if fail {
		_, _ = io.Copy(io.Discard, r.Body)
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	if code != "" {
		_, _ = io.Copy(io.Discard, r.Body)
		b, _ := v.encode(oadr2b.SignedObject{Response: &oadr2b.Response{EiResponse: oadr2b.EiResponse{ResponseCode: code, ResponseDescription: "not now"}, VenID: v.VenID()}})
		v.writeAnswer(w, b)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err := v.check(body); err != nil {
		http.Error(w, err.Error(), http.StatusNotAcceptable)
		return
	}
	if err := v.verify(body, r.TLS); err != nil {
		b, _ := v.encode(oadr2b.SignedObject{Response: &oadr2b.Response{EiResponse: oadr2b.EiResponse{
			ResponseCode: oadr2b.CodeBadSignature, ResponseDescription: "XML signature: " + err.Error()}, VenID: v.VenID()}})
		v.writeAnswer(w, b)
		return
	}
	so, err := oadr2b.Unmarshal(body)
	if err != nil {
		http.Error(w, "not an OpenADR payload", http.StatusNotAcceptable)
		return
	}
	name := oadr2b.MessageName(so)
	v.mu.Lock()
	v.received = append(v.received, name+"(push)")
	if so.DistributeEvent != nil {
		v.pushCount++
	}
	v.mu.Unlock()
	resp := v.answer(so)
	if resp == nil {
		resp = &oadr2b.SignedObject{Response: &oadr2b.Response{EiResponse: oadr2b.EiResponse{ResponseCode: oadr2b.CodeOK, RequestID: openadrRequestID(so)}, VenID: v.VenID()}}
	}
	b, err := v.encode(*resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	v.writeAnswer(w, b)
}

func openadrRequestID(so *oadr2b.SignedObject) string {
	if so.DistributeEvent != nil {
		return so.DistributeEvent.RequestID
	}
	return ""
}

func (v *VEN) servePushA(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err := v.check(body); err != nil {
		http.Error(w, err.Error(), http.StatusNotAcceptable)
		return
	}
	m, err := oadr2b.UnmarshalA(body)
	if err != nil || m.DistributeEvent == nil {
		http.Error(w, "expected a 2.0a oadrDistributeEvent", http.StatusNotAcceptable)
		return
	}
	v.mu.Lock()
	v.received = append(v.received, "oadrDistributeEvent(push)")
	v.pushCount++
	v.mu.Unlock()
	out := oadr2b.MessageA{Response: &oadr2b.ResponseA{EiResponse: oadr2b.EiResponse{ResponseCode: oadr2b.CodeOK, RequestID: m.DistributeEvent.RequestID}}}
	if resp := v.onEvents(fromA(m.DistributeEvent)); resp != nil {
		out = oadr2b.MessageA{CreatedEvent: &oadr2b.CreatedEventA{EiCreatedEvent: resp.CreatedEvent.EiCreatedEvent}}
	}
	b, err := oadr2b.MarshalA(out)
	if err == nil {
		err = v.check(b)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	v.writeAnswer(w, b)
}

func describe(so *oadr2b.SignedObject) string {
	if so == nil {
		return "nothing"
	}
	if so.Response != nil {
		return fmt.Sprintf("oadrResponse %s %s", so.Response.EiResponse.ResponseCode, so.Response.EiResponse.ResponseDescription)
	}
	return oadr2b.MessageName(so)
}

func xmlName(ns, local string) xml.Name { return xml.Name{Space: ns, Local: local} }
