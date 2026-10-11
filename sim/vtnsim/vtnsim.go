// Package vtnsim is an in-process OpenADR 2.0b VTN for tests of VENs: it
// registers one VEN over simple HTTP (mutual TLS when given a
// certificate), answers oadrRequestEvent and oadrPoll with the events and
// queued messages the test sets, pushes them instead when the VEN
// registered for push, signs and checks XML signatures when configured,
// and records everything the VEN sends.
package vtnsim

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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

// Config configures a simulated VTN.
type Config struct {
	VtnID string
	// VenID is assigned to the VEN that registers (default ven-1).
	VenID string
	// Certificate serves TLS and is the push client's certificate; nil
	// means plain HTTP.
	Certificate *tls.Certificate
	// ClientCAs verify VEN certificates (and push servers).
	ClientCAs *x509.CertPool
	// PollFreq is oadrRequestedOadrPollFreq (default PT1S).
	PollFreq string
	// RequestReports makes oadrRegisteredReport request every report of
	// the VEN's METADATA (granularity and reportBackDuration: the data
	// points' oadrMinPeriod).
	RequestReports bool
	// SignWith, when set, signs every answer and push (XML signature
	// with ReplayProtect).
	SignWith *tls.Certificate
	// RequireSigned refuses requests that are not signed, or not signed
	// by the VEN's TLS client certificate when it has one, with an
	// oadrResponse of code oadr2b.CodeBadSignature; replays are refused
	// too. SignatureErrors lists the failures.
	RequireSigned bool
}

// VTN is a simulated VTN.
type VTN struct {
	cfg    Config
	srv    *http.Server
	url    string
	push   *http.Client
	signer *oadr2b.Signer
	guard  oadr2b.ReplayGuard

	mu       sync.Mutex
	sigErrs  []error
	regID    string
	pushAddr string
	events   []oadr2b.OadrEvent
	dirty    bool
	queue    []oadr2b.SignedObject
	received []oadr2b.SignedObject
	meta     []oadr2b.Report
}

// New creates a VTN (no I/O). It panics when SignWith cannot sign (not
// an RSA or ECDSA key).
func New(cfg Config) *VTN {
	if cfg.VtnID == "" {
		cfg.VtnID = "vtnsim"
	}
	if cfg.VenID == "" {
		cfg.VenID = "ven-1"
	}
	if cfg.PollFreq == "" {
		cfg.PollFreq = "PT1S"
	}
	tc := &tls.Config{RootCAs: cfg.ClientCAs, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: oadr2b.MandatedCipherSuites}
	if cfg.Certificate != nil {
		tc.Certificates = []tls.Certificate{*cfg.Certificate}
	}
	v := &VTN{cfg: cfg, push: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}}
	if cfg.SignWith != nil {
		s, err := oadr2b.NewSigner(*cfg.SignWith)
		if err != nil {
			panic("vtnsim: " + err.Error())
		}
		v.signer = s
	}
	return v
}

// encode marshals a message and signs it when SignWith is set.
func (v *VTN) encode(so oadr2b.SignedObject) ([]byte, error) {
	b, err := oadr2b.Marshal(so)
	if err != nil || v.signer == nil {
		return b, err
	}
	return v.signer.Sign(b)
}

// verify applies RequireSigned to a payload from the VEN; tlsState is
// the connection it came on (nil for plain HTTP).
func (v *VTN) verify(b []byte, tlsState *tls.ConnectionState) error {
	if !v.cfg.RequireSigned {
		return nil
	}
	err := func() error {
		got, err := oadr2b.VerifyPayload(b)
		if err != nil {
			return err
		}
		if tlsState != nil && len(tlsState.PeerCertificates) > 0 {
			want := oadr2b.Fingerprint(tlsState.PeerCertificates[0].Raw)
			if fp := oadr2b.Fingerprint(got.Cert.Raw); fp != want {
				return fmt.Errorf("signed by %s, the TLS client is %s", fp, want)
			}
		}
		return v.guard.Check(got)
	}()
	if err != nil {
		v.mu.Lock()
		v.sigErrs = append(v.sigErrs, err)
		v.mu.Unlock()
	}
	return err
}

// SignatureErrors lists the requests refused under RequireSigned.
func (v *VTN) SignatureErrors() []error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]error(nil), v.sigErrs...)
}

// Start listens on 127.0.0.1 and returns the base URL.
func (v *VTN) Start() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	scheme := "http"
	if v.cfg.Certificate != nil {
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{*v.cfg.Certificate}, ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs: v.cfg.ClientCAs, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: oadr2b.MandatedCipherSuites})
		scheme = "https"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+oadr2b.PathBase+"{service}", v.serve)
	v.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	v.url = scheme + "://" + ln.Addr().String()
	go func() { _ = v.srv.Serve(ln) }()
	return v.url, nil
}

// Close stops the server.
func (v *VTN) Close() {
	if v.srv != nil {
		_ = v.srv.Close()
	}
}

// Received lists every message the VEN sent (requests and push answers).
func (v *VTN) Received() []oadr2b.SignedObject {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]oadr2b.SignedObject(nil), v.received...)
}

// Find is the messages received whose element name is name.
func (v *VTN) Find(name string) []oadr2b.SignedObject {
	var out []oadr2b.SignedObject
	for _, so := range v.Received() {
		if oadr2b.MessageName(&so) == name {
			out = append(out, so)
		}
	}
	return out
}

// Metadata is the VEN's last METADATA.
func (v *VTN) Metadata() []oadr2b.Report {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.meta
}

// Registered reports the registration: registrationID, push address.
func (v *VTN) Registered() (regID, pushAddr string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.regID, v.pushAddr
}

// SetEvents replaces the event list; the VEN gets it on its next poll or
// pushed.
func (v *VTN) SetEvents(ctx context.Context, evs ...oadr2b.OadrEvent) error {
	v.mu.Lock()
	v.events, v.dirty = evs, true
	v.mu.Unlock()
	return v.flush(ctx)
}

// Queue adds a message for the VEN's next poll, or pushes it.
func (v *VTN) Queue(ctx context.Context, so oadr2b.SignedObject) error {
	v.mu.Lock()
	v.queue = append(v.queue, so)
	v.mu.Unlock()
	return v.flush(ctx)
}

func (v *VTN) distribution(requestID string) *oadr2b.DistributeEvent {
	ok := oadr2b.EiResponse{ResponseCode: oadr2b.CodeOK, RequestID: requestID}
	return &oadr2b.DistributeEvent{EiResponse: &ok, RequestID: requestID, VtnID: v.cfg.VtnID, Events: append([]oadr2b.OadrEvent(nil), v.events...)}
}

// next pops what waits for the VEN (nil: nothing).
func (v *VTN) next() *oadr2b.SignedObject {
	v.mu.Lock()
	defer v.mu.Unlock()
	switch {
	case len(v.queue) > 0:
		m := v.queue[0]
		v.queue = v.queue[1:]
		return &m
	case v.dirty:
		v.dirty = false
		return &oadr2b.SignedObject{DistributeEvent: v.distribution("dist-" + strconv.Itoa(len(v.received)))}
	}
	return nil
}

// flush pushes everything waiting when the VEN is in push mode.
func (v *VTN) flush(ctx context.Context) error {
	v.mu.Lock()
	addr := v.pushAddr
	v.mu.Unlock()
	if addr == "" {
		return nil
	}
	for {
		m := v.next()
		if m == nil {
			return nil
		}
		b, err := v.encode(*m)
		if err != nil {
			return err
		}
		svc := oadr2b.ServiceEvent
		switch {
		case m.CreateReport != nil, m.CancelReport != nil, m.RegisterReport != nil, m.UpdateReport != nil:
			svc = oadr2b.ServiceReport
		case m.CancelPartyRegistration != nil, m.RequestReregistration != nil:
			svc = oadr2b.ServiceRegisterParty
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(addr, "/")+oadr2b.PathBase+svc, bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", oadr2b.ContentType)
		resp, err := v.push.Do(req)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("push: HTTP %d", resp.StatusCode)
		}
		if len(bytes.TrimSpace(body)) > 0 {
			if so, err := oadr2b.Unmarshal(body); err == nil {
				v.record(so)
			}
		}
	}
}

func (v *VTN) record(so *oadr2b.SignedObject) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.received = append(v.received, *so)
	if so.RegisterReport != nil && len(so.RegisterReport.Reports) > 0 {
		v.meta = so.RegisterReport.Reports
	}
}

func (v *VTN) serve(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	so, err := oadr2b.Unmarshal(b)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotAcceptable)
		return
	}
	var out *oadr2b.SignedObject
	if err := v.verify(b, r.TLS); err != nil {
		out = &oadr2b.SignedObject{Response: &oadr2b.Response{EiResponse: oadr2b.EiResponse{ResponseCode: oadr2b.CodeBadSignature,
			ResponseDescription: "XML signature: " + err.Error(), RequestID: requestID(so)}, VenID: v.cfg.VenID}}
	} else {
		v.record(so)
		out = v.answer(so)
	}
	body, err := v.encode(*out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", oadr2b.ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}

func (v *VTN) answer(so *oadr2b.SignedObject) *oadr2b.SignedObject {
	ok := func(req string) oadr2b.EiResponse {
		return oadr2b.EiResponse{ResponseCode: oadr2b.CodeOK, ResponseDescription: "OK", RequestID: req}
	}
	resp := func(req string) *oadr2b.SignedObject {
		return &oadr2b.SignedObject{Response: &oadr2b.Response{EiResponse: ok(req), VenID: v.cfg.VenID}}
	}
	switch {
	case so.QueryRegistration != nil:
		return &oadr2b.SignedObject{CreatedPartyRegistration: &oadr2b.CreatedPartyRegistration{EiResponse: ok(so.QueryRegistration.RequestID),
			VtnID: v.cfg.VtnID, Profiles: profiles(), PollFreq: &oadr2b.DurationProp{Duration: v.cfg.PollFreq}}}
	case so.CreatePartyRegistration != nil:
		c := so.CreatePartyRegistration
		v.mu.Lock()
		if c.RegistrationID != "" && c.RegistrationID != v.regID {
			v.mu.Unlock()
			return &oadr2b.SignedObject{CreatedPartyRegistration: &oadr2b.CreatedPartyRegistration{EiResponse: oadr2b.EiResponse{ResponseCode: oadr2b.CodeInvalidID,
				RequestID: c.RequestID}, VtnID: v.cfg.VtnID, Profiles: profiles()}}
		}
		if v.regID == "" {
			v.regID = "reg-sim-1"
		}
		v.pushAddr = ""
		if c.HTTPPullModel != nil && !*c.HTTPPullModel {
			v.pushAddr = c.TransportAddress
		}
		reg := v.regID
		v.mu.Unlock()
		if v.pushAddr != "" {
			go func() { _ = v.flush(context.Background()) }()
		}
		return &oadr2b.SignedObject{CreatedPartyRegistration: &oadr2b.CreatedPartyRegistration{EiResponse: ok(c.RequestID), RegistrationID: reg,
			VenID: v.cfg.VenID, VtnID: v.cfg.VtnID, Profiles: profiles(), PollFreq: &oadr2b.DurationProp{Duration: v.cfg.PollFreq}}}
	case so.CancelPartyRegistration != nil:
		v.mu.Lock()
		v.regID, v.pushAddr = "", ""
		v.mu.Unlock()
		return &oadr2b.SignedObject{CanceledPartyRegistration: &oadr2b.CanceledPartyRegistration{EiResponse: ok(so.CancelPartyRegistration.RequestID),
			RegistrationID: so.CancelPartyRegistration.RegistrationID, VenID: v.cfg.VenID}}
	case so.RequestEvent != nil:
		v.mu.Lock()
		v.dirty = false
		de := v.distribution(so.RequestEvent.EiRequestEvent.RequestID)
		v.mu.Unlock()
		return &oadr2b.SignedObject{DistributeEvent: de}
	case so.Poll != nil:
		if m := v.next(); m != nil {
			return m
		}
		return resp("")
	case so.RegisterReport != nil:
		out := &oadr2b.RegisteredReport{EiResponse: ok(so.RegisterReport.RequestID), VenID: v.cfg.VenID}
		if v.cfg.RequestReports {
			out.ReportRequests = requestAll(so.RegisterReport.Reports)
		}
		return &oadr2b.SignedObject{RegisteredReport: out}
	case so.UpdateReport != nil:
		return &oadr2b.SignedObject{UpdatedReport: &oadr2b.UpdatedReport{EiResponse: ok(so.UpdateReport.RequestID), VenID: v.cfg.VenID}}
	case so.CreateOpt != nil:
		return &oadr2b.SignedObject{CreatedOpt: &oadr2b.CreatedOpt{EiResponse: ok(so.CreateOpt.RequestID), OptID: so.CreateOpt.OptID}}
	case so.CancelOpt != nil:
		return &oadr2b.SignedObject{CanceledOpt: &oadr2b.CanceledOpt{EiResponse: ok(so.CancelOpt.RequestID), OptID: so.CancelOpt.OptID}}
	}
	return resp(requestID(so))
}

func requestID(so *oadr2b.SignedObject) string {
	switch {
	case so.CreatedEvent != nil:
		return so.CreatedEvent.EiCreatedEvent.EiResponse.RequestID
	case so.CreatedReport != nil:
		return so.CreatedReport.EiResponse.RequestID
	}
	return ""
}

func profiles() oadr2b.Profiles {
	return oadr2b.Profiles{Profile: []oadr2b.Profile{{Name: oadr2b.ProfileName, Transports: oadr2b.Transports{Transport: []oadr2b.Transport{{Name: oadr2b.TransportName}}}}}}
}

// requestAll asks for every report of a METADATA.
func requestAll(reps []oadr2b.Report) []oadr2b.ReportRequest {
	var out []oadr2b.ReportRequest
	for i, rep := range reps {
		gran := "PT1M"
		var sp []oadr2b.SpecifierPayload
		for _, d := range rep.Descriptions {
			sp = append(sp, oadr2b.SpecifierPayload{RID: d.RID, ReadingType: "x-notApplicable"})
			if d.SamplingRate != nil {
				gran = d.SamplingRate.MinPeriod
			}
		}
		if strings.HasPrefix(rep.ReportName, "METADATA_HISTORY") {
			continue
		}
		out = append(out, oadr2b.ReportRequest{ReportRequestID: "sim-rr-" + strconv.Itoa(i), ReportSpecifier: oadr2b.ReportSpecifier{
			ReportSpecifierID: rep.ReportSpecifierID, Granularity: oadr2b.DurationProp{Duration: gran}, ReportBackDuration: oadr2b.DurationProp{Duration: gran},
			ReportInterval:    &oadr2b.ReportInterval{Properties: oadr2b.Properties{DtStart: oadr2b.DtStart{DateTime: oadr2b.FormatTime(time.Now())}, Duration: oadr2b.DurationProp{Duration: "PT0S"}}},
			SpecifierPayloads: sp}})
	}
	return out
}

// HistoryRequest is an oadrCreateReport for a VEN's HISTORY_USAGE report
// (its reportSpecifierID) over the last span.
func HistoryRequest(id, specifier string, span time.Duration) oadr2b.SignedObject {
	now := time.Now()
	return oadr2b.SignedObject{CreateReport: &oadr2b.CreateReport{RequestID: "req-" + id, ReportRequests: []oadr2b.ReportRequest{{ReportRequestID: id,
		ReportSpecifier: oadr2b.ReportSpecifier{ReportSpecifierID: specifier, Granularity: oadr2b.DurationProp{Duration: "PT0S"},
			ReportBackDuration: oadr2b.DurationProp{Duration: "PT0S"},
			ReportInterval: &oadr2b.ReportInterval{Properties: oadr2b.Properties{DtStart: oadr2b.DtStart{DateTime: oadr2b.FormatTime(now.Add(-span))},
				Duration: oadr2b.DurationProp{Duration: oadr2b.FormatDuration(span)}}}}}}}}
}

var errNotRegistered = errors.New("vtnsim: no VEN registered")

var _ = errNotRegistered
