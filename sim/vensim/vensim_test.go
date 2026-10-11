// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package vensim_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/openadr-sim/internal/testpki"
	"github.com/cB-Sigma/openadr-sim/sim/vensim"
	"github.com/cB-Sigma/openadr-sim/sim/vtnsim"
	"github.com/cB-Sigma/openadr/oadr2b"
)

// event is one SIMPLE event for venID that asks for an answer.
func event(id, venID string, level float64) oadr2b.OadrEvent {
	now := time.Now()
	return oadr2b.OadrEvent{ResponseRequired: "always", EiEvent: oadr2b.EiEvent{
		Descriptor: oadr2b.EventDescriptor{EventID: id, ModificationNumber: 0, MarketContext: oadr2b.MarketContext{MarketContext: "http://sim.test/mc"},
			CreatedDateTime: oadr2b.FormatTime(now), EventStatus: "active"},
		ActivePeriod: oadr2b.ActivePeriod{Properties: oadr2b.Properties{DtStart: oadr2b.DtStart{DateTime: oadr2b.FormatTime(now)},
			Duration: oadr2b.DurationProp{Duration: "PT1H"}}, Components: oadr2b.Components{Nil: "true"}},
		Signals: oadr2b.EventSignals{Signal: []oadr2b.EventSignal{{SignalName: "SIMPLE", SignalType: "level", SignalID: "s1",
			Intervals: oadr2b.Intervals{Interval: []oadr2b.Interval{{Duration: &oadr2b.DurationProp{Duration: "PT1H"}, UID: &oadr2b.UID{Text: "0"},
				SignalPayload: &oadr2b.SignalPayload{PayloadFloat: oadr2b.PayloadFloat{Value: level}}}}}}}},
		Target: oadr2b.Target{VenID: []string{venID}},
	}}
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

// The VEN registers with the VTN, offers its reports and is asked for
// them, gets an event by poll and by oadrRequestEvent and opts in, sends
// telemetry, opts, answers a report request and cancels its
// registration, over plain HTTP in pull mode.
func TestVENAgainstVTNSim(t *testing.T) {
	c := ctx(t)
	vtn := vtnsim.New(vtnsim.Config{VtnID: "VTN-1", VenID: "ven-7", RequestReports: true})
	url, err := vtn.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer vtn.Close()
	ven := vensim.New(vensim.Config{VTN: url, VenName: "ven-a"})
	defer ven.Close()

	if err := ven.Register(c); err != nil {
		t.Fatal(err)
	}
	if ven.VenID() != "ven-7" || ven.RegistrationID() != "reg-sim-1" {
		t.Fatalf("registered as %q / %q", ven.VenID(), ven.RegistrationID())
	}
	if reg, push := vtn.Registered(); reg != "reg-sim-1" || push != "" {
		t.Fatalf("the VTN has %q, push %q", reg, push)
	}
	if n := len(vtn.Metadata()); n != 2 {
		t.Fatalf("the VTN has %d METADATA reports, want 2", n)
	}
	if rq := ven.Requests(); rq["usage-1"] == "" || rq["status-1"] == "" {
		t.Fatalf("report requests: %v", rq)
	}
	if n := len(vtn.Find("oadrCreatedReport")); n != 1 {
		t.Fatalf("%d oadrCreatedReport, want 1", n)
	}

	// Nothing waits: the poll gets an oadrResponse.
	if got, err := ven.Poll(c); err != nil || got != "oadrResponse" {
		t.Fatalf("empty poll: %q, %v", got, err)
	}
	if err := vtn.SetEvents(c, event("ev-1", "ven-7", 2)); err != nil {
		t.Fatal(err)
	}
	if got, err := ven.Poll(c); err != nil || got != "oadrDistributeEvent" {
		t.Fatalf("poll: %q, %v", got, err)
	}
	if ev, ok := ven.Events()["ev-1"]; !ok || ev.Signals.Signal[0].Intervals.Interval[0].SignalPayload.PayloadFloat.Value != 2 {
		t.Fatalf("events: %+v", ven.Events())
	}
	created := vtn.Find("oadrCreatedEvent")
	if len(created) != 1 {
		t.Fatalf("%d oadrCreatedEvent, want 1", len(created))
	}
	rs := created[0].CreatedEvent.EiCreatedEvent.EventResponses.Response
	if len(rs) != 1 || rs[0].OptType != "optIn" || rs[0].QualifiedEventID.EventID != "ev-1" || rs[0].RequestID == "" {
		t.Fatalf("event responses: %+v", rs)
	}
	if err := ven.RequestEvents(c); err != nil {
		t.Fatal(err)
	}
	if n := len(vtn.Find("oadrCreatedEvent")); n != 2 {
		t.Fatalf("%d oadrCreatedEvent after oadrRequestEvent, want 2", n)
	}

	if err := ven.SendTelemetry(c, time.Now(), 1.5, 640, true); err != nil {
		t.Fatal(err)
	}
	ur := vtn.Find("oadrUpdateReport")
	if len(ur) != 1 || len(ur[0].UpdateReport.Reports) != 2 {
		t.Fatalf("oadrUpdateReport: %+v", ur)
	}
	if p := ur[0].UpdateReport.Reports[0].Intervals.Interval[0].ReportPayload[1]; p.RID != "power" || p.PayloadFloat.Value != 640 {
		t.Fatalf("power payload: %+v", p)
	}

	if err := ven.CreateOpt(c, "opt-1", "optOut", "ev-1", 0); err != nil {
		t.Fatal(err)
	}
	if err := ven.CancelOpt(c, "opt-1"); err != nil {
		t.Fatal(err)
	}

	if err := vtn.Queue(c, vtnsim.HistoryRequest("hist-1", "usage-1", time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, err := ven.Poll(c); err != nil || got != "oadrCreateReport" {
		t.Fatalf("poll for the report request: %q, %v", got, err)
	}
	if ven.Requests()["usage-1"] != "hist-1" {
		t.Fatalf("report requests after oadrCreateReport: %v", ven.Requests())
	}
	if n := len(vtn.Find("oadrCreatedReport")); n != 2 {
		t.Fatalf("%d oadrCreatedReport, want 2", n)
	}

	if err := ven.CancelRegistration(c); err != nil {
		t.Fatal(err)
	}
	if reg, _ := vtn.Registered(); reg != "" || ven.RegistrationID() != "" {
		t.Fatalf("still registered: VTN %q, VEN %q", reg, ven.RegistrationID())
	}
}

// A VEN registered in push mode gets events pushed and answers them in
// the push's HTTP answer; a failed push is reported to the VTN.
func TestVENPushMode(t *testing.T) {
	c := ctx(t)
	vtn := vtnsim.New(vtnsim.Config{})
	url, err := vtn.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer vtn.Close()
	ven := vensim.New(vensim.Config{VTN: url, PushListen: "127.0.0.1:0"})
	defer ven.Close()
	if err := ven.Register(c); err != nil {
		t.Fatal(err)
	}
	if _, push := vtn.Registered(); !strings.HasPrefix(push, "http://127.0.0.1:") {
		t.Fatalf("push address %q", push)
	}
	if err := vtn.SetEvents(c, event("ev-p", "ven-1", 1)); err != nil {
		t.Fatal(err)
	}
	if ven.Pushes() != 1 {
		t.Fatalf("%d pushes, want 1", ven.Pushes())
	}
	if n := len(vtn.Find("oadrCreatedEvent")); n != 1 {
		t.Fatalf("%d oadrCreatedEvent from the push answer, want 1", n)
	}
	ven.SetPushFailures(1)
	if err := vtn.SetEvents(c, event("ev-q", "ven-1", 1)); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("failed push: %v", err)
	}
}

// Over mutual TLS with the OpenADR suites, both sides sign every
// message and check the other's signature against its TLS certificate;
// an unsigned or altered request is refused, a replay too.
func TestSignedMutualTLS(t *testing.T) {
	c := ctx(t)
	pki := testpki.New(t)
	vtnCert := pki.Issue(t, "vtn", "127.0.0.1", "localhost")
	venCert := pki.Issue(t, "ven", "127.0.0.1", "localhost")
	vtn := vtnsim.New(vtnsim.Config{Certificate: &vtnCert.TLS, ClientCAs: pki.Pool, SignWith: &vtnCert.TLS, RequireSigned: true})
	url, err := vtn.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer vtn.Close()
	if !strings.HasPrefix(url, "https://") {
		t.Fatalf("url %q", url)
	}
	ven := vensim.New(vensim.Config{VTN: url, Certificate: &venCert.TLS, RootCAs: pki.Pool, SignWith: &venCert.TLS, RequireSigned: true})
	defer ven.Close()
	if err := ven.Register(c); err != nil {
		t.Fatal(err)
	}
	if err := vtn.SetEvents(c, event("ev-s", "ven-1", 3)); err != nil {
		t.Fatal(err)
	}
	if err := ven.RequestEvents(c); err != nil {
		t.Fatal(err)
	}
	if errs := vtn.SignatureErrors(); len(errs) != 0 {
		t.Fatalf("signature errors: %v", errs)
	}
	if st := ven.TLS(); st == nil || st.CipherSuite != 0xc023 { // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
		t.Fatalf("TLS state: %+v", st)
	}

	// The same signed bytes again: a replay.
	svc, last := ven.LastSent()
	ans, err := ven.SendRaw(c, svc, last)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Response == nil || ans.Response.EiResponse.ResponseCode != oadr2b.CodeBadSignature {
		t.Fatalf("replay answered %+v", ans)
	}

	// Unsigned, and signed then altered.
	plain := vensim.New(vensim.Config{VTN: url, Certificate: &venCert.TLS, RootCAs: pki.Pool})
	if err := plain.Register(c); err == nil || !strings.Contains(err.Error(), oadr2b.CodeBadSignature) {
		t.Fatalf("unsigned registration: %v", err)
	}
	tampered := vensim.New(vensim.Config{VTN: url, VenID: "ven-1", Certificate: &venCert.TLS, RootCAs: pki.Pool, SignWith: &venCert.TLS,
		Tamper: func(b []byte) []byte { return bytes.Replace(b, []byte("<ei:venID>"), []byte("<ei:venID>x"), 1) }})
	if _, err := tampered.Poll(c); err == nil && len(vtn.SignatureErrors()) < 3 {
		t.Fatalf("altered poll accepted; errors %v", vtn.SignatureErrors())
	}
	if n := len(vtn.SignatureErrors()); n < 3 {
		t.Fatalf("%d signature errors, want at least 3", n)
	}
}
