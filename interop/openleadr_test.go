// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/cB-Sigma/openadr-sim/internal/testpki"
	"github.com/cB-Sigma/openadr-sim/sim/vensim"
	"github.com/cB-Sigma/openadr-sim/sim/vtnsim"
	"github.com/cB-Sigma/openadr/oadr2b"
)

// eventually polls cond until it holds or within passes.
func eventually(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %s", what, within)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// simpleEvent is one SIMPLE event for venID that asks for an answer.
func simpleEvent(id, venID string, mod uint32, level float64) oadr2b.OadrEvent {
	now := time.Now()
	return oadr2b.OadrEvent{ResponseRequired: "always", EiEvent: oadr2b.EiEvent{
		Descriptor: oadr2b.EventDescriptor{EventID: id, ModificationNumber: mod, MarketContext: oadr2b.MarketContext{MarketContext: "http://sim.test/mc"},
			CreatedDateTime: oadr2b.FormatTime(now), EventStatus: "active"},
		ActivePeriod: oadr2b.ActivePeriod{Properties: oadr2b.Properties{DtStart: oadr2b.DtStart{DateTime: oadr2b.FormatTime(now.Add(-time.Minute))},
			Duration: oadr2b.DurationProp{Duration: "PT1H"}}, Components: oadr2b.Components{Nil: "true"}},
		Signals: oadr2b.EventSignals{Signal: []oadr2b.EventSignal{{SignalName: "SIMPLE", SignalType: "level", SignalID: "s1",
			Intervals: oadr2b.Intervals{Interval: []oadr2b.Interval{{Duration: &oadr2b.DurationProp{Duration: "PT1H"}, UID: &oadr2b.UID{Text: "0"},
				SignalPayload: &oadr2b.SignalPayload{PayloadFloat: oadr2b.PayloadFloat{Value: level}}}}}}}},
		Target: oadr2b.Target{VenID: []string{venID}},
	}}
}

// OpenLEADR's VTN against our simulated VEN, over plain HTTP and over
// mutual TLS with XML signatures both ways: registration, report
// registration and requests, events by oadrRequestEvent and by poll with
// oadrCreatedEvent, telemetry in oadrUpdateReport, cancellation.
// OpenLEADR validates every message it receives against the 2.0b schema.
func TestOpenLEADRVTNWithVENSim(t *testing.T) {
	needDocker(t)
	build(t, imageOpenLEADR, "openleadr")
	for _, secure := range []bool{false, true} {
		name := "http"
		if secure {
			name = "tls-signed"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			port := freePort(t)
			cfg := vensim.Config{VTN: fmt.Sprintf("http://127.0.0.1:%d", port), VenName: "sigma-ven"}
			args := []string{"-p", fmt.Sprintf("127.0.0.1:%d:%d", port, port)}
			script := []string{"python", "-u", "vtn.py", strconv.Itoa(port), "ven-olr"}
			if secure {
				pki := testpki.New(t)
				vtnLeaf := pki.Issue(t, "olr-vtn", "127.0.0.1", "localhost")
				venLeaf := pki.Issue(t, "sigma-ven", "127.0.0.1", "localhost")
				dir := t.TempDir()
				pki.Write(t, dir, map[string]testpki.Leaf{"vtn": vtnLeaf})
				args = append(args, "-v", dir+":/certs:ro")
				script = append(script, "/certs", oadr2b.Fingerprint(venLeaf.TLS.Certificate[0]))
				cfg.VTN = fmt.Sprintf("https://127.0.0.1:%d", port)
				cfg.Certificate, cfg.RootCAs, cfg.SignWith = &venLeaf.TLS, pki.Pool, &venLeaf.TLS
				cfg.RequireSigned, cfg.VTNFingerprint = true, oadr2b.Fingerprint(vtnLeaf.TLS.Certificate[0])
			}
			p := startPeer(t, append(append(args, imageOpenLEADR), script...)...)
			p.expect(30*time.Second, "ready")
			waitPort(t, port, 10*time.Second)

			ven := vensim.New(cfg)
			defer ven.Close()
			if err := ven.Register(ctx); err != nil {
				t.Fatalf("register: %v", err)
			}
			signed := "False"
			if secure {
				signed = "True"
			}
			p.expect(5*time.Second, "registration sigma-ven True "+signed) // pull model, xmlSignature
			if ven.VenID() != "ven-olr" || ven.RegistrationID() != "reg-olr-1" {
				t.Fatalf("registered as %q / %q", ven.VenID(), ven.RegistrationID())
			}
			p.expect(5*time.Second, "register-report", "resource-1")
			if rq := ven.Requests(); rq["usage-1"] == "" || rq["status-1"] == "" {
				t.Fatalf("OpenLEADR's report requests: %v", rq)
			}

			if err := ven.RequestEvents(ctx); err != nil {
				t.Fatalf("request events: %v", err)
			}
			ev, ok := ven.Events()["olr-ev-1"]
			if !ok || ev.Signals.Signal[0].Intervals.Interval[0].SignalPayload.PayloadFloat.Value != 2 {
				t.Fatalf("events: %+v", ven.Events())
			}
			p.expect(5*time.Second, "opt ven-olr olr-ev-1 optIn")

			ans, err := ven.Send(ctx, oadr2b.ServiceReport, telemetry(ven.VenID(), ven.Requests()["usage-1"], time.Now(), 1.5, 640))
			if err != nil || ans.UpdatedReport == nil || ans.UpdatedReport.EiResponse.ResponseCode != oadr2b.CodeOK {
				t.Fatalf("telemetry: %+v, %v", ans, err)
			}
			p.expect(5*time.Second, "report resource-1 RealEnergy 1.5")
			p.expect(5*time.Second, "report resource-1 RealPower 640")

			// OpenLEADR also queues the first event for the next poll
			// (oadrRequestEvent does not clear it); then the poll is empty.
			got, err := ven.Poll(ctx)
			if err == nil && got == "oadrDistributeEvent" {
				got, err = ven.Poll(ctx)
			}
			if err != nil || got != "oadrResponse" {
				t.Fatalf("empty poll: %q, %v", got, err)
			}
			p.send("event olr-ev-2 3")
			p.expect(5*time.Second, "event-added olr-ev-2")
			if got, err := ven.Poll(ctx); err != nil || got != "oadrDistributeEvent" {
				t.Fatalf("poll: %q, %v", got, err)
			}
			if _, ok := ven.Events()["olr-ev-2"]; !ok {
				t.Fatalf("events after poll: %+v", ven.Events())
			}
			p.expect(5*time.Second, "opt ven-olr olr-ev-2 optIn")

			if err := ven.CancelRegistration(ctx); err != nil {
				t.Fatalf("cancel: %v", err)
			}
			p.expect(5*time.Second, "cancel ven-olr reg-olr-1")
			if errs := ven.CheckErrors(); len(errs) != 0 {
				t.Fatalf("check errors: %v", errs)
			}
		})
	}
}

// OpenLEADR's VEN client against our simulated VTN, over plain HTTP and
// over mutual TLS with XML signatures both ways: registration, report
// registration (the simulator requests every report), events by
// oadrRequestEvent and by poll with oadrCreatedEvent, oadrCreatedReport
// and oadrUpdateReport, cancellation.
func TestOpenLEADRVENWithVTNSim(t *testing.T) {
	needDocker(t)
	build(t, imageOpenLEADR, "openleadr")
	for _, secure := range []bool{false, true} {
		name := "http"
		if secure {
			name = "tls-signed"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			cfg := vtnsim.Config{VtnID: "SIM-VTN", VenID: "ven-sim-9", RequestReports: true, PollFreq: "PT1S"}
			args := []string{"--add-host=host.docker.internal:host-gateway"}
			var script []string
			if secure {
				pki := testpki.New(t)
				vtnLeaf := pki.Issue(t, "host.docker.internal", "host.docker.internal", "127.0.0.1")
				venLeaf := pki.Issue(t, "olr-ven")
				dir := t.TempDir()
				pki.Write(t, dir, map[string]testpki.Leaf{"ven": venLeaf})
				args = append(args, "-v", dir+":/certs:ro")
				script = []string{"/certs", oadr2b.Fingerprint(vtnLeaf.TLS.Certificate[0])}
				cfg.Certificate, cfg.ClientCAs, cfg.SignWith, cfg.RequireSigned = &vtnLeaf.TLS, pki.Pool, &vtnLeaf.TLS, true
			}
			vtn := vtnsim.New(cfg)
			url, err := vtn.Start()
			if err != nil {
				t.Fatal(err)
			}
			defer vtn.Close()
			if err := vtn.SetEvents(ctx, simpleEvent("sim-ev-1", "ven-sim-9", 0, 2)); err != nil {
				t.Fatal(err)
			}
			_, port, _ := cutPort(url)
			scheme := "http"
			if secure {
				scheme = "https"
			}
			vtnURL := fmt.Sprintf("%s://host.docker.internal:%s/OpenADR2/Simple/2.0b", scheme, port)
			p := startPeer(t, append(append(args, imageOpenLEADR, "python", "-u", "ven.py", vtnURL), script...)...)

			// run() registers, offers its report, asks for events and polls
			// once before it says it is registered.
			p.expect(30*time.Second, "event sim-ev-1 0 SIMPLE 2.0")
			p.expect(10*time.Second, "registered ven-sim-9 reg-sim-1")
			eventually(t, 5*time.Second, "oadrCreatedEvent for sim-ev-1", func() bool { return optedIn(vtn, "sim-ev-1") })
			meta := vtn.Metadata()
			if len(meta) != 1 || meta[0].ReportSpecifierID != "olr-usage" || len(meta[0].Descriptions) != 1 || meta[0].Descriptions[0].RID != "olr-voltage" {
				t.Fatalf("OpenLEADR's METADATA: %+v", meta)
			}
			eventually(t, 5*time.Second, "oadrCreatedReport", func() bool { return len(vtn.Find("oadrCreatedReport")) > 0 })
			eventually(t, 20*time.Second, "oadrUpdateReport with 231.5", func() bool {
				for _, so := range vtn.Find("oadrUpdateReport") {
					for _, r := range so.UpdateReport.Reports {
						if r.Intervals == nil {
							continue
						}
						for _, iv := range r.Intervals.Interval {
							for _, rp := range iv.ReportPayload {
								if rp.RID == "olr-voltage" && rp.PayloadFloat != nil && rp.PayloadFloat.Value == 231.5 {
									return true
								}
							}
						}
					}
				}
				return false
			})

			// A changed event list reaches the VEN by poll.
			if err := vtn.SetEvents(ctx, simpleEvent("sim-ev-2", "ven-sim-9", 0, 3)); err != nil {
				t.Fatal(err)
			}
			p.expect(10*time.Second, "event sim-ev-2 0 SIMPLE 3.0")
			eventually(t, 5*time.Second, "oadrCreatedEvent for sim-ev-2", func() bool { return optedIn(vtn, "sim-ev-2") })
			if len(vtn.Find("oadrPoll")) == 0 {
				t.Fatal("no oadrPoll received")
			}

			p.send("cancel")
			p.expect(10*time.Second, "canceled None")
			if reg, _ := vtn.Registered(); reg != "" {
				t.Fatalf("still registered: %q", reg)
			}
			if errs := vtn.SignatureErrors(); len(errs) != 0 {
				t.Fatalf("signature errors: %v", errs)
			}
		})
	}
}

// telemetry is the simulated VEN's TELEMETRY_USAGE update with each data
// point's payload in an interval of its own. OpenLEADR 0.5.36's VTN reads
// one payload per interval: an interval with several payloads (as
// vensim's SendTelemetry sends, which the 2.0b schema allows) passes its
// schema check and then fails in its report handler with HTTP 500.
func telemetry(venID, requestID string, at time.Time, energyKWh, powerW float64) oadr2b.SignedObject {
	start := &oadr2b.DtStart{DateTime: oadr2b.FormatTime(at)}
	min1 := &oadr2b.DurationProp{Duration: "PT1M"}
	iv := func(rid string, v float64) oadr2b.Interval {
		return oadr2b.Interval{DtStart: start, Duration: min1, ReportPayload: []oadr2b.ReportPayload{
			{RID: rid, PayloadFloat: &oadr2b.PayloadFloat{Value: v}, DataQuality: "Quality Good - Non Specific"}}}
	}
	return oadr2b.SignedObject{UpdateReport: &oadr2b.UpdateReport{RequestID: "ur-interop-1", VenID: venID, Reports: []oadr2b.Report{{
		DtStart: start, Duration: min1, ReportRequestID: requestID, ReportSpecifierID: "usage-1", ReportName: "TELEMETRY_USAGE",
		CreatedDateTime: oadr2b.FormatTime(time.Now()),
		Intervals:       &oadr2b.Intervals{Interval: []oadr2b.Interval{iv("energy", energyKWh), iv("power", powerW)}},
	}}}}
}

// optedIn reports whether the VTN received an optIn for eventID.
func optedIn(vtn *vtnsim.VTN, eventID string) bool {
	for _, so := range vtn.Find("oadrCreatedEvent") {
		rs := so.CreatedEvent.EiCreatedEvent.EventResponses
		if rs == nil {
			continue
		}
		for _, r := range rs.Response {
			if r.QualifiedEventID.EventID == eventID && r.OptType == "optIn" && r.ResponseCode == oadr2b.CodeOK {
				return true
			}
		}
	}
	return false
}

// cutPort splits "scheme://host:port".
func cutPort(url string) (host, port string, ok bool) {
	for i := len(url) - 1; i >= 0; i-- {
		if url[i] == ':' {
			return url[:i], url[i+1:], true
		}
	}
	return url, "", false
}
