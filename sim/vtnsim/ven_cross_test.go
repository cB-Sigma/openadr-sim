// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package vtnsim_test

import (
	"context"
	"testing"
	"time"

	"github.com/cB-Sigma/openadr-sim/internal/testpki"
	"github.com/cB-Sigma/openadr-sim/sim/vtnsim"
	"github.com/cB-Sigma/openadr/oadr2b"
	"github.com/cB-Sigma/openadr/oadr2b/ven"
)

func eventually(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %s", what, within)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func simpleEvent(id, venID string, level float64) oadr2b.OadrEvent {
	now := time.Now()
	return oadr2b.OadrEvent{ResponseRequired: "always", EiEvent: oadr2b.EiEvent{
		Descriptor: oadr2b.EventDescriptor{EventID: id, MarketContext: oadr2b.MarketContext{MarketContext: "http://sim.test/mc"},
			CreatedDateTime: oadr2b.FormatTime(now), EventStatus: "active"},
		ActivePeriod: oadr2b.ActivePeriod{Properties: oadr2b.Properties{DtStart: oadr2b.DtStart{DateTime: oadr2b.FormatTime(now.Add(-time.Minute))},
			Duration: oadr2b.DurationProp{Duration: "PT1H"}}, Components: oadr2b.Components{Nil: "true"}},
		Signals: oadr2b.EventSignals{Signal: []oadr2b.EventSignal{{SignalName: "SIMPLE", SignalType: "level", SignalID: "s1",
			Intervals: oadr2b.Intervals{Interval: []oadr2b.Interval{{Duration: &oadr2b.DurationProp{Duration: "PT1H"}, UID: &oadr2b.UID{Text: "0"},
				SignalPayload: &oadr2b.SignalPayload{PayloadFloat: oadr2b.PayloadFloat{Value: level}}}}}}}},
		Target: oadr2b.Target{VenID: []string{venID}},
	}}
}

func optedIn(v *vtnsim.VTN, eventID string) bool {
	for _, so := range v.Find("oadrCreatedEvent") {
		if rs := so.CreatedEvent.EiCreatedEvent.EventResponses; rs != nil {
			for _, r := range rs.Response {
				if r.QualifiedEventID.EventID == eventID && r.OptType == "optIn" {
					return true
				}
			}
		}
	}
	return false
}

func reported(v *vtnsim.VTN, rid string, value float64) bool {
	for _, so := range v.Find("oadrUpdateReport") {
		for _, r := range so.UpdateReport.Reports {
			if r.Intervals == nil {
				continue
			}
			for _, iv := range r.Intervals.Interval {
				for _, p := range iv.ReportPayload {
					if p.RID == rid && p.PayloadFloat != nil && p.PayloadFloat.Value == value {
						return true
					}
				}
			}
		}
	}
	return false
}

// openadr's ready VEN (oadr2b/ven) against the simulated VTN, pulling and
// pushed, over plain HTTP and mutual TLS with signatures both ways.
func TestOpenADRVENWithVTNSim(t *testing.T) {
	for _, c := range []struct {
		name         string
		secure, push bool
	}{{"http-pull", false, false}, {"http-push", false, true}, {"tls-signed-pull", true, false}, {"tls-signed-push", true, true}} {
		t.Run(c.name, func(t *testing.T) {
			cfg := vtnsim.Config{VtnID: "SIM-VTN", VenID: "ven-x", RequestReports: true, PollFreq: "PT1S"}
			vc := ven.Config{VenName: "lib-ven", Reports: []oadr2b.Report{{ReportSpecifierID: "usage", ReportName: "METADATA_TELEMETRY_USAGE",
				Descriptions: []oadr2b.ReportDescription{{RID: "power", ReportType: "usage", ReadingType: "Direct Read",
					SamplingRate: &oadr2b.SamplingRate{MinPeriod: "PT1S", MaxPeriod: "PT1H"},
					ItemBase:     &oadr2b.ItemBase{XMLName: oadr2b.XMLName(oadr2b.NSPower, "powerReal"), ItemDescription: "RealPower", ItemUnits: "W"}}}}},
				ReadData: func(context.Context, string, string, time.Time) (oadr2b.ReportPayload, bool) {
					return oadr2b.ReportPayload{PayloadFloat: &oadr2b.PayloadFloat{Value: 640}}, true
				}}
			if c.secure {
				pki := testpki.New(t)
				vtnLeaf := pki.Issue(t, "vtn", "127.0.0.1")
				venLeaf := pki.Issue(t, "ven", "127.0.0.1")
				cfg.Certificate, cfg.ClientCAs, cfg.SignWith, cfg.RequireSigned = &vtnLeaf.TLS, pki.Pool, &vtnLeaf.TLS, true
				s, _ := oadr2b.NewSigner(venLeaf.TLS)
				vc.Certificate, vc.RootCAs, vc.TLSProfile, vc.Signer, vc.RequireSignatures = &venLeaf.TLS, pki.Pool, oadr2b.TLSProfileOpenADR, s, true
			}
			if c.push {
				vc.PushListen = "127.0.0.1:0"
			}
			sim := vtnsim.New(cfg)
			url, err := sim.Start()
			if err != nil {
				t.Fatal(err)
			}
			defer sim.Close()
			vc.VTNURL = url
			vn, err := ven.New(vc)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			done := make(chan error)
			go func() { done <- vn.Run(ctx) }()
			eventually(t, 10*time.Second, "registration", func() bool { return vn.RegistrationID() == "reg-sim-1" })
			if reg, push := sim.Registered(); reg != "reg-sim-1" || (push != "") != c.push {
				t.Fatalf("registered %q, push %q", reg, push)
			}
			if err := sim.SetEvents(ctx, simpleEvent("sim-ev-1", "ven-x", 2)); err != nil {
				t.Fatal(err)
			}
			eventually(t, 10*time.Second, "oadrCreatedEvent", func() bool { return optedIn(sim, "sim-ev-1") })
			eventually(t, 10*time.Second, "oadrUpdateReport", func() bool { return reported(sim, "power", 640) })
			if len(sim.Find("oadrCreatedReport")) == 0 {
				t.Fatal("no oadrCreatedReport")
			}
			if err := vn.CancelRegistration(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if errs := sim.SignatureErrors(); len(errs) != 0 {
				t.Fatalf("signature errors: %v", errs)
			}
		})
	}
}
