// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package vensim_test

import (
	"context"
	"crypto/tls"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/openadr-sim/internal/testpki"
	"github.com/cB-Sigma/openadr-sim/sim/vensim"
	"github.com/cB-Sigma/openadr/oadr2b"
	"github.com/cB-Sigma/openadr/oadr2b/vtn"
)

// The simulated VEN against openadr's ready VTN (oadr2b/vtn), over plain
// HTTP and over mutual TLS with XML signatures both ways: registration,
// report registration with requests, events by poll with
// oadrCreatedEvent, telemetry, opts and cancellation.
func TestVENSimWithOpenADRVTN(t *testing.T) {
	for _, secure := range []bool{false, true} {
		name := "http"
		if secure {
			name = "tls-signed"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			var mu sync.Mutex
			values := map[string]float64{}
			opts := map[string]string{}
			cfg := vtn.Config{VtnID: "lib-vtn",
				OnRegisterReport: func(_ context.Context, _ string, reports []oadr2b.Report) []oadr2b.ReportRequest {
					return vtn.RequestAll(reports, time.Minute, time.Minute)
				},
				OnUpdateReport: func(_ context.Context, _ string, reports []oadr2b.Report) error {
					mu.Lock()
					defer mu.Unlock()
					for _, r := range reports {
						for _, iv := range r.Intervals.Interval {
							for _, p := range iv.ReportPayload {
								if p.PayloadFloat != nil {
									values[p.RID] = p.PayloadFloat.Value
								}
							}
						}
					}
					return nil
				},
				OnEventResponse: func(_ context.Context, _, eventID, optType string) {
					mu.Lock()
					opts[eventID] = optType
					mu.Unlock()
				}}
			vcfg := vensim.Config{VenName: "sim"}
			srv := httptest.NewUnstartedServer(nil)
			if secure {
				pki := testpki.New(t)
				vtnLeaf := pki.Issue(t, "vtn", "127.0.0.1")
				venLeaf := pki.Issue(t, "ven")
				s, _ := oadr2b.NewSigner(vtnLeaf.TLS)
				cfg.Signer, cfg.RequireSignatures = s, true
				tc, err := vtn.ServerTLSConfig(oadr2b.TLSProfileOpenADR, pki.Pool, vtnLeaf.TLS)
				if err != nil {
					t.Fatal(err)
				}
				srv.TLS = tc
				vcfg.Certificate, vcfg.RootCAs, vcfg.SignWith, vcfg.RequireSigned = &venLeaf.TLS, pki.Pool, &venLeaf.TLS, true
			}
			v := vtn.New(cfg)
			defer v.Close()
			srv.Config.Handler = v
			if secure {
				srv.StartTLS()
			} else {
				srv.Start()
			}
			defer srv.Close()
			vcfg.VTN = srv.URL
			if secure {
				vcfg.MinTLS, vcfg.MaxTLS = tls.VersionTLS12, tls.VersionTLS12
				vcfg.CipherSuites = oadr2b.MandatedCipherSuites
			}
			ven := vensim.New(vcfg)
			defer ven.Close()
			if err := ven.Register(ctx); err != nil {
				t.Fatalf("register: %v", err)
			}
			venID := ven.VenID()
			if rq := ven.Requests(); rq["usage-1"] == "" || rq["status-1"] == "" {
				t.Fatalf("report requests: %v", rq)
			}
			if err := v.AddEvent(venID, vtn.EventSpec{ID: "ev-1", Start: time.Now(), Intervals: []vtn.IntervalSpec{{Duration: time.Hour, Value: 2}}}.Build()); err != nil {
				t.Fatal(err)
			}
			if got, err := ven.Poll(ctx); err != nil || got != "oadrDistributeEvent" {
				t.Fatalf("poll: %q, %v", got, err)
			}
			if err := ven.SendTelemetry(ctx, time.Now(), 1.5, 640, true); err != nil {
				t.Fatalf("telemetry: %v", err)
			}
			if err := ven.CreateOpt(ctx, "opt-1", "optOut", "ev-1", 0); err != nil {
				t.Fatalf("opt: %v", err)
			}
			if err := ven.CancelOpt(ctx, "opt-1"); err != nil {
				t.Fatalf("cancel opt: %v", err)
			}
			mu.Lock()
			if opts["ev-1"] != "optIn" || values["energy"] != 1.5 || values["power"] != 640 {
				t.Errorf("opts %v, values %v", opts, values)
			}
			mu.Unlock()
			if v.OptState(venID, "ev-1") != "optOut" {
				t.Errorf("opt state %q", v.OptState(venID, "ev-1"))
			}
			if err := ven.CancelRegistration(ctx); err != nil {
				t.Fatalf("cancel: %v", err)
			}
			if r, _ := v.Registration(ctx, venID); r != nil {
				t.Fatalf("still registered: %+v", r)
			}
		})
	}
}
