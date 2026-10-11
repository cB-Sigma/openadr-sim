// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package oadr3sim_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/cB-Sigma/openadr-sim/sim/oadr3sim"
	"github.com/cB-Sigma/openadr/oadr3"
)

// The 3.0 mode: demo objects in the 3.0 target form, and a grant.
func TestSimulatedVTN30(t *testing.T) {
	v, err := oadr3sim.NewVTN(oadr3sim.VTNConfig{Demo: true, Version: "3.0"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	ctx := context.Background()
	c := oadr3.NewClient(oadr3.ClientConfig{BaseURL: v.URL(), ClientID: oadr3sim.DemoVENClientID, Secret: oadr3sim.DemoVENSecret, TokenURL: v.URL() + "/auth/token"})
	var ven oadr3.Object
	if _, err := c.Do(ctx, http.MethodPost, "/vens", nil, oadr3.Object{"venName": "v"}, &ven); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := v.Grant(ctx, oadr3.Str(ven, "id"), oadr3sim.DemoTarget); err != nil {
			t.Fatal(err)
		}
	}
	evs, err := c.All(ctx, "/events", map[string][]string{"targetType": {"GROUP"}, "targetValues": {oadr3sim.DemoTarget}})
	if err != nil || len(evs) != 1 {
		t.Fatalf("3.0 events: %v %v", evs, err)
	}
}

// The simulated VTN with its demo program and event, the simulated VEN
// enrolling with it and reporting, and a webhook notified of a new event.
func TestSimulatedVTN(t *testing.T) {
	v, err := oadr3sim.NewVTN(oadr3sim.VTNConfig{Demo: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ven := oadr3sim.NewVEN(v.URL(), oadr3sim.DemoVENClientID, oadr3sim.DemoVENSecret, "site-1", nil)
	if err := ven.Enrol(ctx, "meter-1"); err != nil {
		t.Fatal(err)
	}
	if err := v.Grant(ctx, ven.VenID, oadr3sim.DemoTarget); err != nil {
		t.Fatal(err)
	}
	ven.Targets = []string{oadr3sim.DemoTarget}
	evs, err := ven.Events(ctx)
	if err != nil || len(evs) != 1 {
		t.Fatalf("events: %v %v", evs, err)
	}
	if _, err := ven.Report(ctx, oadr3.Str(evs[0], "id"), "meter-1", "USAGE", 0, 1.25); err != nil {
		t.Fatal(err)
	}
	reps, err := v.VTN().List(ctx, oadr3.TypeReport)
	if err != nil || len(reps) != 1 {
		t.Fatalf("reports: %v %v", reps, err)
	}

	hook, err := oadr3sim.NewWebhook(nil, "hook-bearer")
	if err != nil {
		t.Fatal(err)
	}
	defer hook.Close()
	if _, err := ven.C.Do(ctx, http.MethodPost, "/subscriptions", nil, oadr3.Object{"clientName": "site-1", "targets": []string{oadr3sim.DemoTarget},
		"objectOperations": []any{map[string]any{"objects": []string{"EVENT"}, "operations": []string{"CREATE"}, "callbackUrl": hook.URL, "bearerToken": "hook-bearer"}}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := v.AddEvent(ctx, "second", 0.5, oadr3sim.DemoTarget); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); len(hook.Notes()) == 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no notification")
		}
	}
	if n := hook.Notes()[0]; n["operation"] != "CREATE" || n["objectType"] != oadr3.TypeEvent {
		t.Fatalf("notification: %v", n)
	}
}
