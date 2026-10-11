// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/openadr-sim/sim/oadr3sim"
	"github.com/cB-Sigma/openadr/oadr3"
)

// Client credentials of openleadr-rs's own user fixtures
// (fixtures/users.sql in its repository, loaded at test time).
const (
	rsBLClient, rsBLSecret   = "bl-client", "bl-client"
	rsVENClient, rsVENSecret = "ven-client-client-id", "ven-client"
)

// startOpenLEADRRS runs PostgreSQL and the openleadr-rs VTN (built from
// peer/openleadr-rs at a pinned commit), loads openleadr-rs's user
// fixtures and returns the VTN's base URL.
func startOpenLEADRRS(t *testing.T) string {
	t.Helper()
	build(t, imageOpenLEADRRS, "openleadr-rs")
	pgPort, vtnPort := freePort(t), freePort(t)
	pg := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:5432", pgPort),
		"-e", "POSTGRES_USER=openadr", "-e", "POSTGRES_PASSWORD=openadr", "-e", "POSTGRES_DB=openadr", imagePostgres)
	deadline := time.Now().Add(60 * time.Second)
	for exec.Command("docker", "exec", pg.name, "pg_isready", "-U", "openadr", "-h", "127.0.0.1").Run() != nil {
		if time.Now().After(deadline) {
			t.Fatalf("PostgreSQL did not start:\n%s", pg.output())
		}
		time.Sleep(500 * time.Millisecond)
	}
	base := fmt.Sprintf("http://127.0.0.1:%d", vtnPort)
	vtn := startPeer(t, "--add-host=host.docker.internal:host-gateway", "-p", fmt.Sprintf("127.0.0.1:%d:3000", vtnPort),
		"-e", fmt.Sprintf("DATABASE_URL=postgres://openadr:openadr@host.docker.internal:%d/openadr", pgPort),
		"-e", "OAUTH_TOKEN_URL="+base+"/auth/token", "-e", "RUST_LOG=openleadr_vtn=info", imageOpenLEADRRS)
	deadline = time.Now().Add(60 * time.Second)
	for {
		resp, err := http.Get(base + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("openleadr-rs did not start:\n%s", vtn.output())
		}
		time.Sleep(500 * time.Millisecond)
	}
	// The VTN has migrated its database; add its fixture users.
	sql, err := exec.Command("docker", "run", "--rm", "--entrypoint", "cat", imageOpenLEADRRS, "/fixtures/users.sql").Output()
	if err != nil {
		t.Fatalf("reading the user fixtures: %v", err)
	}
	load := exec.Command("docker", "exec", "-i", pg.name, "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "openadr", "-d", "openadr")
	load.Stdin = bytes.NewReader(sql)
	if out, err := load.CombinedOutput(); err != nil {
		t.Fatalf("loading the user fixtures: %v\n%s", err, out)
	}
	return base
}

// openleadr-rs's OpenADR 3 VTN against our OpenADR 3 VEN simulator: a
// business-logic client (our oadr3 client) creates a program and an
// event; the simulated VEN gets a token through the discovered token
// endpoint, enrols (its ven object and a resource), reads the program
// and the event and reports a value, which the business client reads
// back.
func TestOpenLEADRRSWithOADR3Sim(t *testing.T) {
	needDocker(t)
	base := startOpenLEADRRS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	bl := oadr3.NewClient(oadr3.ClientConfig{BaseURL: base, ClientID: rsBLClient, Secret: rsBLSecret})
	var prog oadr3.Object
	if _, err := bl.Do(ctx, http.MethodPost, "/programs", nil, oadr3.Object{"programName": "sigma-program"}, &prog); err != nil {
		t.Fatalf("create program: %v", err)
	}
	progID, _ := prog["id"].(string)
	if progID == "" || prog["objectType"] != oadr3.TypeProgram {
		t.Fatalf("program: %v", prog)
	}
	start := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	var ev oadr3.Object
	if _, err := bl.Do(ctx, http.MethodPost, "/events", nil, oadr3.Object{
		"programID": progID, "eventName": "sigma-event",
		"intervalPeriod": map[string]any{"start": start, "duration": "PT1H"},
		"intervals":      []any{map[string]any{"id": 0, "payloads": []any{map[string]any{"type": "SIMPLE", "values": []any{1}}}}},
	}, &ev); err != nil {
		t.Fatalf("create event: %v", err)
	}
	evID, _ := ev["id"].(string)
	if evID == "" {
		t.Fatalf("event: %v", ev)
	}

	ven := oadr3sim.NewVEN(base, rsVENClient, rsVENSecret, "sigma-ven", nil)
	if err := ven.Enrol(ctx, "meter-1"); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if ven.VenID == "" {
		t.Fatal("no venID after enrolment")
	}
	// Enrolling again finds the same ven object.
	again := oadr3sim.NewVEN(base, rsVENClient, rsVENSecret, "sigma-ven", nil)
	if err := again.Enrol(ctx); err != nil || again.VenID != ven.VenID {
		t.Fatalf("second enrolment: %v, %q (first %q)", err, again.VenID, ven.VenID)
	}
	progs, err := ven.Programs(ctx)
	if err != nil {
		t.Fatalf("programs: %v", err)
	}
	if !hasID(progs, progID) {
		t.Fatalf("the VEN does not see program %s: %v", progID, progs)
	}
	evs, err := ven.Events(ctx)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if !hasID(evs, evID) {
		t.Fatalf("the VEN does not see event %s: %v", evID, evs)
	}
	for _, e := range evs {
		if e["id"] == evID {
			if w := oadr3.EventWindow(e); w.Start.IsZero() || w.End.Sub(w.Start) != time.Hour {
				t.Fatalf("event window of %v: %+v", e, w)
			}
		}
	}
	rep, err := ven.Report(ctx, evID, "meter-1", "USAGE", 0, 4.25)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if rep["objectType"] != oadr3.TypeReport || rep["eventID"] != evID {
		t.Fatalf("report answer: %v", rep)
	}
	reports, err := bl.All(ctx, "/reports", nil)
	if err != nil {
		t.Fatalf("reports: %v", err)
	}
	if !hasID(reports, rep["id"].(string)) || !strings.Contains(fmt.Sprint(reports), "4.25") {
		t.Fatalf("the business client does not see the report: %v", reports)
	}
}

func hasID(objs []oadr3.Object, id string) bool {
	for _, o := range objs {
		if o["id"] == id {
			return true
		}
	}
	return false
}
