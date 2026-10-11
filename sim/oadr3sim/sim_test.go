// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package oadr3sim_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/openadr-sim/sim/oadr3sim"
)

// miniVTN is a small OpenADR 3 VTN for these tests: token discovery and
// the client-credentials grant, vens and resources, programs and events
// filtered by target, and reports. It checks the bearer token on every
// call and records what it is sent.
type miniVTN struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	tokens    int
	vens      []map[string]any
	resources []map[string]any
	reports   []map[string]any
	queries   []url.Values
}

const (
	clientID = "ven-client"
	secret   = "s3cret"
	token    = "tok-1"
)

func newMiniVTN(t *testing.T) *miniVTN {
	m := &miniVTN{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/server", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"tokenURL": m.srv.URL + "/auth/token"})
	})
	mux.HandleFunc("POST /auth/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "client_credentials" ||
			r.Form.Get("client_id") != clientID || r.Form.Get("client_secret") != secret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		m.mu.Lock()
		m.tokens++
		m.mu.Unlock()
		writeJSON(w, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600})
	})
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+token {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			m.mu.Lock()
			m.queries = append(m.queries, r.URL.Query())
			m.mu.Unlock()
			h(w, r)
		}
	}
	mux.HandleFunc("GET /vens", authed(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		out := []map[string]any{}
		for _, v := range m.vens {
			if v["venName"] == r.URL.Query().Get("venName") {
				out = append(out, v)
			}
		}
		writeJSON(w, out)
	}))
	mux.HandleFunc("POST /vens", authed(func(w http.ResponseWriter, r *http.Request) {
		v := readJSON(t, r)
		m.mu.Lock()
		v["id"] = fmt.Sprintf("ven-%d", len(m.vens)+1)
		m.vens = append(m.vens, v)
		m.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, v)
	}))
	mux.HandleFunc("POST /resources", authed(func(w http.ResponseWriter, r *http.Request) {
		v := readJSON(t, r)
		m.mu.Lock()
		v["id"] = fmt.Sprintf("res-%d", len(m.resources)+1)
		m.resources = append(m.resources, v)
		m.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, v)
	}))
	mux.HandleFunc("GET /programs", authed(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, []map[string]any{{"id": "prog-1", "objectType": "PROGRAM", "programName": "demo"}})
	}))
	mux.HandleFunc("GET /events", authed(func(w http.ResponseWriter, r *http.Request) {
		out := []map[string]any{}
		if r.URL.Query().Get("targets") == "group-a" {
			out = append(out, map[string]any{"id": "ev-1", "objectType": "EVENT", "programID": "prog-1"})
		}
		writeJSON(w, out)
	}))
	mux.HandleFunc("POST /reports", authed(func(w http.ResponseWriter, r *http.Request) {
		v := readJSON(t, r)
		m.mu.Lock()
		v["id"] = "rep-1"
		m.reports = append(m.reports, v)
		m.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, v)
	}))
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(t *testing.T, r *http.Request) map[string]any {
	var v map[string]any
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		t.Errorf("request body: %v", err)
	}
	return v
}

// The VEN enrols (creating its ven object once and its resources),
// reads programs and the events for its targets, and reports a value,
// with a token from the discovered token endpoint.
func TestVENAgainstMiniVTN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	vtn := newMiniVTN(t)
	ven := oadr3sim.NewVEN(vtn.srv.URL, clientID, secret, "ven-a", nil)
	if err := ven.Enrol(ctx, "meter-1", "battery-1"); err != nil {
		t.Fatal(err)
	}
	if ven.VenID != "ven-1" {
		t.Fatalf("VenID %q", ven.VenID)
	}
	if vtn.vens[0]["objectType"] != "VEN_VEN_REQUEST" || vtn.vens[0]["venName"] != "ven-a" {
		t.Fatalf("ven object sent: %v", vtn.vens[0])
	}
	if len(vtn.resources) != 2 || vtn.resources[1]["venID"] != "ven-1" || vtn.resources[1]["objectType"] != "VEN_RESOURCE_REQUEST" {
		t.Fatalf("resources sent: %v", vtn.resources)
	}

	// Enrolling again finds the ven object instead of creating one.
	again := oadr3sim.NewVEN(vtn.srv.URL, clientID, secret, "ven-a", nil)
	if err := again.Enrol(ctx); err != nil || again.VenID != "ven-1" || len(vtn.vens) != 1 {
		t.Fatalf("second enrolment: %v, %q, %d vens", err, again.VenID, len(vtn.vens))
	}

	progs, err := ven.Programs(ctx)
	if err != nil || len(progs) != 1 || progs[0]["id"] != "prog-1" {
		t.Fatalf("programs: %v, %v", progs, err)
	}
	if evs, err := ven.Events(ctx); err != nil || len(evs) != 0 {
		t.Fatalf("events without targets: %v, %v", evs, err)
	}
	ven.Targets = []string{"group-a"}
	evs, err := ven.Events(ctx)
	if err != nil || len(evs) != 1 || evs[0]["id"] != "ev-1" {
		t.Fatalf("events for group-a: %v, %v", evs, err)
	}
	last := vtn.queries[len(vtn.queries)-1]
	if last.Get("skip") != "0" || last.Get("limit") == "" {
		t.Fatalf("paging parameters: %v", last)
	}

	rep, err := ven.Report(ctx, "ev-1", "meter-1", "USAGE", 0, 4.2)
	if err != nil || rep["id"] != "rep-1" {
		t.Fatalf("report: %v, %v", rep, err)
	}
	b, _ := json.Marshal(vtn.reports[0])
	for _, want := range []string{`"eventID":"ev-1"`, `"clientName":"ven-a"`, `"resourceName":"meter-1"`, `"type":"USAGE"`, `"values":[4.2]`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("report lacks %s: %s", want, b)
		}
	}
	if vtn.tokens != 2 { // one per client
		t.Errorf("%d tokens fetched, want 2", vtn.tokens)
	}

	// Wrong credentials stop at the token endpoint.
	bad := oadr3sim.NewVEN(vtn.srv.URL, clientID, "wrong", "ven-b", nil)
	if err := bad.Enrol(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("wrong secret: %v", err)
	}
}

// The webhook answers the echo challenge (or refuses it when told to)
// and records notifications that carry its bearer token.
func TestWebhook(t *testing.T) {
	w, err := oadr3sim.NewWebhook(nil, "hook-token")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	get := func() string {
		resp, err := http.Get(w.URL + "?echo=abc123")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if got := get(); got != "abc123" {
		t.Fatalf("echo answered %q", got)
	}
	w.SetEcho(false)
	if got := get(); got == "abc123" {
		t.Fatal("echo answered while refusing")
	}
	post := func(bearer string) int {
		req, _ := http.NewRequest(http.MethodPost, w.URL, strings.NewReader(`{"objectType":"EVENT","operation":"POST"}`))
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := post("wrong"); got != http.StatusUnauthorized {
		t.Fatalf("wrong bearer: %d", got)
	}
	if got := post("hook-token"); got != http.StatusOK {
		t.Fatalf("notification: %d", got)
	}
	if n := w.Notes(); len(n) != 1 || n[0]["operation"] != "POST" {
		t.Fatalf("notes: %v", n)
	}
}
