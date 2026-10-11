// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package oadr3sim

// A simulated OpenADR 3 VTN: the VTN of github.com/cB-Sigma/openadr's
// oadr3/vtn package on a local address, with demo clients and, on
// request, a demo program and event, for testing VENs and business logic.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cB-Sigma/openadr/oadr3"
	"github.com/cB-Sigma/openadr/oadr3/vtn"
)

// Demo credentials and target of the simulated VTN (demo values only).
const (
	DemoBLClientID  = "sim-bl"
	DemoBLSecret    = "sim-bl-secret"
	DemoVENClientID = "sim-ven"
	DemoVENSecret   = "sim-ven-secret"
	DemoProgramName = "sim-tariff"
	DemoTarget      = "sim-group"
)

// VTNConfig configures a simulated VTN.
type VTNConfig struct {
	// Version is vtn.Version31 (default) or vtn.Version30.
	Version string
	// BasePath before /programs (default "").
	BasePath string
	// Clients may get tokens (default: the demo BL and VEN clients).
	Clients []vtn.Client
	// Demo creates a program and an event targeted at DemoTarget.
	Demo bool
	// Certificate serves TLS (nil: plain HTTP).
	Certificate *tls.Certificate
	// AnonymousRead answers untargeted programs and events without a
	// token.
	AnonymousRead bool
	// Config, when set, is used as the base of the VTN's configuration
	// (Clients, Version, BasePath and AnonymousRead above override it
	// when set).
	Config *vtn.Config
}

// VTN is a simulated OpenADR 3 VTN.
type VTN struct {
	cfg VTNConfig
	v   *vtn.VTN
	srv *http.Server
	url string
}

// NewVTN makes a simulated VTN (no I/O until Start).
func NewVTN(cfg VTNConfig) (*VTN, error) {
	c := vtn.Config{}
	if cfg.Config != nil {
		c = *cfg.Config
	}
	if cfg.Version != "" {
		c.Version = cfg.Version
	}
	if cfg.BasePath != "" {
		c.BasePath = cfg.BasePath
	}
	if cfg.AnonymousRead {
		c.AnonymousRead = true
	}
	switch {
	case len(cfg.Clients) > 0:
		c.Clients = cfg.Clients
	case len(c.Clients) == 0:
		c.Clients = []vtn.Client{{ClientID: DemoBLClientID, Secret: DemoBLSecret, Role: vtn.RoleBL},
			{ClientID: DemoVENClientID, Secret: DemoVENSecret, Role: vtn.RoleVEN}}
	}
	// Local webhooks are the point of a simulator.
	c.Webhooks.AllowHTTP, c.Webhooks.AllowPrivate = true, true
	v, err := vtn.New(c)
	if err != nil {
		return nil, err
	}
	return &VTN{cfg: cfg, v: v}, nil
}

// VTN gives the underlying VTN (for business logic in the test: Create,
// List, …).
func (s *VTN) VTN() *vtn.VTN { return s.v }

// URL is the VTN's base URL (after Start).
func (s *VTN) URL() string { return s.url }

// Start listens on addr (e.g. 127.0.0.1:0) and gives the base URL.
func (s *VTN) Start(addr string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	scheme := "http"
	if s.cfg.Certificate != nil {
		ln = tls.NewListener(ln, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*s.cfg.Certificate}})
		scheme = "https"
	}
	s.url = fmt.Sprintf("%s://%s%s", scheme, ln.Addr(), s.cfg.BasePath)
	if s.cfg.Config == nil || s.cfg.Config.PublicURL == "" {
		s.v.SetPublicURL(s.url)
	}
	s.srv = &http.Server{Handler: s.v, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = s.srv.Serve(ln) }()
	if s.cfg.Demo {
		if err := s.demo(context.Background()); err != nil {
			s.Close()
			return "", err
		}
	}
	return s.url, nil
}

func (s *VTN) demo(ctx context.Context) error {
	targets := []string{DemoTarget}
	var t any = targets
	if s.cfg.Version == vtn.Version30 {
		t = []any{map[string]any{"type": "GROUP", "values": []any{DemoTarget}}}
	}
	if _, err := s.v.Create(ctx, oadr3.TypeProgram, oadr3.Object{"programName": DemoProgramName, "targets": t}); err != nil {
		return err
	}
	_, err := s.AddEvent(ctx, "sim-peak", 0.25, DemoTarget)
	return err
}

// AddEvent creates an event of an hour from now in the demo program with
// one PRICE interval.
func (s *VTN) AddEvent(ctx context.Context, name string, price float64, targets ...string) (oadr3.Object, error) {
	progs, err := s.v.List(ctx, oadr3.TypeProgram)
	if err != nil {
		return nil, err
	}
	var pid string
	for _, p := range progs {
		if p["programName"] == DemoProgramName {
			pid = oadr3.Str(p, "id")
		}
	}
	if pid == "" {
		p, err := s.v.Create(ctx, oadr3.TypeProgram, oadr3.Object{"programName": DemoProgramName})
		if err != nil {
			return nil, err
		}
		pid = oadr3.Str(p, "id")
	}
	ev := oadr3.Object{"programID": pid, "eventName": name,
		"intervalPeriod": map[string]any{"start": time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), "duration": "PT1H"},
		"intervals":      []any{map[string]any{"id": 0, "payloads": []any{map[string]any{"type": "PRICE", "values": []any{price}}}}}}
	if len(targets) > 0 {
		if s.cfg.Version == vtn.Version30 {
			ev["targets"] = []any{map[string]any{"type": "GROUP", "values": targets}}
		} else {
			ev["targets"] = targets
		}
	}
	return s.v.Create(ctx, oadr3.TypeEvent, ev)
}

// Grant gives the ven venID the targets, as business logic does after
// enrolment.
func (s *VTN) Grant(ctx context.Context, venID string, targets ...string) error {
	ven, err := s.v.Get(ctx, oadr3.TypeVEN, venID)
	if err != nil {
		return err
	}
	if ven["clientID"] == nil {
		return errors.New("oadr3sim: the ven has no client")
	}
	o := oadr3.Object{"venName": ven["venName"], "clientID": ven["clientID"], "attributes": ven["attributes"]}
	if s.cfg.Version == vtn.Version30 {
		// Stored 3.0 targets are "TYPE:value"; new ones are groups.
		var list []any
		for _, t := range oadr3.Strs(ven["targets"]) {
			typ, val, _ := strings.Cut(t, ":")
			list = append(list, map[string]any{"type": typ, "values": []any{val}})
		}
		for _, t := range targets {
			list = append(list, map[string]any{"type": "GROUP", "values": []any{t}})
		}
		o["targets"] = list
	} else {
		o["targets"] = append(oadr3.Strs(ven["targets"]), targets...)
	}
	_, err = s.v.Update(ctx, oadr3.TypeVEN, venID, o)
	return err
}

// Close stops the VTN.
func (s *VTN) Close() {
	if s.srv != nil {
		_ = s.srv.Close()
	}
	_ = s.v.Close()
}
