// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Command oadrsim runs the OpenADR simulators of this module:
//
//	oadrsim vtn [-ven-id ven-1] [-level 1]
//	    an OpenADR 2.0b VTN (plain HTTP on 127.0.0.1) holding one demo
//	    SIMPLE event, until interrupted
//	oadrsim ven -vtn URL [-ven-id ven-1] [-polls 3] [-every 2s]
//	    an OpenADR 2.0b VEN (plain HTTP): registers, asks for events and
//	    polls
//	oadrsim ven3 -vtn URL -client-id ID -secret S [-name ven-1]
//	    an OpenADR 3 VEN: enrols over the REST API and lists programs and
//	    events
//	oadrsim vtn3 [-addr 127.0.0.1:0] [-version 3.1] [-base-path P] [-demo] [-anonymous]
//	    an OpenADR 3 VTN (plain HTTP) with demo BL and VEN clients and,
//	    with -demo (the default), a demo program and event, until
//	    interrupted
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/cB-Sigma/openadr-sim/sim/oadr3sim"
	"github.com/cB-Sigma/openadr-sim/sim/vensim"
	"github.com/cB-Sigma/openadr-sim/sim/vtnsim"
	"github.com/cB-Sigma/openadr/oadr2b"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "oadrsim:", err)
		os.Exit(1)
	}
}

const usage = "usage: oadrsim vtn|ven|vtn3|ven3 [flags] (oadrsim <command> -h for the flags)"

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch args[0] {
	case "vtn":
		return runVTN(ctx, args[1:], out)
	case "ven":
		return runVEN(ctx, args[1:], out)
	case "ven3":
		return runVEN3(ctx, args[1:], out)
	case "vtn3":
		return runVTN3(ctx, args[1:], out)
	}
	return errors.New(usage)
}

func runVTN3(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("vtn3", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:0", "address to listen on")
	version := fs.String("version", "3.1", "OpenADR version: 3.1 or 3.0")
	basePath := fs.String("base-path", "", "path before /programs, e.g. /openadr3/3.1.0")
	demo := fs.Bool("demo", true, "create a demo program and event")
	anonymous := fs.Bool("anonymous", false, "answer untargeted programs and events without a token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	v, err := oadr3sim.NewVTN(oadr3sim.VTNConfig{Version: *version, BasePath: *basePath, Demo: *demo, AnonymousRead: *anonymous})
	if err != nil {
		return err
	}
	url, err := v.Start(*addr)
	if err != nil {
		return err
	}
	defer v.Close()
	fmt.Fprintf(out, "OpenADR %s VTN listening on %s\n", *version, url)
	fmt.Fprintf(out, "business logic: client ID %s, secret %s\n", oadr3sim.DemoBLClientID, oadr3sim.DemoBLSecret)
	fmt.Fprintf(out, "VEN: client ID %s, secret %s (demo values)\n", oadr3sim.DemoVENClientID, oadr3sim.DemoVENSecret)
	<-ctx.Done()
	st := v.VTN().Status()
	fmt.Fprintf(out, "objects: %d program(s), %d event(s), %d ven(s), %d report(s)\n", st.Objects["PROGRAM"], st.Objects["EVENT"], st.Objects["VEN"], st.Objects["REPORT"])
	return nil
}

func runVTN(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("vtn", flag.ContinueOnError)
	venID := fs.String("ven-id", "ven-1", "venID given to the VEN that registers")
	level := fs.Float64("level", 1, "SIMPLE signal level of the demo event")
	if err := fs.Parse(args); err != nil {
		return err
	}
	v := vtnsim.New(vtnsim.Config{VtnID: "oadrsim", VenID: *venID})
	url, err := v.Start()
	if err != nil {
		return err
	}
	defer v.Close()
	if err := v.SetEvents(ctx, demoEvent(*venID, *level, time.Now())); err != nil {
		return err
	}
	fmt.Fprintf(out, "OpenADR 2.0b VTN listening on %s (one SIMPLE event, level %g)\n", url, *level)
	<-ctx.Done()
	fmt.Fprintf(out, "received %d messages\n", len(v.Received()))
	return nil
}

// demoEvent is one active SIMPLE event of an hour for venID.
func demoEvent(venID string, level float64, now time.Time) oadr2b.OadrEvent {
	return oadr2b.OadrEvent{ResponseRequired: "always", EiEvent: oadr2b.EiEvent{
		Descriptor: oadr2b.EventDescriptor{EventID: "demo-1", MarketContext: oadr2b.MarketContext{MarketContext: "http://oadrsim/demo"},
			CreatedDateTime: oadr2b.FormatTime(now), EventStatus: "active"},
		ActivePeriod: oadr2b.ActivePeriod{Properties: oadr2b.Properties{DtStart: oadr2b.DtStart{DateTime: oadr2b.FormatTime(now.Add(-time.Minute))},
			Duration: oadr2b.DurationProp{Duration: "PT1H"}}, Components: oadr2b.Components{Nil: "true"}},
		Signals: oadr2b.EventSignals{Signal: []oadr2b.EventSignal{{SignalName: "SIMPLE", SignalType: "level", SignalID: "s",
			Intervals: oadr2b.Intervals{Interval: []oadr2b.Interval{{Duration: &oadr2b.DurationProp{Duration: "PT1H"}, UID: &oadr2b.UID{Text: "0"},
				SignalPayload: &oadr2b.SignalPayload{PayloadFloat: oadr2b.PayloadFloat{Value: level}}}}}}}},
		Target: oadr2b.Target{VenID: []string{venID}},
	}}
}

func runVEN(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("ven", flag.ContinueOnError)
	vtn := fs.String("vtn", "", "VTN base URL, e.g. http://127.0.0.1:8080")
	venID := fs.String("ven-id", "", "venID to claim (default: the one the VTN assigns)")
	polls := fs.Int("polls", 3, "polls to make (0: until interrupted)")
	every := fs.Duration("every", 2*time.Second, "time between polls")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *vtn == "" {
		return errors.New("ven needs -vtn")
	}
	v := vensim.New(vensim.Config{VTN: *vtn, VenID: *venID, VenName: "oadrsim"})
	defer v.Close()
	if err := v.Register(ctx); err != nil {
		return fmt.Errorf("registering: %w", err)
	}
	fmt.Fprintf(out, "registered as %s (registration %s)\n", v.VenID(), v.RegistrationID())
	if err := v.RequestEvents(ctx); err != nil {
		return fmt.Errorf("asking for events: %w", err)
	}
	for id, ev := range v.Events() {
		fmt.Fprintf(out, "event %s: %s, %d signal(s)\n", id, ev.Descriptor.EventStatus, len(ev.Signals.Signal))
	}
	for i := 0; *polls == 0 || i < *polls; i++ {
		got, err := v.Poll(ctx)
		if err != nil {
			return fmt.Errorf("polling: %w", err)
		}
		fmt.Fprintf(out, "poll %d: %s\n", i+1, got)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(*every):
		}
	}
	return nil
}

func runVEN3(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("ven3", flag.ContinueOnError)
	vtn := fs.String("vtn", "", "VTN base URL up to its base path")
	id := fs.String("client-id", "", "OAuth2 client ID")
	secret := fs.String("secret", "", "OAuth2 client secret")
	name := fs.String("name", "ven-1", "venName")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *vtn == "" {
		return errors.New("ven3 needs -vtn")
	}
	v := oadr3sim.NewVEN(*vtn, *id, *secret, *name, nil)
	if err := v.Enrol(ctx); err != nil {
		return fmt.Errorf("enrolling: %w", err)
	}
	fmt.Fprintf(out, "enrolled as %s\n", *name)
	progs, err := v.Programs(ctx)
	if err != nil {
		return err
	}
	evs, err := v.Events(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%d program(s), %d event(s)\n", len(progs), len(evs))
	return nil
}
