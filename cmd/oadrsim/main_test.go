// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a bytes.Buffer safe for a writer and a reader.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// The vtn command serves a VEN that the ven command runs against it.
func TestVTNAndVEN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	vtnCtx, stopVTN := context.WithCancel(ctx)
	var vtnOut syncBuffer
	done := make(chan error, 1)
	go func() { done <- run(vtnCtx, []string{"vtn", "-ven-id", "ven-7"}, &vtnOut) }()
	var url string
	for url == "" {
		if ctx.Err() != nil {
			t.Fatal("the VTN did not start")
		}
		if s := vtnOut.String(); strings.Contains(s, "listening on ") {
			url = strings.Fields(strings.SplitN(s, "listening on ", 2)[1])[0]
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}
	var venOut bytes.Buffer
	if err := run(ctx, []string{"ven", "-vtn", url, "-polls", "1", "-every", "1ms"}, &venOut); err != nil {
		t.Fatalf("ven: %v\n%s", err, venOut.String())
	}
	for _, want := range []string{"registered as ven-7", "event demo-1: active, 1 signal(s)", "poll 1:"} {
		if !strings.Contains(venOut.String(), want) {
			t.Errorf("ven output lacks %q:\n%s", want, venOut.String())
		}
	}
	stopVTN()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(vtnOut.String(), "received ") {
		t.Errorf("vtn output: %s", vtnOut.String())
	}
}

func TestUsage(t *testing.T) {
	if err := run(context.Background(), nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("got %v", err)
	}
	if err := run(context.Background(), []string{"ven"}, &bytes.Buffer{}); err == nil {
		t.Fatal("ven without -vtn was accepted")
	}
}
