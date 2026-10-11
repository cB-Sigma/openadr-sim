// Package oadr3sim simulates OpenADR 3 parties for tests and demonstrations:
// a scripted VEN and business-logic client (both over the real REST API
// with OAuth2 tokens) and a webhook receiver that answers the VTN's echo
// challenge and records notifications.
package oadr3sim

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/cB-Sigma/openadr/oadr3"
)

// Client makes an API client for a VTN.
func Client(vtn, clientID, secret string, roots *x509.CertPool) *oadr3.APIClient {
	return oadr3.NewClient(oadr3.ClientConfig{BaseURL: vtn, ClientID: clientID, Secret: secret, RootCAs: roots})
}

// VEN is a scripted VEN.
type VEN struct {
	C       *oadr3.APIClient
	Name    string
	VenID   string
	Targets []string
}

// NewVEN makes a VEN simulator.
func NewVEN(vtn, clientID, secret, venName string, roots *x509.CertPool) *VEN {
	return &VEN{C: Client(vtn, clientID, secret, roots), Name: venName}
}

// Enrol finds or creates the VEN's ven object and the named resources.
func (v *VEN) Enrol(ctx context.Context, resources ...string) error {
	vens, err := v.C.All(ctx, "/vens", url.Values{"venName": {v.Name}})
	if err != nil {
		return err
	}
	var ven oadr3.Object
	if len(vens) > 0 {
		ven = vens[0]
	} else if _, err := v.C.Do(ctx, http.MethodPost, "/vens", nil,
		oadr3.Object{"objectType": "VEN_VEN_REQUEST", "venName": v.Name}, &ven); err != nil {
		return err
	}
	v.VenID, _ = ven["id"].(string)
	for _, r := range resources {
		if _, err := v.C.Do(ctx, http.MethodPost, "/resources", nil,
			oadr3.Object{"objectType": "VEN_RESOURCE_REQUEST", "resourceName": r, "venID": v.VenID}, nil); err != nil {
			return err
		}
	}
	return nil
}

func (v *VEN) query() url.Values {
	q := url.Values{}
	for _, t := range v.Targets {
		q.Add("targets", t)
	}
	return q
}

// Programs reads the programs the VEN can see.
func (v *VEN) Programs(ctx context.Context) ([]oadr3.Object, error) {
	return v.C.All(ctx, "/programs", v.query())
}

// Events reads the events the VEN can see.
func (v *VEN) Events(ctx context.Context) ([]oadr3.Object, error) {
	return v.C.All(ctx, "/events", v.query())
}

// Report sends one value for one resource and interval.
func (v *VEN) Report(ctx context.Context, eventID, resource, payloadType string, interval int, value any) (oadr3.Object, error) {
	var out oadr3.Object
	_, err := v.C.Do(ctx, http.MethodPost, "/reports", nil, oadr3.Object{
		"eventID": eventID, "clientName": v.Name,
		"resources": []any{map[string]any{"resourceName": resource, "intervals": []any{
			map[string]any{"id": interval, "payloads": []any{map[string]any{"type": payloadType, "values": []any{value}}}}}}},
	}, &out)
	return out, err
}

// Webhook is a callback endpoint.
type Webhook struct {
	URL    string
	Bearer string
	srv    *http.Server
	ln     net.Listener

	mu    sync.Mutex
	notes []map[string]any
	// Echo is false to fail the echo challenge.
	Echo bool
}

// NewWebhook serves a callback on 127.0.0.1 (TLS when cert is not nil).
// Notifications must carry bearer.
func NewWebhook(cert *tls.Certificate, bearer string) (*Webhook, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	w := &Webhook{Bearer: bearer, Echo: true}
	scheme := "http"
	if cert != nil {
		ln = tls.NewListener(ln, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*cert}})
		scheme = "https"
	}
	w.ln = ln
	w.URL = fmt.Sprintf("%s://%s/callback", scheme, ln.Addr())
	w.srv = &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(w.serve)}
	go func() { _ = w.srv.Serve(ln) }()
	return w, nil
}

func (w *Webhook) serve(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.mu.Lock()
		echo := w.Echo
		w.mu.Unlock()
		if echo {
			_, _ = io.WriteString(rw, r.URL.Query().Get("echo"))
		} else {
			_, _ = io.WriteString(rw, "no")
		}
	case http.MethodPost:
		if w.Bearer != "" && r.Header.Get("Authorization") != "Bearer "+w.Bearer {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		var n map[string]any
		if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		w.mu.Lock()
		w.notes = append(w.notes, n)
		w.mu.Unlock()
		rw.WriteHeader(http.StatusOK)
	}
}

// SetEcho sets whether the echo challenge is answered.
func (w *Webhook) SetEcho(ok bool) {
	w.mu.Lock()
	w.Echo = ok
	w.mu.Unlock()
}

// Notes gives the notifications received.
func (w *Webhook) Notes() []map[string]any {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]map[string]any(nil), w.notes...)
}

// Close stops the endpoint.
func (w *Webhook) Close() { _ = w.srv.Close() }
