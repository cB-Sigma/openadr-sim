# openadr-sim

Simulated OpenADR VENs and VTNs, 2.0b, 2.0a and OpenADR 3, for testing OpenADR software without devices or a utility; not affiliated with the OpenADR Alliance.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/openadr-sim.svg)](https://pkg.go.dev/github.com/cB-Sigma/openadr-sim) [![test](https://github.com/cB-Sigma/openadr-sim/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/openadr-sim/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.27.1-00ADD8.svg)](go.mod)

A 2.0b VEN that registers, offers and sends telemetry reports, polls or
takes pushes, opts in or out and signs its messages; the same VEN as a
2.0a VEN; a 2.0b VTN that registers one VEN, serves events and queued
messages, pushes, requests reports, signs and checks signatures and
records everything; an OpenADR 3 VEN and business-logic client over the
REST API with OAuth2 tokens; and a webhook receiver. Each runs in
process in a Go test, or from the `oadrsim` command. It is built on
[openadr](https://github.com/cB-Sigma/openadr). Written for SigmaM2M, a
oneM2M platform; it has no dependency on it.

## What is simulated

| Feature | Status |
|---|---|
| 2.0b VEN (`vensim`): query and create registration, re-registration, cancellation; METADATA telemetry reports and the VTN's report requests; oadrRequestEvent and oadrPoll with oadrCreatedEvent; telemetry in oadrUpdateReport; oadrCreateOpt and oadrCancelOpt; oadrCreateReport and oadrCancelReport from the VTN | yes |
| 2.0b VEN in push mode: its own endpoint, pushed events answered in the HTTP answer | yes |
| 2.0a VEN (`Config.Profile` "2.0a"): oadrRequestEvent on the 2.0a path or pushed events, oadrCreatedEvent | yes |
| Mutual TLS with the OpenADR suites, or chosen versions and suites | yes |
| XML signatures: sign every message, require the VTN's signature (by its TLS certificate or a fingerprint), replay guard; tampering after signing (`Tamper`) | yes |
| VEN faults: failed pushes (`SetPushFailures`), busy answers (`SetPushCode`), held pushes (`HoldPushes`), event response codes (`SetEventResponseCode`), a schema check hook (`Check`) | yes |
| 2.0b VTN (`vtnsim`): registration of one VEN, oadrRequestEvent, oadrPoll with queued messages and changed events, push to a VEN registered for push, report requests for every METADATA report (`RequestReports`), oadrUpdateReport, opts, cancellation; everything recorded (`Received`, `Find`, `Metadata`) | yes |
| VTN signatures (`SignWith`, `RequireSigned`): signs answers and pushes, refuses unsigned, altered or replayed requests with code 463 | yes (since v0.1.0) |
| 2.0b VTN over XMPP, a 2.0a VTN | no |
| OpenADR 3 VEN (`oadr3sim.VEN`): token, enrolment (ven object and resources), programs and events by target, reports | yes |
| OpenADR 3 webhook receiver (`oadr3sim.Webhook`): echo challenge (or a failed one), bearer check, notifications recorded | yes |
| OpenADR 3 VTN | no |

## Install

```
go get github.com/cB-Sigma/openadr-sim@latest
```

Requires Go 1.27.1 or later. The command:

```
go install github.com/cB-Sigma/openadr-sim/cmd/oadrsim@latest
```

## Command line

```
oadrsim vtn                                          # prints its URL
oadrsim ven -vtn http://127.0.0.1:PORT -polls 3
oadrsim ven3 -vtn https://vtn.example/openadr3/3.1.0 -client-id ID -secret S
```

| Command | Flags |
|---|---|
| `vtn` | `-ven-id` (default `ven-1`, given to the VEN that registers), `-level` (SIMPLE level of the one demo event, default 1); plain HTTP on 127.0.0.1 until interrupted |
| `ven` | `-vtn` URL (required), `-ven-id` (default: the one the VTN assigns), `-polls` (default 3; 0 polls until interrupted), `-every` (default 2s) |
| `ven3` | `-vtn` URL up to the base path (required), `-client-id`, `-secret`, `-name` (venName, default `ven-1`) |

## In Go tests

From `TestVENAgainstVTNSim` in sim/vensim/vensim_test.go:

```go
vtn := vtnsim.New(vtnsim.Config{VtnID: "VTN-1", VenID: "ven-7", RequestReports: true})
url, _ := vtn.Start()
defer vtn.Close()

ven := vensim.New(vensim.Config{VTN: url, VenName: "ven-a"})
_ = ven.Register(ctx)                                  // registration and report registration
_ = vtn.SetEvents(ctx, event)                          // an oadr2b.OadrEvent
name, _ := ven.Poll(ctx)                               // "oadrDistributeEvent", answered with optIn
_ = ven.SendTelemetry(ctx, time.Now(), 1.5, 640, true) // oadrUpdateReport
fmt.Println(name, len(vtn.Find("oadrCreatedEvent")))
```

Point `vensim` at your VTN, or your VEN at `vtnsim`, the same way.

## Documentation

Reference: https://pkg.go.dev/github.com/cB-Sigma/openadr-sim

| Package | What it does |
|---|---|
| `sim/vensim` | `New(Config)`, `VEN` (`Register`, `Reregister`, `RequestEvents`, `Poll`, `SendTelemetry`, `CreateOpt`, `CancelOpt`, `CancelRegistration`, `Send`, `SendRaw`, `SendA`, `StartPush`, the fault switches, `Events`, `Requests`, `Received`, `LastSent`, `TLS`) |
| `sim/vtnsim` | `New(Config)`, `VTN` (`Start`, `SetEvents`, `Queue`, `Registered`, `Received`, `Find`, `Metadata`, `SignatureErrors`), `HistoryRequest` |
| `sim/oadr3sim` | `Client`, `NewVEN` / `VEN` (`Enrol`, `Programs`, `Events`, `Report`), `NewWebhook` / `Webhook` |
| `cmd/oadrsim` | `vtn`, `ven` and `ven3`, as above |
| `interop` (nested module, tests only) | OpenLEADR's VTN and VEN client and openleadr-rs's VTN against the simulators, in containers |

Changes per version are in [CHANGELOG.md](CHANGELOG.md).

## Testing

```
go test -race ./...
cd interop && SIGMA_OPENADR_INTEROP=1 go test -v ./...   # needs Docker
```

The tests drive the openadr library's code through the simulators: the
2.0b VEN against the VTN in pull and push mode and over mutual TLS with
signatures both ways (with unsigned, altered and replayed requests
refused), the OpenADR 3 VEN and webhook against a small VTN written in
the test, and the command's VTN and VEN against each other.

`interop/` is a nested module with its own go.mod. Its tests build
`interop/peer/openleadr` (python:3.12.10-slim with openleadr 0.5.36 from
PyPI) and `interop/peer/openleadr-rs` (openleadr-rs cloned at tag
v0.2.6, commit b20d616, built with rust:1.94-alpine, run on alpine:3.20
next to postgres:16), and are skipped unless `SIGMA_OPENADR_INTEROP=1`
is set and Docker answers.

### Interop tested against

Run on 2026-10-11 in Docker Desktop 29.4.3 on arm64; each 2.0b run over
plain HTTP and again over mutual TLS (ECDSA P-256 certificates, TLS 1.2
with TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256) with XML signatures both
ways, each side checking the other's signature against its
fingerprint.

- OpenLEADR 0.5.36's VTN (`OpenADRServer`) with `vensim`: query and
  create registration (OpenLEADR saw xmlSignature set when signing),
  report registration (OpenLEADR read energy, power and status
  descriptions and requested all three), oadrRequestEvent with
  oadrCreatedEvent (OpenLEADR's callback got optIn), telemetry in
  oadrUpdateReport (OpenLEADR's report callbacks got 1.5 and 640), an
  empty oadrPoll, a new event delivered by oadrPoll and opted in, and
  cancellation. OpenLEADR checks every message it receives against its
  2.0b XSDs; all passed. Found: OpenLEADR 0.5.36's VTN reads one report
  payload per interval; `SendTelemetry`'s interval with two payloads
  (which the schema allows) passes its schema check and then fails in
  its handler with HTTP 500, so the test sends each data point in an
  interval of its own. OpenLEADR also repeats an event on the next
  oadrPoll after it was delivered by oadrRequestEvent.
- OpenLEADR 0.5.36's VEN client (`OpenADRClient`) with `vtnsim`:
  registration, its TELEMETRY_USAGE METADATA (one voltage data point),
  the report request `vtnsim` makes and OpenLEADR's oadrCreatedReport
  and periodic oadrUpdateReport (231.5 V), an event by oadrRequestEvent
  and a changed event by oadrPoll, both opted in, and cancellation.
  `vtnsim` gained signing for these runs (`SignWith`, `RequireSigned`,
  v0.1.0): given the VTN's fingerprint, OpenLEADR's client checks the
  signature of every answer.
- openleadr-rs v0.2.6's OpenADR 3.1 VTN with `oadr3sim` (and the
  openadr library's client as the business-logic client): token
  endpoint discovery and client credentials, a program and an event
  created by the business client, the VEN's enrolment (VEN_VEN_REQUEST
  and VEN_RESOURCE_REQUEST) and its second enrolment finding the same
  ven object, programs and events read by the VEN, and a report that
  the business client read back.
- Not yet: 2.0b push mode, 2.0a and XMPP against another
  implementation (OpenLEADR has none of them), opts against another VTN
  (OpenLEADR's VTN serves no EiOpt endpoint), the webhook receiver
  against another VTN (openleadr-rs does not send webhooks), an OpenADR
  Alliance test harness, a certified VTN or VEN, real devices. The
  simulators and the openadr library are written by the same author, so
  their agreement with each other is not independent; the OpenLEADR and
  openleadr-rs runs are.

## Demo values

Every VEN and VTN ID, name, market context, URL, client ID and secret in
this module is a made-up demo value, except the client IDs and secrets
of openleadr-rs's public test fixtures in interop/openleadrrs_test.go.
Keys and certificates are generated when the tests run.

## Related repositories

- [openadr](https://github.com/cB-Sigma/openadr): the OpenADR library
  these simulators are built on.

## Status

v0.x: the API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam.

"OpenADR" is a trademark of the OpenADR Alliance. This module is not
made, affiliated with, endorsed or certified by the OpenADR Alliance;
the name is used only to say which protocol it simulates. No OpenADR
Alliance schema, OpenAPI definition or specification text is included.
