# Changelog

All notable changes to this module. Versions follow semantic versioning;
before v1 the API may change in minor versions.

## v0.2.0 (2026-10-11)

Needs openadr v0.2.0.

- New: `oadr3sim.VTN` (`NewVTN`, `Start`, `AddEvent`, `Grant`), a
  simulated OpenADR 3.1 or 3.0 VTN built on openadr's new `oadr3/vtn`,
  with demo business-logic and VEN clients and an optional demo program
  and event; webhooks to local callbacks are allowed.
- New: `oadrsim vtn3` runs it (`-addr`, `-version`, `-base-path`,
  `-demo`, `-anonymous`).
- New tests: `vensim` against openadr's new `oadr2b/vtn`, and openadr's
  new `oadr2b/ven` against `vtnsim` (pull and push, plain HTTP and
  mutual TLS with signatures).

## v0.1.0 (2026-10-11)

First release as a module of its own, split from the openadr module: a
2.0b and 2.0a VEN (`sim/vensim`), a 2.0b VTN (`sim/vtnsim`), an
OpenADR 3 VEN, business-logic client and webhook receiver
(`sim/oadr3sim`), and `cmd/oadrsim`. Needs openadr v0.1.0.

- New: `vtnsim.Config.SignWith` signs the VTN's answers and pushes;
  `RequireSigned` refuses unsigned, altered or replayed requests with
  code 463; `VTN.SignatureErrors` lists them.
- New tests for the simulator packages: the VEN against the VTN (pull,
  push, mutual TLS with signatures), and the OpenADR 3 VEN and webhook
  against a VTN written in the test.
- Interop tests running OpenLEADR 0.5.36's VTN and VEN client and
  openleadr-rs v0.2.6's VTN against the simulators, in a nested
  test-only module, `interop`.
