# Provenance

## How the code was written

Written for SigmaM2M, a oneM2M platform, in Go, by the author of the
openadr module and from the same specifications. No code was ported or
copied from another implementation. The simulators were first written
next to SigmaM2M's OpenADR integrations to test them without a utility
or devices; they came with SigmaM2M's first commit (2026-09-27), moved
into the openadr library on 2026-10-06, and moved out of it into this
module on 2026-10-11 (with `git mv`), together with `cmd/oadrsim`, so
the library does not depend on its simulators.

History:

- 2026-10-11: module path github.com/cB-Sigma/openadr-sim. New tests
  for the simulator packages (until then they were exercised only by
  SigmaM2M's integration tests and the command's test):
  sim/vensim/vensim_test.go (the VEN against the VTN in pull and push
  mode and over mutual TLS with signatures) and
  sim/oadr3sim/sim_test.go (the OpenADR 3 VEN and webhook against a
  small VTN written in the test). `vtnsim` gained XML signatures
  (`SignWith`, `RequireSigned`, `SignatureErrors`) so that OpenLEADR's
  VEN client, which checks the VTN's signatures, could run against it.
  The interop module was added and run against OpenLEADR 0.5.36 (its
  VTN and VEN client) and openleadr-rs v0.2.6 (its VTN); no simulator
  bug was found. Comments that named SigmaM2M's VEN integration were
  reworded.

## Sources

| Area (files) | Followed |
|---|---|
| 2.0b and 2.0a VEN (sim/vensim) | the openadr module's messages, signatures and TLS rules; the OpenADR 2.0b Profile Specification v1.1 and 2.0a v1.0 for the exchanges (registration, report registration, polling, push, opts) |
| 2.0b VTN (sim/vtnsim) | the same |
| OpenADR 3 VEN, business client and webhook (sim/oadr3sim) | the openadr module's client; the OpenADR 3.1.0 definition for the paths, object types and the webhook echo challenge |
| Command (cmd/oadrsim) | none (flags are our own) |
| Test PKI (internal/testpki) | our own; crypto/x509 |
| Interop peers (interop/peer/openleadr/vtn.py, ven.py) | our own scripts using OpenLEADR 0.5.36's OpenADRServer and OpenADRClient, installed from PyPI at test time; openleadr-rs v0.2.6 built at test time and driven over its REST API |

The OpenADR Alliance documents are not redistributed; no specification
text is reproduced.

## Tests

| Test | Source |
|---|---|
| sim/vensim, sim/oadr3sim, cmd/oadrsim | the openadr library against these simulators (and a VTN written in the test), by the same author; not independent |
| interop/ | OpenLEADR 0.5.36's VTN and VEN client and openleadr-rs v0.2.6's VTN against these simulators |

All IDs, names and URLs are made-up demo values; keys and certificates
are generated when the tests run.
