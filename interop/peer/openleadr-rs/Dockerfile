# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# The openleadr-rs OpenADR 3 VTN (Apache-2.0 OR MIT,
# github.com/OpenLEADR/openleadr-rs) as an interop peer. It is cloned at a
# pinned tag and commit and built at test time; nothing of it is
# redistributed here. It needs PostgreSQL (DATABASE_URL); its user
# fixtures are kept in /fixtures for the test to load.
FROM rust:1.94-alpine AS builder
RUN apk add --no-cache git cmake g++ make openssl-dev
RUN git clone --depth 1 --branch v0.2.6 https://github.com/OpenLEADR/openleadr-rs.git /app \
 && test "$(git -C /app rev-parse HEAD)" = "b20d616d9bbf511a48314e127844a240e0349a17"
WORKDIR /app
RUN SQLX_OFFLINE=true RUSTFLAGS="-Ctarget-feature=-crt-static" \
    cargo build --release --bin openleadr-vtn --features internal-oauth

FROM alpine:3.20
RUN apk add --no-cache libssl3 libgcc
COPY --from=builder /app/target/release/openleadr-vtn /usr/local/bin/openleadr-vtn
COPY --from=builder /app/fixtures /fixtures
USER 2000:2000
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/openleadr-vtn"]
