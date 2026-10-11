# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# An OpenLEADR VTN for the interop tests. It registers one VEN, requests
# every report the VEN offers, holds one event for it and adds more on
# command, and prints what happens as "PEER ..." lines.
#
#   python vtn.py <port> <ven-id> [<cert-dir> <ven-fingerprint>]
#
# With a certificate directory (ca.pem, vtn.crt, vtn.key) it serves HTTPS
# with client certificates, signs its messages and checks the VEN's
# signatures and TLS certificate against <ven-fingerprint>.
#
# Commands on standard input: "event <id> <level>", "quit".

import asyncio
import logging
import sys
from datetime import datetime, timedelta, timezone
from functools import partial

from openleadr import OpenADRServer, enable_default_logging

enable_default_logging(level=logging.WARNING)


def say(*parts):
    print("PEER", *parts, flush=True)


port = int(sys.argv[1])
VEN_ID = sys.argv[2]
cert_dir = sys.argv[3] if len(sys.argv) > 3 else None
ven_fp = sys.argv[4] if len(sys.argv) > 4 else None
state = {"registration_id": None}


def ven_lookup(ven_id=None):
    if ven_id != VEN_ID:
        return None
    return {"ven_id": ven_id, "ven_name": "ven", "fingerprint": ven_fp,
            "registration_id": state["registration_id"]}


async def on_create_party_registration(info):
    if cert_dir and info.get("fingerprint") != ven_fp:
        say("registration-refused", info.get("fingerprint"))
        return False
    state["registration_id"] = "reg-olr-1"
    say("registration", info.get("ven_name"), info.get("http_pull_model"), info.get("xml_signature"))
    return VEN_ID, state["registration_id"]


async def on_cancel_party_registration(payload):
    say("cancel", payload.get("ven_id"), payload.get("registration_id"))
    state["registration_id"] = None
    return "oadrCanceledPartyRegistration", {"registration_id": payload.get("registration_id")}


async def on_update_report(data, ven_id, resource_id, measurement):
    for when, value in data:
        say("report", resource_id, measurement, value)


async def on_register_report(ven_id, resource_id, measurement, unit, scale,
                             min_sampling_interval, max_sampling_interval):
    say("register-report", resource_id, measurement, unit, scale, min_sampling_interval)
    cb = partial(on_update_report, ven_id=ven_id, resource_id=resource_id, measurement=measurement)
    return cb, min_sampling_interval


async def on_event_response(ven_id, event_id, opt_type):
    say("opt", ven_id, event_id, opt_type)


def add_event(server, event_id, level):
    now = datetime.now(timezone.utc)
    server.add_event(ven_id=VEN_ID, signal_name="simple", signal_type="level",
                     intervals=[{"dtstart": now, "duration": timedelta(minutes=30),
                                 "signal_payload": level}],
                     callback=on_event_response, event_id=event_id,
                     market_context="http://openleadr.test/mc")
    say("event-added", event_id, level)


async def main():
    kw = {}
    if cert_dir:
        kw = dict(cert=f"{cert_dir}/vtn.crt", key=f"{cert_dir}/vtn.key",
                  http_cert=f"{cert_dir}/vtn.crt", http_key=f"{cert_dir}/vtn.key",
                  http_ca_file=f"{cert_dir}/ca.pem", ven_lookup=ven_lookup)
    server = OpenADRServer(vtn_id="OLR-VTN", http_host="0.0.0.0", http_port=port,
                           requested_poll_freq=timedelta(seconds=1), show_fingerprint=False, **kw)
    server.add_handler("on_create_party_registration", on_create_party_registration)
    server.add_handler("on_cancel_party_registration", on_cancel_party_registration)
    server.add_handler("on_register_report", on_register_report)
    add_event(server, "olr-ev-1", 2.0)
    await server.run()
    say("ready")
    loop = asyncio.get_running_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line or line.strip() == "quit":
            break
        parts = line.split()
        if parts and parts[0] == "event":
            add_event(server, parts[1], float(parts[2]))
    await server.stop()


asyncio.run(main())
