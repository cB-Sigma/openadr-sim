# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# OpenLEADR (openleadr-python, Apache-2.0, github.com/OpenLEADR/openleadr-python)
# as an OpenADR 2.0b interop peer; it is installed from PyPI at build time,
# not redistributed.
FROM python:3.12.10-slim
RUN pip install --no-cache-dir openleadr==0.5.36
WORKDIR /peer
COPY *.py /peer/
