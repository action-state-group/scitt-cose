# SPDX-License-Identifier: Apache-2.0
# Standalone SCITT-only verifier — a stateless, read-only HTTP service.
#
# This serves ONLY the generic SCITT/COSE verification utility. It is NOT a
# Transparency Service: it does not register statements, issue receipts, or hold
# any state. (Operating a TS is a separate offering.)
#
# Build:  docker build -t scitt-verifier tools/scitt-cose
# Run:    docker run -p 8080:8080 scitt-verifier
#   GET  /         -> capabilities (what it does / does not do)
#   POST /verify   -> verify a SCITT Signed Statement and/or COSE Receipt
FROM python:3.12-slim

# Non-root, no build toolchain needed (pure-Python deps: cbor2, cryptography).
WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir ".[serve]" \
    && useradd --create-home --uid 10001 verifier
USER verifier

EXPOSE 8080

# Stateless and read-only: the ASGI app retains nothing across requests.
CMD ["python", "-m", "uvicorn", "scitt_cose.hosted:make_asgi_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
