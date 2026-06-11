# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures: throwaway Ed25519 and EC P-256 keypairs (PEM bytes)."""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519


def _priv_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _pub_pem(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@pytest.fixture
def eddsa_keys():
    k = ed25519.Ed25519PrivateKey.generate()
    return _priv_pem(k), _pub_pem(k)


@pytest.fixture
def es256_keys():
    k = ec.generate_private_key(ec.SECP256R1())
    return _priv_pem(k), _pub_pem(k)


@pytest.fixture(params=["EdDSA", "ES256"])
def alg_keys(request, eddsa_keys, es256_keys):
    if request.param == "EdDSA":
        priv, pub = eddsa_keys
    else:
        priv, pub = es256_keys
    return request.param, priv, pub


@pytest.fixture
def other_eddsa_keys():
    k = ed25519.Ed25519PrivateKey.generate()
    return _priv_pem(k), _pub_pem(k)
