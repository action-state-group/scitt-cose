# SPDX-License-Identifier: Apache-2.0
"""Application-profile renderers for the deployed hosted verify surface.

Deliberately NOT part of the published ``scitt-cose`` package (excluded from
the wheel via ``[tool.setuptools] packages`` in pyproject.toml): the neutral
verifier carries no application-profile awareness. ``scitt_cose/hosted.py``
imports from here only when running from a full repo checkout (see the
Dockerfile — ``COPY . /app`` then run from that working directory), which is
how the deployed hosted verify surface (verify.agentactioncapsule.org) is
built.
"""
from __future__ import annotations
