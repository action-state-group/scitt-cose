# SPDX-License-Identifier: Apache-2.0
"""The deployed hosted verify surface: the HTTP wrapper (``hosted.py``) plus
its application-profile renderers (AAC, MachineMandate).

Deliberately NOT part of the published ``scitt-cose`` package (excluded from
the wheel via ``[tool.setuptools] packages`` in pyproject.toml): the neutral
verifier package carries no application-profile awareness and no hosted-surface
code. This package only exists in a full repo checkout (see the Dockerfile —
``COPY . /app`` then run ``hosted_profiles.hosted:make_asgi_app`` from that
working directory), which is how the deployed hosted verify surface
(verify.agentactioncapsule.org) is built. ``hosted.py`` imports the neutral
verifier through ``scitt_cose``'s public API, same as any downstream consumer.
"""
from __future__ import annotations
