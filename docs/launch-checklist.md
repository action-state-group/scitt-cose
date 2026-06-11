<!-- SPDX-License-Identifier: Apache-2.0 -->
# Public-repo launch checklist

The gates between "this directory" and "a public repo + public endpoint."
Ordered; the **datatracker prose audit is the FINAL gate before the flip** —
nothing publishes after it without re-running it.

## 1. Repo extraction & layout

- [ ] New repo under the Action State Group GitHub org. Target layout — repo
      root is the contents of this package, with the Go cross-verifier as a
      subdirectory:

      ```
      /                      <- contents of tools/scitt-cose
      scitt-cose-go-verify/  <- contents of tools/scitt-cose-go-verify
      ```

      The cross-language test finds the Go tool at either location (sibling or
      subdir) or via `SCITT_GO_VERIFIER_DIR`; CI assumes the subdir layout.
- [ ] **Fresh git history** (`git init` + one import commit), NOT a filtered
      copy of the private monorepo history.
- [ ] **No-reserved-code-in-history gate (green before first push):**

      ```bash
      # (pattern split so this checklist doesn't match itself)
      git grep -i "goph""er_ai" $(git rev-list --all)   # -> empty
      git log --all --format=%ae | sort -u              # -> expected authors only
      python -m pytest tests/test_iana_codepoints.py -q # file-level neutrality gate
      ```

      The CI `neutrality-gate` job keeps the *tree* clean from then on; this
      manual sweep is the one chance to keep the *history* clean.

## 2. Name & namespace claim

- [x] Finalize the generic name: **`scitt-cose`, finalized 2026-06-10.**
      Claimed on PyPI; GitHub claim is the private-repo push of the §1
      extraction (`action-state-group/scitt-cose`).
- [x] PyPI: claim by uploading the real `0.0.1` (preferred over an empty
      placeholder). `python -m build && twine upload`. **Done —
      https://pypi.org/project/scitt-cose/0.0.1/ ; install-from-PyPI verified
      in a clean venv.**
- [x] If renamed: not renamed — `scitt-cose` kept; README name-note updated
      from "provisional" to finalized.
- [x] Add `[project.urls]` (Homepage/Source/Issues) to `pyproject.toml` once
      the repo URL exists. **Done — points at
      github.com/action-state-group/scitt-cose.**

## 3. Repo hygiene (now in-tree; verify after extraction)

- [ ] `LICENSE` — Apache-2.0, canonical text. ✔ in-tree
- [ ] `NOTICE` — Action State Group copyright line. ✔ in-tree
- [ ] `CONTRIBUTING.md` — scope rules + DCO sign-off requirement. ✔ in-tree
- [ ] **DCO enforcement ON** — enable the DCO check (GitHub DCO app or
      equivalent required status check) + branch protection on `main`.
      **Deferred to the public flip:** branch protection on private repos
      needs a paid plan (GitHub returns 403 on the free org); it is free the
      moment the repo goes public. On flip day: install the DCO app
      (github.com/apps/dco) and require `DCO`, `test (3.9)`, `test (3.12)`,
      `go-verifier`, `neutrality-gate` on `main`.
- [ ] CI green on the extracted repo: pytest with `SCITT_REQUIRE_GO=1`
      (cross-language check may never silently skip), ruff, Go vet/build,
      neutrality gate (`.github/workflows/ci.yml`).
- [ ] README carries the three positioning statements (Provenance, neutrality
      & governance section): **built by Action State Group**, **neutral by
      design** (test-enforced), **foundation intent, foundation unnamed**. ✔ in-tree

## 4. Hosted endpoint (verify.actionstate.ai) — parallel track

- [x] Deploy the container (`Dockerfile` in this repo) behind TLS + edge rate
      limiting + body-size cap, per `docs/hosted-verifier-design.md`.
      **Done 2026-06-10 — Cloud Run `scitt-verifier` (project `fluxxom`,
      us-central1, max 3 instances), Google-managed TLS via domain mapping;
      body-size cap + in-process rate backstop in the app. Residual: per-IP
      edge limiting would need an LB + Cloud Armor; the anonymous backstop +
      instance cap is the current abuse control.**
- [ ] Confirm in a real browser that `GET /` renders the
      **verifier-vs-Transparency-Service boundary table on the page itself**
      (HTML via content negotiation; API clients get the same data as JSON in
      the `boundary` field) — plus the page's full job list: one-sentence
      summary, how-to-use (curl + `pip install` + "you don't need this
      service"), privacy posture, and the attribution footer ("Operated by
      Action State Group · Apache-2.0 · foundation intent"). All pinned by
      `tests/test_hosted_page.py`.
- [x] `GET /health` returns `{"ok": true}` (deploy probe target). **Verified
      on https://verify.actionstate.ai/health. (Deploy finding: Google's
      frontend intercepts `/healthz` on run.app — `/health` is canonical.)**
- [x] Run `scripts/smoke_verify.py --url https://verify.actionstate.ai` from a
      clean venv (standalone + still-verifies guard). **SMOKE OK 2026-06-10.**
- [x] Confirm access logs carry no request bodies (design constraint).
      **Verified: Cloud Run request logs carry method + URL + status only;
      app access logging is silenced by design.**
- [ ] On repo extraction / name claim (§2): update `REPO_URL` and the
      `pip install` lines in `scitt_cose/hosted.py` — the landing page's repo
      link must point at the real public repo before the flip.

## 5. Datatracker prose audit — FINAL GATE before the flip

Re-verify, against the live IETF Datatracker, **on flip day**:

- [ ] `draft-ietf-scitt-architecture-22` — still the current revision? Still
      "Active Internet-Draft / RFC Editor Queue"? If it has been **published as
      an RFC**, update `scitt_cose/_status.py`, the README draft-tracking
      section, the landing page, and the announcement text with the real RFC
      number — and re-run the whole suite (the honesty tests pin the exact
      status wording).
- [ ] `draft-ietf-cose-merkle-tree-proofs-18` — same check.
- [ ] Confirm the shipped prose still claims **no unassigned RFC number**
      (no unassigned RFC number is claimed anywhere; the scan test enforces this — keep it green).
- [ ] Re-read every status sentence in README / `_status.py` / the landing
      page and the announcement post against what the Datatracker says *today*.
      RFC-Ed-Queue documents can be published at any moment; stale prose on
      launch day is the one unforced error this project cannot afford.

## 6. Announcement frame (validated)

The profile-coverage check passes: this verifier validates receipts whose
verifiable data structure is **`RFC9162_SHA256`** (vds = 1) — the tree
algorithm the COSE Receipts draft registers — enforced from the protected
header, cross-validated against the published RFC 6962/9162 vectors, an
independent Go implementation, and a third-party COSE library. So the launch
post may use the working group's own IETF 124 framing — the noted absence of a
known deployed implementation, "please correct me if I'm wrong" — and answer
it:

> The WG noted this gap at IETF 124. Here is a standalone, ledger-independent
> verifier that fills it: cross-validated, Apache-2.0, with intent to
> contribute it to a neutral foundation.

Keep the README's stance verbatim: **no primacy claimed** — the value is
neutrality + verifiable conformance, not being "first". Invite correction
explicitly; if someone surfaces a prior deployed implementation, that's a
welcome outcome, not a contradiction.
