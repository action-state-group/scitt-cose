<!-- SPDX-License-Identifier: Apache-2.0 -->
# Releasing

`scitt-cose` publishes one package, the Python distribution on PyPI. A release
is a merged version bump: you choose the bump, review it as a pull request,
and merging it tags and publishes. The package is listed in
[`.github/releases.json`](.github/releases.json), which
[`.github/release.py`](.github/release.py) reads.

| Package | Manifest | Tag | Publisher | Environment |
|---|---|---|---|---|
| `python` | `pyproject.toml` | `v<version>` | `release.yml` | `pypi` (tag rule `v[0-9]*`) |

Other tags in this repository (`rust-scitt-cose-v*`, `vectors-*`) belong to
other artifacts and never publish to PyPI.

## Cutting a release

1. **Prepare.** Run [Prepare release](https://github.com/action-state-group/scitt-cose/actions/workflows/prepare-release.yml)
   on `main`, choosing `patch`, `minor` or `major`. It raises the version in
   `pyproject.toml`, commits the bump with a sign-off, and pushes
   `release/python-v<version>`.
2. **Review.** Open the pull request from the link in the run summary. Open it
   yourself: a pull request opened by the workflow would not start CI. Add the
   CHANGELOG entry on the same branch if it is not in yet.
3. **Merge.** [Tag release](https://github.com/action-state-group/scitt-cose/actions/workflows/tag-release.yml)
   runs on the merge. When the version changed it creates `v<version>` and its
   GitHub Release on the merge commit and dispatches `release.yml` on that tag.
4. **Publish.** `release.yml` checks that the tag is `v` plus the
   `pyproject.toml` version and that the commit is on `main`, then uploads
   through OIDC trusted publishing from the `pypi` environment. Confirm the run
   and the new version at <https://pypi.org/project/scitt-cose/>.

Bumping the version by hand in any pull request releases it the same way when
it merges.

If a publish fails after the tag exists:

- **A transient or configuration failure** (PyPI outage, trusted publisher or
  environment settings): fix it and re-run the failed `release.yml` run.
- **A defect in the code or the workflow:** a re-run uses the tagged commit
  again, so a fix merged to `main` does not reach it. Release the fix as a new
  version.
- **Tag release failed before dispatching** (no `release.yml` run exists):
  re-run the Tag release run. It accepts a tag and GitHub Release it already
  created on the same commit and dispatches `release.yml` again.

## Safeguards

- **Guard.** `release.py check` refuses another artifact's tag, a version that
  differs from `pyproject.toml`, and a commit that is not on `main`.
- **Environment.** `pypi` accepts deployments only from `v[0-9]*` tags.
- **Tags.** The `release tags` ruleset lets only admins move or delete tags.

## PyPI configuration

The PyPI trusted publisher for `scitt-cose` names owner `action-state-group`,
repository `scitt-cose`, workflow `release.yml` and environment `pypi`.
Renaming `release.yml` breaks publishing until a PyPI project owner adds a
publisher for the new name. No API token is stored in this repository.
