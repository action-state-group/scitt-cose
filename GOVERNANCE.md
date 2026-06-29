<!-- SPDX-License-Identifier: Apache-2.0 -->
# Governance

The Agent Action Capsule is an open project that produces a **neutral, openly
governed record layer for agent actions** — and is built to be donated. This
document states how the project is run today, the principles it holds to, and the
concrete path to a neutral foundation home. It is modeled on Linux Foundation
project-governance practice.

> A human-readable version of this model is published at
> <https://agentactioncapsule.org/docs/governance.html>.

## Why governed this way

Verifiable records of what AI agents do are infrastructure the whole ecosystem
depends on. We believe AI safety and open standards matter far too much for that
layer to be controlled by any single company — so the design goal from day one is
to give it away. The maintainers have stewarded openly and neutrally governed
software before (the Presto Foundation, under the Linux Foundation), and this
project is modeled on that practice.

## Principles

- **Open** — Apache-2.0 tooling; the specification under the IETF Trust's terms
  (BCP 78/79, with code components under the Revised BSD License). Developed in
  public.
- **Vendor-neutral** — no required product; the specification favors no vendor.
  Any party can implement, run, and anchor — including in their own environment.
- **Verifiable** — decisions happen in the open: public issues, public pull
  requests, public discussion.
- **Donate by design** — the profile, the trademark, and the reference services
  are intended to transfer to a neutral foundation as the ecosystem matures.

## Where it stands today

The project is **stewarded by Action State Group**, which also operates the
reference services (the public transparency log and the hosted verifier) for now.
This is the honest current state: a single steward, structured to become neutral —
not yet a multi-party foundation. We state this plainly rather than imply
neutrality the structure does not yet have.

## Roles

- **Contributors** — anyone who opens an issue or pull request. Contributions are
  made under the Developer Certificate of Origin (DCO sign-off); there is no CLA.
- **Maintainers** — review and merge changes, cut releases, and steward each
  repository. Co-maintainers from other organizations are explicitly welcome, and
  earn merge rights through sustained, high-quality contribution.
- **Technical Steering Committee (planned)** — as independent maintainers join, a
  lightweight TSC will take over cross-repository and cross-cutting decisions, in
  the standard Linux-Foundation-style model.

## How decisions are made

Changes happen by pull request and public discussion, with **lazy consensus**
among maintainers; significant changes get an issue first. Maintainers aim for
consensus; where it can't be reached, a majority of maintainers decides, and the
rationale is recorded in the issue or PR.

The **specification** evolves through the IETF process — it is an individual
Internet-Draft (`draft-mih-scitt-agent-action-capsule`), and the goal is to bring
it to the SCITT working group, where the working group — not this project —
decides its standing.

## Conformance to the final standard

SCITT and COSE are still being finalized at the IETF. This profile is built to
**track them**: as those drafts advance and are published as RFCs, the profile and
its reference implementations will be updated to conform to the final versions, and
any breaking changes will be versioned and documented. Building on it today should
not strand you when the standard lands.

## Becoming a maintainer

Open issues and PRs, review others' changes, and help in discussions. After a
track record of quality contributions, existing maintainers may invite you to
become a maintainer. Maintainership is not tied to employer; contributors from any
organization are welcome.

## The path to a neutral foundation

Donation is a commitment, not just an intention. The intended sequence:

| Trigger | What transfers |
| --- | --- |
| Independent implementers + a stable profile | governance moves to a multi-organization Technical Steering Committee |
| A foundation home is selected (with the community) | the `agentactioncapsule.org` domain, the "Agent Action Capsule" trademark, and the reference services transfer to the neutral home |
| Spec adoption | change control of the profile follows the IETF process on WG adoption / RFC publication |

Candidate homes are neutral, foundation-style bodies in the open-source and
standards world. The specific home will be chosen **with the community**, not
announced unilaterally.

## Scope & boundaries

The open project is the **record layer**: the profile, the producer (with example
constraint manifests), the verifier, and the anchor. Acting on declared
constraints at runtime — *enforcement* — is a separate concern that composes with
a policy gateway. The capsule records what happened; it does not gate. We state
this boundary so the open/commercial line is transparent rather than implied.

## Code of Conduct

All participants are expected to follow the project
[Code of Conduct](./CODE_OF_CONDUCT.md). Report concerns to the maintainers at
<conduct@actionstate.ai>.

## Licensing

- Tooling (`capsule-emit`, `scitt-cose`, `capsule-anchor`): **Apache-2.0**.
- Specification (`agent-action-capsule`): **IETF Trust BCP 78/79**, with code
  components under the **Revised BSD License**.

## Getting involved

Open an issue or PR on [GitHub](https://github.com/action-state-group), comment on
the [Internet-Draft](https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/),
or email <spec@actionstate.ai>. A community chat (Discord/Slack) is coming soon.
