# stackarmor-vdr-tap

StackArmor VDR (`stackarmor_vdr`): the StackArmor method for evaluating FedRAMP 20x vulnerabilities, as a TAP plugin.

StackArmor's memo describes how to rate a vulnerability's Potential Agency Impact (PAIN) from the CVSS impact of the vulnerability and what the affected asset needs (its confidentiality, integrity and availability requirement), instead of leaving every finding at the worst case. This plugin holds **only that method**. Everything generic to FedRAMP's VDR process, and anything another method could reuse, lives in `fedramp_20x_vdr`: which asset a finding belongs to, the ordered PAIN levels, the remediation deadline lookup, the evidence-backed factors and the fail-safe profile reduction.

The method's own vocabulary lives here and adds nothing to the nodes and edges that describe the system being evaluated: an **asset profile** node and a **`PROFILES_PROGRAM`** edge pointing at the program it describes, and archetype nodes the profile names.

## Read first

`specs/spec-stackarmor-vdr-v0.md`.

## Depends on

`fedramp_20x_vdr` (v0.1.2 or later), which brings `computing_core` (v0.10.2) and `compliance_core` (v0.8.7).

## Stand it up

From a TAP core checkout:

```bash
scripts/spawn-session.sh <label> cli --from 'git+https://github.com/CriticalSecLLC/stackarmor-vdr-tap@<rev>#ci' --dev-plugins stackarmor_vdr
```

The `ci` record ships in the package (`tap_plugin/stackarmor_vdr/boot/ci.boot.json`); until the first release it pins this plugin at the placeholder `v0.0.0`, which the consumer flips to the checkout under test.

## What it ships

- `stackarmor_vdr__asset_profile` and `stackarmor_vdr__archetype` nodes, the `PROFILES_PROGRAM__stackarmor_vdr` and `USES_ARCHETYPE__stackarmor_vdr` edges, and the sixteen archetypes of the memo's Appendix A as a seed.
- Four `module` Search runners (the fourth, `stackarmor-trace`, returns the objects behind one finding's score as a graph for a graph panel), `stackarmor-pain` (a score, N-level and deadline per open finding per owner, with every input in the row; `vuln_id` limits it to one vulnerability), `stackarmor-assets` (the profile each node resolves to) and `stackarmor-summary` (counts by PAIN level and by what was assumed, for charts and cards). Their parameters are one `INPUT_SCHEMA` in `searches/pain.py`; a Search node copies it. Nothing is stored.
- One panel type, `stackarmor_prose` (view `stackarmor_vdr/panels/prose.html`): styled prose from config text, variants `plain`, `method` and `steps`; text is escaped and colours are theme tokens. It takes only config and reads no Search.
- A stamp may state the affected-agency flag `multi_agency` (0 or 1) for its program; a program that states none uses the Search input, default 1, and the row says which.
- The pure method: `score.py`, `impact.py`, `exposure.py` (Django-free).

A row whose `profile_source` is `unclassified` or `container`, or whose `multi_agency_source` is `assumed`, is the conservative compatibility result, not an evidenced derivation.
