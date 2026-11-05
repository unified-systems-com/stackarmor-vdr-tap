# stackarmor-vdr-tap

FedRAMP publishes the PAIN levels N1 to N5 and the remediation matrix, and not a rule that turns a vulnerability on an asset into a VDR evaluation with attached SLA. stackArmor's Matthew Venne has published a [whitepaper](https://stackarmor.github.io/rfc-fedramp-vdr/vdr-pain-cvss.pdf) and an [explanatory site](https://stackarmor.github.io/rfc-fedramp-vdr/) that supplies an implementation. This prototype plugin implements their approach using data from the grid.

StackArmor's memo describes how to rate a vulnerability's Potential Agency Impact (PAIN) from the CVSS impact of the vulnerability and what the affected asset needs (its confidentiality, integrity and availability requirement), instead of leaving every finding at the worst case. This plugin holds **only that method**. Everything generic to FedRAMP's VDR process, and anything another method could reuse, lives in `fedramp_20x_vdr`: which asset a finding belongs to, the ordered PAIN levels, the remediation deadline lookup, the evidence-backed factors and the fail-safe profile reduction.

The method's own vocabulary lives here and adds nothing to the nodes and edges that describe the system being evaluated: an **asset profile** node and a **`PROFILES_PROGRAM`** edge pointing at the program it describes, and archetype nodes the profile names.

## How this came about, and who to thank

FedRAMP 20x asks a cloud provider to evaluate every vulnerability it finds on an asset and to remediate within a time set by the finding's Potential Agency Impact (PAIN, N1 to N5), the provider's certification class and how exposed the finding is. FedRAMP publishes those levels and the remediation matrix. It does not publish the step that decides, for one vulnerability on one asset, which PAIN level applies. Without that step a provider either treats every finding as the worst case or invents its own rule.

We started the other way round: a plugin, `fedramp_20x_vdr`, that evaluates every finding at the worst case, reads the evidence a human or a tool attaches, and lowers the answer only when evidence supports it. Then we looked for a published method that could replace the worst-case default with something defensible, and found [Matthew Venne](https://github.com/stackArmor)'s work at stackArmor. His whitepaper, [*A Deterministic, CVSS-Environmental Method for FedRAMP VDR/VER Vulnerability Prioritization*](https://stackarmor.github.io/rfc-fedramp-vdr/vdr-pain-cvss.pdf), and the [explanatory site and companion papers](https://stackarmor.github.io/rfc-fedramp-vdr/) (source: [stackArmor/rfc-fedramp-vdr](https://github.com/stackArmor/rfc-fedramp-vdr)) turn the standard CVSS Environmental metrics, the confidentiality, integrity and availability requirements of the asset, into a closed-form PAIN level that can be computed, audited and argued with. It is the first published method we found that does the missing step in the open and with the arithmetic shown.

**Thank you, Matthew, and stackArmor, for putting it out there.** Publishing a worked, testable method, with examples, a calibration and an honest list of what it does not cover, made this plugin possible and made it checkable: the five worked examples in the whitepaper are tests here and come out at the published values. The method is theirs; any error in this implementation is ours.

This plugin was developed with AI coding assistance (Claude Code) under the direction of the maintainer. Each change records what was run and what was not in its pull request, and the tests in this repository are the evidence.

## What this is, and is not

- A **prototype** implementation of the stackArmor method on [TAP](https://github.com/unified-systems-com/tap), computed on read from the nodes and edges in the grid; it stores no result.
- Built against the stackArmor repository at commit `e3368d72d4354d107d6002cdc881a1d8110d617f` (the whitepaper still carries a July 2026 date). Where this plugin departs from the whitepaper, the spec says so: see "Local choices" in `specs/spec-stackarmor-vdr-v0.md`.
- **Uncapped.** The whitepaper's intended-use ceiling is not implemented; every row says `uncapped`, so a result is the compatibility subset, not an agency-specific derivation.
- **Not affiliated with, endorsed by or reviewed by stackArmor or FedRAMP**, and not a statement of FedRAMP compliance. The stackArmor materials are linked, not copied: we checked this repository's text against the stackArmor sources for copied passages and found only the cited title and URL and the published weights and formula, which are the method itself.

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
- `module` Search runners ( `stackarmor-trace`, returns the objects behind one finding's score as a graph for a graph panel), `stackarmor-pain` (a score, N-level and deadline per open finding per owner, with every input in the row; `vuln_id` limits it to one vulnerability), `stackarmor-assets` (the profile each node resolves to) `stackarmor-summary` (counts by PAIN level and by what was assumed, for charts and cards) and `stackarmor-trace`. Their parameters are one `INPUT_SCHEMA` in `searches/pain.py`; a Search node copies it. Nothing is stored.
- `stackarmor-finding`, a fifth Search runner: one finding on one component under one owner walked step by step, as a breakdown and twelve steps with a short description and an expandable detail each.
- Three panel types. `stackarmor_prose`: styled prose from config text, variants `plain`, `method` and `steps`. `stackarmor_finding`: draws the `stackarmor-finding` result. `stackarmor_html`: untrusted HTML from config or from a field of a Search, cleaned on every render against a closed vocabulary of features that each panel can only narrow (see the spec's HTML Panel section for the threat model). Text is escaped and colours are theme tokens.
- A stamp may state the affected-agency flag `multi_agency` (0 or 1) for its program; a program that states none uses the Search input, default 1, and the row says which.
- The pure method: `score.py`, `impact.py`, `exposure.py` (Django-free).

A row whose `profile_source` is `unclassified` or `container`, or whose `multi_agency_source` is `assumed`, is the conservative compatibility result, not an evidenced derivation.
