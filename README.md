# stackarmor-vdr-tap

StackArmor VDR (`stackarmor_vdr`): the StackArmor method for evaluating FedRAMP 20x vulnerabilities, as a TAP plugin.

StackArmor's memo describes how to rate a vulnerability's Potential Agency Impact (PAIN) from the CVSS impact of the vulnerability and what the affected asset needs (its confidentiality, integrity and availability requirement), instead of leaving every finding at the worst case. This plugin holds **only that method**. Everything generic to FedRAMP's VDR process, and anything another method could reuse, lives in `fedramp_20x_vdr`: which asset a finding belongs to, the ordered PAIN levels, the remediation deadline lookup, the evidence-backed factors and the fail-safe profile reduction.

The method's own vocabulary lives here and adds nothing to the nodes and edges that describe the system being evaluated: an **asset profile** node and a **`PROFILES_PROGRAM`** edge pointing at the program it describes, and archetype nodes the profile names.

## Read first

`specs/spec-stackarmor-vdr-v0.md`, once the spec PR is merged. Until then the spec is on the PR branch `spec/stackarmor-vdr-v0`.

## Depends on

`fedramp_20x_vdr` (v0.1.2 or later), which brings `computing_core` (v0.10.2) and `compliance_core` (v0.8.7).

## Stand it up

From a TAP core checkout:

```bash
scripts/spawn-session.sh <label> cli --from 'git+https://github.com/CriticalSecLLC/stackarmor-vdr-tap@<rev>#ci' --dev-plugins stackarmor_vdr
```

The `ci` record is added with the plugin itself; it is not in the repository yet.
