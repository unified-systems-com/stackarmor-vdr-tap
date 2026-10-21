# StackArmor VDR Plugin Specification

**`stackarmor_vdr` scores each vulnerability finding's Potential Agency Impact (PAIN) with the deterministic method of stackArmor's memo, from the finding's CVSS impact and what its asset needs, and returns the N-level with its remediation deadline and every number behind it. It is one scoring method on top of `fedramp_20x_vdr`, which owns the reach, the levels and the timeframe tables; it computes on read and stores nothing.**

## Plugin Identity

| Row | Value |
| --- | --- |
| Slug | `stackarmor_vdr` |
| Display name | `StackArmor VDR` |
| Description | The stackArmor deterministic, CVSS-environmental PAIN method for FedRAMP VDR: a finding's N-level and deadline from its CVSS impact, its asset's requirements and its exposure. |
| Kind | Leaf plugin. It consumes `fedramp_20x_vdr` (the finding reach, the PAIN levels and the timeframe rows), `computing_core` (the program a stamp describes) and `compliance_core` (vulnerability facts), and is consumed by the pages and products that show vulnerability posture. |

The display name omits the `TAP` prefix by the owner's choice (George, 2026-10-21).

Default dimensions, one key for every node and edge the plugin ships:

| Key | Value | Why |
| --- | --- | --- |
| `fedramp.rule` | `vdr` | The same rule-family key as `fedramp_20x_vdr`, so one filter scopes to VDR. The value is not the entity type. |

## Philosophy

FedRAMP publishes PAIN's vocabulary (N1 to N5) and the remediation matrix, and not a function from a vulnerability and an asset to an N-level. The memo supplies one: re-weight the CVSS impact of the vulnerability by what the affected asset requires, rescale, map to a word, then to an N-level with the affected-agency flag. It is one defensible method. Other methods can exist, so the method lives in its own plugin and the shared parts live in `fedramp_20x_vdr`, which a second method would reuse unchanged.

The plugin follows the same stair-step as its base: it starts from the worst case and lowers a value only on evidence. A missing CVSS vector scores High, an unclassified asset is High on all three objectives, and the affected-agency flag defaults to 1. Each such assumption is named in the row, so a reader can tell an evidenced derivation from the conservative compatibility result.

What the plugin deliberately does not do: it stores no PAIN (the evaluation's `pain` field stays refused in the base), it does not decide which asset a finding belongs to (the base's reach does), it does not compute internet reachability, it adds nothing to any node or edge that describes the system (a program's profile is a separate stamp node that points at the program, ruled by George, 2026-10-21), and it implements none of the memo's optional extensions in this version (the Backlog rows).

Three states. A value the plugin cannot know is reported as assumed, never as the favourable answer; an absent EPSS or KEV reading makes a finding likely exploitable, not safe.

**Provenance markers.** *Documented:* the memo *A Deterministic, CVSS-Environmental Method for FedRAMP VDR/VER Vulnerability Prioritization* (stackArmor, July 2026; informational, not FedRAMP canon), read in full on 2026-10-20, and the companion paper *Internet Reachability at Scale under the FedRAMP VDR/VER Rules* (July 2026), whose sections 1 to 5 were read in full on 2026-10-21. The memo's other companion papers were not read. *Observed:* the 48 `VDR-TFR-PVR` timeframe rows seeded by `fedramp_20x_vdr` equal the memo's Appendix B (compared 2026-10-20, no mismatch). *Designed:* everything under Requirements.

## Goals

| # | Name | Description |
| --- | --- | --- |
| 1 | Reproducible Score | The same finding, asset and parameters give the same N-level, and a reviewer can redo it by hand from the row. |
| 2 | Conservative By Default | A missing input raises the score and is named, never silently lowers it. |
| 3 | Governed Parameters | Weights, thresholds and the archetype catalog are Search input defaults with history, not constants in code. |
| 4 | One Method, Reusable Base | The plugin holds only what is the method's own, so another method can sit beside it. |

## Requirements

| RID | Name | Status | Notes |
| --- | --- | :---: | --- |
| req-stackarmor-vdr-score | [The Score](#the-score) | Proposed | The pure function from impact, requirements and the affected-agency flag to U, S, the word and the N-level. |
| req-stackarmor-vdr-impact | [Impact From The Vector](#impact-from-the-vector) | Proposed | C, I and A from a CVSS 3.0, 3.1 or 4.0 vector; a missing vector is High. |
| req-stackarmor-vdr-exposure | [Likely Exploitable](#likely-exploitable) | Proposed | LEV from KEV and EPSS thresholds that depend on reachability. |
| req-stackarmor-vdr-stamp | [Asset Profile Stamp](#asset-profile-stamp) | Proposed | The `asset_profile` node, a stamp holding an archetype or an explicit CR, IR and AR with its rationale, and the `PROFILES_PROGRAM` edge to the program it describes. |
| req-stackarmor-vdr-archetypes | [Archetype Catalog](#archetype-catalog) | Proposed | The catalog from archetype to CR, IR and AR, as a Search default. |
| req-stackarmor-vdr-search | [The PAIN Search](#the-pain-search) | Proposed | The `stackarmor-pain` and `stackarmor-assets` `module` Search runners, which read the stamps, reduce them with the base and score. |
| req-stackarmor-vdr-nongoals | [v0 Non-Goals](#v0-non-goals) | Proposed | What this version does not build. |
| req-stackarmor-vdr-ceiling | [Intended-Use Ceiling](#v0-non-goals) | Backlog | The Security Requirements ceiling per agency scope; until it exists the result is the uncapped, conservative compatibility mode and says so. |
| req-stackarmor-vdr-mitigation | [Mitigation Ladder](#v0-non-goals) | Backlog | Evidence-gated Modified C/I/A (High to Low, never None), the residual-response PAIN proxy and the retained consequence PAIN. |
| req-stackarmor-vdr-agencies | [Affected Agencies](#v0-non-goals) | Backlog | The affected-agency flag per asset or finding, from governed hierarchical metadata, and the ephemeral-workload exclusion. This version takes both as Search inputs. |
| req-stackarmor-vdr-library | [Library Profile](#v0-non-goals) | Backlog | A profile for a library or package inside its program, for operators who want finer than the program level. |
| req-stackarmor-vdr-trigger | [Indirect Triggers](#v0-non-goals) | Backlog | The companion paper's carried-content and chained branches of reachability: a CVE-level indirect-trigger status, the CAPEC chain table and the CVE record references a reviewer needs. Parts belong to `compliance_core` (references) and `fedramp_20x_vdr` (the reachability computation). |

### The Score
----
RID: `req-stackarmor-vdr-score`

Status: `Proposed`

#### Implementation

A Django-free module `tap_plugin/stackarmor_vdr/score.py` takes the impact vector (C, I, A), the effective requirement vector (CR, IR, AR) and the affected-agency flag `m`, and returns every intermediate value. With the weights None 0, Low 0.22, High 0.56 for impact and Low 0.5, Medium 1.0, High 1.5 for requirements:

    U = 1 - (1 - C*CR) * (1 - I*IR) * (1 - A*AR)
    D_H = 1 - (1 - 0.56*1.5)^3 = 0.995904        (computed from the weights, not typed in)
    S = U / D_H

The word is Minimal below `theta1`, Narrow from `theta1` to below `theta2`, Disruptive from `theta2` to below `theta3`, Debilitating from `theta3`, with `theta1 = 0.28 / D_H`, `theta2 = 0.56 / D_H` and `theta3 = 0.933`. The N-level is N1 for Minimal, N2 for Narrow, N3 for Disruptive with `m = 0`, N4 for Disruptive with `m = 1` or Debilitating with `m = 0`, and N5 for Debilitating with `m = 1`. The arithmetic uses `decimal.Decimal`, and the first two boundaries are compared as `U` against 0.28 and 0.56, because the memo's worked example 5 sits exactly on `theta1` (`S = 0.28 / D_H`) and a rounded decimal threshold would flip it.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-stackarmor-vdr-score-1 | Pure Function | Proposed | `score.py` imports and runs with Django blocked, reads no node and gives the same output for the same input. | |
| req-stackarmor-vdr-score-2 | The Memo's Five Examples | Proposed | The function returns N5, N4, N3, N3 and N2 for the memo's worked examples 1 to 5, with the memo's `U` and `S` to six places. | Requirements and flag: 1 is H/H/H, `m` 1 (impact H/H/H); 2 is M/M/M, `m` 1 (impact H/H/H); 3 is L/L/L, `m` 0 (impact H/H/H); 4 is M/M/H, `m` 0 (impact A only); 5 is L/M/M, `m` 0 (impact C only). |
| req-stackarmor-vdr-score-3 | Exact Boundaries | Proposed | One High impact at a Low requirement (`U` exactly 0.28) is Narrow and one High impact at a Medium requirement (`U` exactly 0.56) is Disruptive; a test fails if the comparison is done on a rounded decimal threshold. | Example 5 sits on the first boundary. |
| req-stackarmor-vdr-score-4 | Maximum Is D_H | Proposed | `D_H` is computed from the weights and equals 0.995904; all-High impact at all-High requirements gives `S` of exactly 1. | |
| req-stackarmor-vdr-score-5 | N-Level From Word And Scope | Proposed | The eight word-and-flag combinations map as stated above: Minimal gives N1 and Narrow N2 for either flag; Disruptive gives N3 with `m` 0 and N4 with `m` 1; Debilitating gives N4 with `m` 0 and N5 with `m` 1. | |

### Impact From The Vector
----
RID: `req-stackarmor-vdr-impact`

Status: `Proposed`

#### Implementation

`compliance_vulnerability.cvss_vector` with `cvss_version` 3.0 or 3.1 gives C, I and A (None, Low, High). Version 4.0 gives VC, VI and VA, the memo's limited compatibility path; the Subsequent-System metrics are returned in the row as evidence and not scored. A missing or unparseable vector assumes High on all three, and the row says `impact_source` is `assumed`, because missing data must not lower PAIN.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-stackarmor-vdr-impact-1 | Version 3 Vectors | Proposed | A 3.0 or 3.1 vector gives C, I and A as None, Low or High. | |
| req-stackarmor-vdr-impact-2 | Version 4 Vectors | Proposed | A 4.0 vector gives C, I and A from VC, VI and VA; the subsequent-system metrics are returned and not scored. | The memo's limited compatibility path. |
| req-stackarmor-vdr-impact-3 | Missing Is High | Proposed | A missing or unparseable vector gives High on all three with `impact_source` `assumed`. | |

### Likely Exploitable
----
RID: `req-stackarmor-vdr-exposure`

Status: `Proposed`

#### Implementation

Likely exploitable (LEV) is, in order: the evaluation's `likely_exploitable` factor when it is evidence-backed (true or false); otherwise true when the vulnerability's `kev` is true, or its `epss_score` is at or above 0.20 for an internet-reachable row or 0.55 for a row that is not, and true when `kev` and `epss_score` are both unobserved. An evaluation factor is evidence-backed under the base's rule (an evidence edge, the finding citing the evidence, `evaluator` and `evaluated_at` set); a null or unsupported factor does not override, so the default stays the computed value. The evaluation read is the one whose scheme equals the Search input `evaluation_scheme` (default `max`). Ruled by George, 2026-10-21: an evidenced evaluation overrides KEV and EPSS. Internet reachability is the base's: read from the finding's evaluation, true unless an evidence-backed false. The column and the deadline come from the base's exposure-column and deadline functions. The ephemeral-workload exclusion needs a flag no node carries and is Backlog (`req-stackarmor-vdr-agencies`); until then no workload is ephemeral.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-stackarmor-vdr-exposure-1 | KEV Or EPSS | Proposed | KEV true, or `epss_score` at or above the threshold for the row's reachability, or both unobserved, gives LEV true; KEV false with a lower EPSS gives false. | |
| req-stackarmor-vdr-exposure-2 | Thresholds Are Inputs | Proposed | The two EPSS thresholds are Search inputs with the defaults 0.20 and 0.55. | |
| req-stackarmor-vdr-exposure-3 | An Evidenced Factor Overrides | Proposed | An evidence-backed `likely_exploitable` on the finding's evaluation for the Search's `evaluation_scheme` decides LEV, whether true or false; a null or unsupported factor does not, and KEV and EPSS decide. | Ruled by George, 2026-10-21. |
| req-stackarmor-vdr-exposure-4 | Evaluation Scheme Is An Input | Proposed | The scheme whose evaluation is read is the Search input `evaluation_scheme`, default `max`. | Separate from the stamp's `scheme`. |

### Asset Profile Stamp
----
RID: `req-stackarmor-vdr-stamp`

Status: `Proposed`

The method needs to know what a program requires. That is the method's own judgment, so it lives in this plugin as a **stamp**: a node of its own that points at the program, so adding the method changes no node or edge that describes the system (ruled by George, 2026-10-21). The profile is stamped on the program and nowhere else (ruled by George, 2026-10-20); a host or container's profile is computed from its programs on read.

#### Implementation

Entity type `stackarmor_vdr__asset_profile`, `NATURAL_KEY = ("source", "stamp_key")`, default dimensions `{"fedramp.rule": "vdr"}`.

| Field | Meaning |
| --- | --- |
| `source` | Required. Who made the stamp (a collector, a person, a seed). |
| `stamp_key` | Required. The source's own name for the stamp, unique within the source. |
| `scheme` | Required, free text, default `stackarmor`. The evaluation scheme the stamp serves, so the Search can filter on it. |
| `archetype` | An archetype name, or null. |
| `cr`, `ir`, `ar` | `low`, `medium`, `high`, or null. An explicit value for one objective. |
| `rationale` | Required text: why this profile. The memo asks for the evidence and rationale to be retained. |

A stamp must carry an archetype or at least one of `cr`, `ir`, `ar`; one with none is refused. Per objective, an explicit value beats the archetype's value (the memo's per-asset override), so an override of one objective leaves the others on the archetype. A stamp is not containment of the program and not contained by it.

Edge `PROFILES_PROGRAM__stackarmor_vdr`, `<asset_profile> PROFILES_PROGRAM <program>`, sources `stackarmor_vdr__asset_profile`, targets `computing_core__program` only. It is a reference with the plain identity (`discriminators: []`), no properties and the default dimensions above. Its target is a program because the profile is stamped on the program only. A program may have several stamps (another source, another scheme); the Search filters by `scheme` and, if several remain, takes the per-objective maximum with the base's reducer, so a second stamp never lowers the result.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-stackarmor-vdr-stamp-1 | Keyed By Source And Stamp Key | Proposed | The node declares `NATURAL_KEY = (source, stamp_key)` and both are required; the same pair is one node. | |
| req-stackarmor-vdr-stamp-2 | Values Are Checked | Proposed | `cr`, `ir` and `ar` outside `low`, `medium`, `high` and null are refused, an `archetype` that is not a lower-case name is refused, and `rationale` and `scheme` are required. | |
| req-stackarmor-vdr-stamp-3 | A Stamp Says Something | Proposed | A stamp with no archetype and none of `cr`, `ir`, `ar` is refused. | |
| req-stackarmor-vdr-stamp-4 | An Explicit Objective Wins | Proposed | Per objective an explicit `cr`, `ir` or `ar` beats the archetype's value for that objective, which beats High. | The memo's override rule. |
| req-stackarmor-vdr-stamp-5 | The Edge Points At A Program Only | Proposed | `PROFILES_PROGRAM` connects an `asset_profile` to a `computing_core__program`; a host, a container or any other target is refused wherever an endpoint declares its edges. | Ruled by George, 2026-10-20. |
| req-stackarmor-vdr-stamp-6 | Plain Reference | Proposed | The edge declares `identity: {discriminators: []}`, has no `property_schema` and is in no model's `CONTAINMENT_EDGES`. | |
| req-stackarmor-vdr-stamp-7 | Several Stamps Never Lower | Proposed | A program with more than one stamp for the Search's scheme is scored on the per-objective maximum of them. | |
| req-stackarmor-vdr-stamp-8 | Nothing Describing The System Changes | Proposed | The plugin adds no field, dimension or edge to a `program`, `host`, `container` or any node it does not ship. | Ruled by George, 2026-10-21. |

### Archetype Catalog
----
RID: `req-stackarmor-vdr-archetypes`

Status: `Proposed`

#### Implementation

The memo's illustrative catalog (its Appendix A) maps an asset archetype to its CR, IR and AR. Archetype names use underscores for the memo's hyphens. The catalog is the `archetypes` default of the plugin's Searches, an object from the archetype name to `{cr, ir, ar}` (each `low`, `medium` or `high`), so a change is a reviewable change of a Search node. The catalog is the provider's own to choose and justify; the memo says it is one example derivation, not the standard.

| Value | CR | IR | AR | Typical members |
| --- | :---: | :---: | :---: | --- |
| `cicd_pipeline` | H | H | H | Build and deploy runners, artifact signing, registries |
| `orchestrator` | H | H | H | Control plane, etcd, scheduler, coordination |
| `config_actuation` | H | H | H | IaC and GitOps, schema registry, admin and migration |
| `identity_secrets` | H | H | H | IdP and SSO, KMS, secrets managers, session stores |
| `security_tooling` | H | H | M | Scanners, SIEM, EDR, runtime security |
| `change_record` | M | M | M | ITSM and ticketing, record only |
| `platform_foundation` | L | H | H | DNS, NTP, service discovery, internal L4 load balancers, metadata only |
| `data_sensitive` | H | H | H | PII and CUI datastores |
| `data_backbone` | H | H | H | Payload queues and brokers, the system-of-record database |
| `telemetry_backbone` | M | M | M | Metrics and trace pipelines, event buses carrying no agency payload |
| `app_tier` | M | M | M | Stateless services, APIs, user interfaces, caches |
| `batch_analytics` | M | M | L | ETL, reporting, analytics jobs |
| `public_edge` | M | M | H | TLS-terminating layer 7: ingress, API gateways, public web |
| `passthrough_edge` | L | L | H | Layer 4 and SNI passthrough load balancers, no TLS termination |
| `internal_tooling` | L | L | L | Dashboards, metrics and log agents |
| `dev_test` | L | L | L | Non-production |

The classification rule the memo recommends is control-plane first: an asset that can deploy, orchestrate, hold cross-estate credentials or actuate configuration is classified by that function, not by the data it stores. The stamp itself (which program carries which archetype) is the instance's data, a stamp node, not this plugin's. An archetype name a stamp carries that the catalog does not hold reads as unclassified, High on all three objectives.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-stackarmor-vdr-archetypes-1 | Sixteen Archetypes | Proposed | The catalog holds exactly the sixteen archetypes of the table, with the table's CR, IR and AR. | |
| req-stackarmor-vdr-archetypes-2 | Catalog Is A Search Default | Proposed | The catalog is the `archetypes` default of the Searches' input schema, keyed by the archetype name, and no constant in code duplicates it. | The memo requires governed configuration. |
| req-stackarmor-vdr-archetypes-3 | Unknown Archetype Is Unclassified | Proposed | A stamp whose archetype the catalog does not hold gives High on all three objectives with `profile_source` `unclassified`. | Fail safe. |

### The PAIN Search
----
RID: `req-stackarmor-vdr-search`

Status: `Proposed`

#### Implementation

Two `module` Search runners in `tap_plugin/stackarmor_vdr/searches/`, under the read rules of `tap_grid.gryphon.read_scope`. They return rows and write nothing; the Search nodes that point at them are the instance's.

**`stackarmor-pain`** imports the base's `reach_rows`. For each reach row it reads the stamp of each program involved by following `PROFILES_PROGRAM`, filtered by `scheme`, resolves each program's profile per objective (an explicit value, else the archetype's value from the catalog, else High), reduces the programs with the base's `reduce_profiles`, then computes the impact, the score, the exposure and the deadline. A program with no stamp counts as unclassified, High on all three. One row per finding per owner per container. Inputs, all with defaults: the weights, the three thresholds, both EPSS thresholds, `multi_agency` (default 1), `fedramp_class` (default `d`), `scheme` (default `stackarmor`), `evaluation_scheme` (default `max`), `archetypes`.

**`stackarmor-assets`** returns one row for each node with `RUNS_PROGRAM` edges (a host, a container, an instance): the per-objective maximum of its programs' resolved profiles, reduced with the base, the program count and the classified count. It is computed on read and nothing is stamped on the asset (ruled by George, 2026-10-20).

**`profile_source`.** `container` for a row owned by a container (its profile is the reduction of its programs). For a program owner: `override` when every objective came from an explicit value, `archetype` when an objective came from the catalog and none was unclassified, `unclassified` when any objective fell to High for want of a stamp or a catalog entry.

**The row.** `finding_id`, `vuln_id`, `component`, `container_id`, `container` (the container in which the owner owns the package; a package node is shared by every host that installs it, so a program-owned row still names its container), `owner_kind`, `owner_id`, `owner`, `scheme`, `profile_source`, `impact_source`, `c`, `i`, `a`, `cr`, `ir`, `ar`, `u`, `s` (decimal strings), `word`, `m`, `multi_agency_source`, `pain`, `lev`, `irv`, `column`, `fedramp_class`, `deadline_hours`. Every input of the derivation is in the row, which is the audit trail the memo asks for.

**The affected-agency flag.** `m` is the Search input `multi_agency`, default 1, the worst case, and the row says it was assumed. A per-asset flag is Backlog.

**Governed parameters.** The weights, the three thresholds, both EPSS thresholds and the catalog are Search input defaults, so they have history and a reviewer can see a change. The memo says they must not be changed after seeing a finding's deadline.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-stackarmor-vdr-search-1 | One Row Per Finding And Owner | Proposed | The Search returns the base's reach rows, one per open finding and owner, each with a score. | Ruled by George, 2026-10-20. |
| req-stackarmor-vdr-search-2 | Derivation In The Row | Proposed | Every row carries every input and intermediate listed under "The row", so a reviewer can redo it by hand. | |
| req-stackarmor-vdr-search-3 | Parameters Are Search Defaults | Proposed | The weights, thresholds, EPSS thresholds, scheme and catalog are declared in the runner's input schema with defaults, and no constant in code duplicates one. | |
| req-stackarmor-vdr-search-4 | Agencies Assumed Visibly | Proposed | `m` is the input `multi_agency`, default 1, and every row carries `multi_agency_source`. | The worst case. |
| req-stackarmor-vdr-search-5 | Nothing Is Stored | Proposed | Neither runner writes a node or an edge, and the evaluation's `pain` stays refused. The stamp node is the instance's data, written by whoever stamps. | |
| req-stackarmor-vdr-search-6 | Unclassified Is Not Evidence | Proposed | A Search's description says that a row with `profile_source` `unclassified` or `container`, or with `multi_agency_source` assumed, is the conservative compatibility result and not an evidenced, agency-specific derivation. | The memo forbids describing it as evidenced. |
| req-stackarmor-vdr-search-7 | Runner Keys | Proposed | The runners are registered as `tap_plugin.stackarmor_vdr.searches.pain:stackarmor-pain` and `tap_plugin.stackarmor_vdr.searches.pain:stackarmor-assets`, the keys the instance's Searches name. | |
| req-stackarmor-vdr-search-8 | Dependency Floor | Proposed | `depends_on` and the dependency floor name `fedramp_20x_vdr` at the first release that ships `reach_rows` and the deadline function, and `compliance_core` at the release that ships the vulnerability fields read. | The floor rises when that release is cut. |
| req-stackarmor-vdr-search-9 | Stamps Are Read Through The Edge | Proposed | The Search reads a program's profile only from `asset_profile` nodes reached by `PROFILES_PROGRAM` with the Search's `scheme`, and from no dimension key. | |
| req-stackarmor-vdr-search-10 | Rows Carry Their Scheme | Proposed | Every row of both Searches carries `scheme`, the Search input. | So the result can be compared with another scheme's. |

### v0 Non-Goals
----
RID: `req-stackarmor-vdr-nongoals`

Status: `Proposed`

This version does not:

- store PAIN, an owner or a profile (`req-stackarmor-vdr-search-5`);
- decide which asset a finding belongs to, or compute reachability: both are the base's;
- implement the memo's intended-use ceiling, mitigation ladder, per-asset agency flag or per-library profile (the Backlog rows), or the memo's cross-system aggregation of CVSS v4.0 subsequent-system impact, which the memo itself does not specify;
- ship pages or panels: the Searches are the surface other pages read;
- ship any model or edge beyond the stamp and its edge.

## Model catalog

| Model | Entity type | Category | Rationale |
| --- | --- | --- | --- |
| Asset Profile | `stackarmor_vdr__asset_profile` | Evaluation input | The method's judgment of what a program requires, kept apart from the program so the system's own nodes are untouched. |

## Edge types

| Edge | From → To | Properties | Rationale |
| --- | --- | --- | --- |
| `PROFILES_PROGRAM__stackarmor_vdr` | `asset_profile` → `computing_core__program` | none | The stamp points at the thing it describes; a program only, because the profile is stamped there. |

## Reference data

The plugin seeds no data. The archetype catalog is a Search default (`req-stackarmor-vdr-archetypes-2`) and stamps are the instance's.
