# StackArmor VDR Plugin Specification

FedRAMP publishes the PAIN levels N1 to N5 and the remediation matrix, and not a rule that turns a vulnerability on an asset into a VDR evaluation with attached SLA. stackArmor's Matthew Venne has published a [whitepaper](https://stackarmor.github.io/rfc-fedramp-vdr/vdr-pain-cvss.pdf) and an [explanatory site](https://stackarmor.github.io/rfc-fedramp-vdr/) that supplies an implementation. This prototype plugin implements their approach using data from the grid.

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
| 3 | Governed Parameters | Weights and thresholds are Search input defaults, and the archetype catalog is data in the grid, both with history and neither a constant in code. |
| 4 | One Method, Reusable Base | The plugin holds only what is the method's own, so another method can sit beside it. |

## Requirements

| RID | Name | Status | Notes |
| --- | --- | :---: | --- |
| req-stackarmor-vdr-score | [The Score](#the-score) | Implemented | The pure function from impact, requirements and the affected-agency flag to U, S, the word and the N-level. |
| req-stackarmor-vdr-impact | [Impact From The Vector](#impact-from-the-vector) | Implemented | C, I and A from a CVSS 3.0, 3.1 or 4.0 vector; a missing vector is High. |
| req-stackarmor-vdr-exposure | [Likely Exploitable](#likely-exploitable) | Implemented | LEV from KEV and EPSS thresholds that depend on reachability. |
| req-stackarmor-vdr-stamp | [Asset Profile Stamp](#asset-profile-stamp) | Implemented | The `asset_profile` node, a stamp holding an explicit CR, IR and AR or pointing at an archetype, with its rationale, and the `PROFILES_PROGRAM` edge to the program it describes. |
| req-stackarmor-vdr-archetypes | [Archetype Catalog](#archetype-catalog) | Implemented | The `archetype` node, one per archetype carrying its CR, IR and AR, the sixteen memo entries seeded as data, and the `USES_ARCHETYPE` edge a stamp uses to name one. |
| req-stackarmor-vdr-search | [The PAIN Search](#the-pain-search) | Implemented | The `stackarmor-pain` and `stackarmor-assets` `module` Search runners, which read the stamps, reduce them with the base and score. |
| req-stackarmor-vdr-summary | [Summary Counts](#summary-counts) | Implemented | The `stackarmor-summary` `module` Search runner: counts of the `stackarmor-pain` rows by PAIN level and by what was assumed, for charts and cards. |
| req-stackarmor-vdr-trace | [Trace](#trace) | Implemented | The `stackarmor-trace` `module` Search runner: the objects behind one finding's score (finding, vulnerability, component, owner, programs, stamps, archetypes) as a graph, for a graph panel. |
| req-stackarmor-vdr-panel-prose | [The Prose Panel](#the-prose-panel) | Implemented | The `stackarmor_prose` panel type: styled prose from config text, as plain paragraphs, a magazine-style method or a numbered stepper, themed from the palette tokens, text always escaped. |
| req-stackarmor-vdr-finding | [Finding Walk-Through](#finding-walk-through) | In Development | The `stackarmor-finding` `module` Search runner: one finding on one component under one owner, returned as a breakdown and as the ordered steps of its evaluation. |
| req-stackarmor-vdr-panel-finding | [The Finding Panel](#the-finding-panel) | In Development | The `stackarmor_finding` panel type: the breakdown, one field to a line with each value linked to its step, and the walk-through, a description column beside a values column with each step expandable. |
| req-stackarmor-vdr-panel-html | [The HTML Panel](#the-html-panel) | Proposed | The `stackarmor_html` panel type: styled HTML from config or from a field of a linked Search, cleaned on every render by an allowlist, so grid content can be shown as rich, good-looking markup without being able to run anything, load anything or restyle the page. |
| req-stackarmor-vdr-nongoals | [v0 Non-Goals](#v0-non-goals) | Implemented | What this version does not build. |
| req-stackarmor-vdr-ceiling | [Intended-Use Ceiling](#v0-non-goals) | Backlog | The Security Requirements ceiling per agency scope; until it exists the result is the uncapped, conservative compatibility mode and says so. |
| req-stackarmor-vdr-mitigation | [Mitigation Ladder](#v0-non-goals) | Backlog | Evidence-gated Modified C/I/A (High to Low, never None), the residual-response PAIN proxy and the retained consequence PAIN. |
| req-stackarmor-vdr-agencies | [Affected Agencies](#v0-non-goals) | Backlog | The affected-agency flag from governed hierarchical metadata, and the ephemeral-workload exclusion. A program's stamp may state the flag (`req-stackarmor-vdr-stamp-9`); the rest takes the Search input. |
| req-stackarmor-vdr-library | [Library Profile](#v0-non-goals) | Backlog | A profile for a library or package inside its program, for operators who want finer than the program level. |
| req-stackarmor-vdr-trigger | [Indirect Triggers](#v0-non-goals) | Backlog | The companion paper's carried-content and chained branches of reachability: a CVE-level indirect-trigger status, the CAPEC chain table and the CVE record references a reviewer needs. Parts belong to `compliance_core` (references) and `fedramp_20x_vdr` (the reachability computation). |

### The Score
----
RID: `req-stackarmor-vdr-score`

Status: `Implemented`

#### Implementation

A Django-free module `tap_plugin/stackarmor_vdr/score.py` takes the impact vector (C, I, A), the effective requirement vector (CR, IR, AR) and the affected-agency flag `m`, and returns every intermediate value. With the weights None 0, Low 0.22, High 0.56 for impact and Low 0.5, Medium 1.0, High 1.5 for requirements:

    U = 1 - (1 - C*CR) * (1 - I*IR) * (1 - A*AR)
    D_H = 1 - (1 - 0.56*1.5)^3 = 0.995904        (computed from the weights, not typed in)
    S = U / D_H

The word is Minimal below `theta1`, Narrow from `theta1` to below `theta2`, Disruptive from `theta2` to below `theta3`, Debilitating from `theta3`, with `theta1 = 0.28 / D_H`, `theta2 = 0.56 / D_H` and `theta3 = 0.933`. The N-level is N1 for Minimal, N2 for Narrow, N3 for Disruptive with `m = 0`, N4 for Disruptive with `m = 1` or Debilitating with `m = 0`, and N5 for Debilitating with `m = 1`. The arithmetic uses `decimal.Decimal`, and the first two boundaries are compared as `U` against 0.28 and 0.56, because the memo's worked example 5 sits exactly on `theta1` (`S = 0.28 / D_H`) and a rounded decimal threshold would flip it.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-stackarmor-vdr-score-1 | Pure Function | Implemented | `score.py` imports and runs with Django blocked, reads no node and gives the same output for the same input. | |
| req-stackarmor-vdr-score-2 | The Memo's Five Examples | Implemented | The function returns N5, N4, N3, N3 and N2 for the memo's worked examples 1 to 5, with the memo's `U` and `S` to six places. | Requirements and flag: 1 is H/H/H, `m` 1 (impact H/H/H); 2 is M/M/M, `m` 1 (impact H/H/H); 3 is L/L/L, `m` 0 (impact H/H/H); 4 is M/M/H, `m` 0 (impact A only); 5 is L/M/M, `m` 0 (impact C only). |
| req-stackarmor-vdr-score-3 | Exact Boundaries | Implemented | One High impact at a Low requirement (`U` exactly 0.28) is Narrow and one High impact at a Medium requirement (`U` exactly 0.56) is Disruptive; a test fails if the comparison is done on a rounded decimal threshold. | Example 5 sits on the first boundary. |
| req-stackarmor-vdr-score-4 | Maximum Is D_H | Implemented | `D_H` is computed from the weights and equals 0.995904; all-High impact at all-High requirements gives `S` of exactly 1. | |
| req-stackarmor-vdr-score-5 | N-Level From Word And Scope | Implemented | The eight word-and-flag combinations map as stated above: Minimal gives N1 and Narrow N2 for either flag; Disruptive gives N3 with `m` 0 and N4 with `m` 1; Debilitating gives N4 with `m` 0 and N5 with `m` 1. | |

### Impact From The Vector
----
RID: `req-stackarmor-vdr-impact`

Status: `Implemented`

#### Implementation

`compliance_vulnerability.cvss_vector` with `cvss_version` 3.0 or 3.1 gives C, I and A (None, Low, High). Version 4.0 gives VC, VI and VA, the memo's limited compatibility path; the Subsequent-System metrics are returned in the row as evidence and not scored. A missing or unparseable vector assumes High on all three, and the row says `impact_source` is `assumed`, because missing data must not lower PAIN.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-stackarmor-vdr-impact-1 | Version 3 Vectors | Implemented | A 3.0 or 3.1 vector gives C, I and A as None, Low or High. | |
| req-stackarmor-vdr-impact-2 | Version 4 Vectors | Implemented | A 4.0 vector gives C, I and A from VC, VI and VA; the subsequent-system metrics are returned and not scored. | The memo's limited compatibility path. |
| req-stackarmor-vdr-impact-3 | Missing Is High | Implemented | A missing or unparseable vector gives High on all three with `impact_source` `assumed`. | |
| req-stackarmor-vdr-impact-4 | Malformed Is High | Implemented | A vector with no `CVSS:3.0`, `CVSS:3.1` or `CVSS:4.0` prefix, a missing Base metric or a Base metric outside its permitted values gives High on all three with `impact_source` `assumed`; a valid vector of no impact stays `vector` and none. | A string that only looks like a vector must never lower PAIN. Found by the codex review of 2026-10-25. |

### Likely Exploitable
----
RID: `req-stackarmor-vdr-exposure`

Status: `Implemented`

#### Implementation

Likely exploitable (LEV) is, in order: the evaluation's `likely_exploitable` factor when it is evidence-backed (true or false); otherwise true when the vulnerability's `kev` is true, or its `epss_score` is at or above 0.20 for an internet-reachable row or 0.55 for a row that is not, and true when `kev` and `epss_score` are both unobserved. An evaluation factor is evidence-backed under the base's rule (an evidence edge, the finding citing the evidence, `evaluator` and `evaluated_at` set); a null or unsupported factor does not override, so the default stays the computed value. The evaluation read is the one whose scheme equals the Search input `evaluation_scheme` (default `max`). Ruled by George, 2026-10-21: an evidenced evaluation overrides KEV and EPSS. Internet reachability is the base's: read from the finding's evaluation, true unless an evidence-backed false. The column and the deadline come from the base's exposure-column and deadline functions. The ephemeral-workload exclusion needs a flag no node carries and is Backlog (`req-stackarmor-vdr-agencies`); until then no workload is ephemeral.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-stackarmor-vdr-exposure-1 | KEV Or EPSS | Implemented | KEV true, or `epss_score` at or above the threshold for the row's reachability, or both unobserved, gives LEV true; KEV false with a lower EPSS gives false. | |
| req-stackarmor-vdr-exposure-2 | Thresholds Are Inputs | Implemented | The two EPSS thresholds are Search inputs with the defaults 0.20 and 0.55. | |
| req-stackarmor-vdr-exposure-3 | An Evidenced Factor Overrides | Implemented | An evidence-backed `likely_exploitable` on the finding's evaluation for the Search's `evaluation_scheme` decides LEV, whether true or false; a null or unsupported factor does not, and KEV and EPSS decide. | Ruled by George, 2026-10-21. |
| req-stackarmor-vdr-exposure-4 | Evaluation Scheme Is An Input | Implemented | The scheme whose evaluation is read is the Search input `evaluation_scheme`, default `max`. | Separate from the stamp's `scheme`. |

### Asset Profile Stamp
----
RID: `req-stackarmor-vdr-stamp`

Status: `Implemented`

The method needs to know what a program requires. That is the method's own judgment, so it lives in this plugin as a **stamp**: a node of its own that points at the program, so adding the method changes no node or edge that describes the system (ruled by George, 2026-10-21). The profile is stamped on the program and nowhere else (ruled by George, 2026-10-20); a host or container's profile is computed from its programs on read.

#### Implementation

Entity type `stackarmor_vdr__asset_profile`, `NATURAL_KEY = ("source", "stamp_key")`, default dimensions `{"fedramp.rule": "vdr"}`.

| Field | Meaning |
| --- | --- |
| `source` | Required. Who made the stamp (a collector, a person, a seed). |
| `stamp_key` | Required. The source's own name for the stamp, unique within the source. |
| `scheme` | Required, free text, default `stackarmor`. The evaluation scheme the stamp serves, so the Search can filter on it. |
| `cr`, `ir`, `ar` | `low`, `medium`, `high`, or null. An explicit value for one objective. |
| `multi_agency` | `0`, `1` or null. The affected-agency flag `m` for this program: `1` when more than one agency is affected, `0` for one, null says nothing. Added in v0.2.0. |
| `rationale` | Required text: why this profile. The memo asks for the evidence and rationale to be retained. |

A stamp names an archetype by a `USES_ARCHETYPE` edge (see Archetype Catalog) and may also carry explicit `cr`, `ir`, `ar`. A stamp with neither an archetype edge nor an explicit value says nothing and reads as unclassified. Per objective, an explicit value beats the archetype's value (the memo's per-asset override), so an override of one objective leaves the others on the archetype. A stamp is not containment of the program and not contained by it.

Edge `PROFILES_PROGRAM__stackarmor_vdr`, `<asset_profile> PROFILES_PROGRAM <program>`, sources `stackarmor_vdr__asset_profile`, targets `computing_core__program` only. It is a reference with the plain identity (`discriminators: []`), no properties and the default dimensions above. Its target is a program because the profile is stamped on the program only. A program may have several stamps (another source, another scheme); the Search filters by `scheme` and, if several remain, takes the per-objective maximum with the base's reducer, so a second stamp never lowers the result.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-stackarmor-vdr-stamp-1 | Keyed By Source And Stamp Key | Implemented | The node declares `NATURAL_KEY = (source, stamp_key)` and both are required; the same pair is one node. | |
| req-stackarmor-vdr-stamp-2 | Values Are Checked | Implemented | `cr`, `ir` and `ar` outside `low`, `medium`, `high` and null are refused, and `rationale` and `scheme` are required. | |
| req-stackarmor-vdr-stamp-3 | A Stamp Says Something | Implemented | A stamp with no `USES_ARCHETYPE` edge and none of `cr`, `ir`, `ar` is read as unclassified, High on all three objectives, with `profile_source` `unclassified`. | An edge arrives after its node, so the node cannot be refused for lacking one; the read fails safe instead. |
| req-stackarmor-vdr-stamp-4 | An Explicit Objective Wins | Implemented | Per objective an explicit `cr`, `ir` or `ar` beats the named archetype's value for that objective, which beats High. | The memo's override rule. |
| req-stackarmor-vdr-stamp-5 | The Edge Points At A Program Only | Implemented | `PROFILES_PROGRAM` connects an `asset_profile` to a `computing_core__program`; a host, a container or any other target is refused wherever an endpoint declares its edges. | Ruled by George, 2026-10-20. |
| req-stackarmor-vdr-stamp-6 | Plain Reference | Implemented | The edge declares `identity: {discriminators: []}`, has no `property_schema` and is in no model's `CONTAINMENT_EDGES`. | |
| req-stackarmor-vdr-stamp-7 | Several Stamps Never Lower | Implemented | A program with more than one stamp for the Search's scheme is scored on the per-objective maximum of them. | |
| req-stackarmor-vdr-stamp-9 | A Stamp May State The Agency Flag | Implemented | `multi_agency` outside `0`, `1` and null is refused; a program's flag is the highest value any of its stamps states, and a program with none stated uses the Search input `multi_agency`. | The flag is the method's own judgment, so it lives on the stamp and changes no system node. Several stamps never lower it. |
| req-stackarmor-vdr-stamp-8 | Nothing Describing The System Changes | Implemented | The plugin adds no field, dimension or edge to a `program`, `host`, `container` or any node it does not ship. | Ruled by George, 2026-10-21. |

### Archetype Catalog
----
RID: `req-stackarmor-vdr-archetypes`

Status: `Implemented`

An archetype is a named shorthand for a set of requirements. The memo's illustrative catalog (its Appendix A) maps each to a CR, IR and AR, and the memo says the provider owns and justifies its own mapping. So the catalog is data in the grid: one node per archetype, which a provider reads on a page and changes by editing a node, not by a release. Ruled by George, 2026-10-21: one archetype node type, with an edge from the stamp.

#### Implementation

Entity type `stackarmor_vdr__archetype`, `NATURAL_KEY = ("name",)`, default dimensions `{"fedramp.rule": "vdr"}`.

| Field | Meaning |
| --- | --- |
| `name` | Required. A lower-case name, underscores for the memo's hyphens. |
| `cr`, `ir`, `ar` | Required. `low`, `medium` or `high`. |
| `description` | Required text: the typical members and why this mapping. |

Edge `USES_ARCHETYPE__stackarmor_vdr`, `<asset_profile> USES_ARCHETYPE <archetype>`, sources `stackarmor_vdr__asset_profile`, targets `stackarmor_vdr__archetype` only. It is a reference with the plain identity (`discriminators: []`), no properties and the default dimensions above. A stamp may name several archetypes; the Search takes the per-objective maximum of them with the base's reducer, so a second never lowers the result.

The plugin seeds the memo's sixteen as reference data, with the source `stackarmor-memo-appendix-a`:

| Name | CR | IR | AR | Typical members |
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

The classification rule the memo recommends is control-plane first: an asset that can deploy, orchestrate, hold cross-estate credentials or actuate configuration is classified by that function, not by the data it stores. Which program carries which archetype is the instance's data, a stamp node and its edge, not this plugin's. A stamp whose archetype edge points at nothing readable (the node is tombstoned, or no edge exists) reads as unclassified, High on all three objectives.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-stackarmor-vdr-archetypes-1 | Sixteen Archetypes Seeded | Implemented | The seed holds exactly the sixteen archetypes of the table, with the table's CR, IR and AR, and a re-seed adds no duplicate. | |
| req-stackarmor-vdr-archetypes-2 | Catalog Is Data | Implemented | The Searches read each archetype's values from `archetype` nodes through `USES_ARCHETYPE`, and no constant, input default or other copy in code holds them. | The memo requires governed configuration; a node has the grid's history. |
| req-stackarmor-vdr-archetypes-3 | Unknown Archetype Is Unclassified | Implemented | A stamp with no readable archetype and no explicit value gives High on all three objectives with `profile_source` `unclassified`. | Fail safe. |
| req-stackarmor-vdr-archetypes-4 | Archetype Values Are Checked | Implemented | The node declares `NATURAL_KEY = (name)`; `name`, `cr`, `ir`, `ar` and `description` are required, `cr`, `ir` and `ar` outside `low`, `medium` and `high` are refused, and a name that is not lower-case with underscores is refused. | |
| req-stackarmor-vdr-archetypes-5 | The Edge Joins A Stamp To An Archetype | Implemented | `USES_ARCHETYPE` connects an `asset_profile` to an `archetype` only, declares `identity: {discriminators: []}`, has no `property_schema` and is in no model's `CONTAINMENT_EDGES`. | |
| req-stackarmor-vdr-archetypes-6 | Several Archetypes Never Lower | Implemented | A stamp with more than one archetype is scored on the per-objective maximum of them. | |
| req-stackarmor-vdr-archetypes-7 | A Seed Never Overwrites An Edit | Implemented | Re-seeding creates a missing archetype and leaves an existing archetype of the same name as the instance has it. | The provider owns the mapping; the sixteen are a starting point. |

### The PAIN Search
----
RID: `req-stackarmor-vdr-search`

Status: `Implemented`

#### Implementation

Two `module` Search runners in `tap_plugin/stackarmor_vdr/searches/`, under the read rules of `tap_grid.gryphon.read_scope`. They return rows and write nothing; the Search nodes that point at them are the instance's.

**`stackarmor-pain`** imports the base's `reach_rows`. For each reach row it reads the stamp of each program involved by following `PROFILES_PROGRAM`, filtered by `scheme`, resolves each program's profile per objective (an explicit value, else the value of the archetype its stamp names through `USES_ARCHETYPE`, else High), reduces the programs with the base's `reduce_profiles`, then computes the impact, the score, the exposure and the deadline. A program with no stamp counts as unclassified, High on all three. One row per finding per owner per container. Inputs, all with defaults: the weights, the three thresholds, both EPSS thresholds, `multi_agency` (default 1), `fedramp_class` (default `d`), `scheme` (default `stackarmor`), `evaluation_scheme` (default `max`).

**`stackarmor-assets`** returns one row for each node with `RUNS_PROGRAM` edges (a host, a container, an instance): the per-objective maximum of its programs' resolved profiles, reduced with the base, the program count and the classified count. It is computed on read and nothing is stamped on the asset (ruled by George, 2026-10-20).

**`profile_source`.** `container` for a row owned by a container (its profile is the reduction of its programs). For a program owner: `override` when every objective came from an explicit value, `archetype` when an objective came from an archetype node and none was unclassified, `unclassified` when any objective fell to High for want of a stamp or an archetype.

**The row.** `finding_id`, `vuln_id` (the vulnerability node's entity id), `cve` (its own id, such as the CVE number; null when the node is missing), `component`, `component_id`, `component_type`, `owner_type` and `container_type` (the entity types of the component, owner and container, so a page can link each to its viewer),  `container_id`, `container` (the container in which the owner owns the package; a package node is shared by every host that installs it, so a program-owned row still names its container), `owner_kind`, `owner_id`, `owner`, `scheme`, `profile_source`, `impact_source`, `c`, `i`, `a`, `cr`, `ir`, `ar`, `u`, `s` (decimal strings), `word`, `m`, `multi_agency_source`, `pain`, `pain_rank` (the level as a number 1 to 5, so a chart can plot it), `lev`, `irv`, `column`, `fedramp_class`, `deadline_hours`. Every input of the derivation is in the row, which is the audit trail the memo asks for.

**The affected-agency flag.** A program's `m` is the highest `multi_agency` value its stamps state (`req-stackarmor-vdr-stamp-9`); a program that states none uses the Search input `multi_agency`, default 1, the worst case. A container-owned row takes the highest `m` over the programs involved, each counted at the input default when it states none. `multi_agency_source` is `stamp` when every program involved stated its flag, else `assumed`. A flag from governed hierarchical metadata is Backlog.

**Governed parameters.** The weights, the three thresholds and both EPSS thresholds are Search input defaults, and the catalog is archetype nodes, so each has history and a reviewer can see a change. The memo says they must not be changed after seeing a finding's deadline.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-stackarmor-vdr-search-1 | One Row Per Finding And Owner | Implemented | The Search returns the base's reach rows, one per open finding and owner, each with a score. | Ruled by George, 2026-10-20. |
| req-stackarmor-vdr-search-2 | Derivation In The Row | Implemented | Every row carries every input and intermediate listed under "The row", so a reviewer can redo it by hand. | |
| req-stackarmor-vdr-search-3 | Parameters Are Search Defaults | Implemented | The weights, thresholds, EPSS thresholds and scheme are declared in the runner's input schema with defaults, and no constant in code duplicates one. The catalog is the archetype nodes (`req-stackarmor-vdr-archetypes-2`). | |
| req-stackarmor-vdr-search-4 | Agencies Assumed Visibly | Implemented | `m` is the stamp's `multi_agency` when the program states one, else the input `multi_agency` (default 1), and every row carries `multi_agency_source` (`stamp` or `assumed`). | The worst case when nothing is stated. |
| req-stackarmor-vdr-search-5 | Nothing Is Stored | Implemented | Neither runner writes a node or an edge, and the evaluation's `pain` stays refused. The stamp node is the instance's data, written by whoever stamps. | |
| req-stackarmor-vdr-search-6 | Unclassified Is Not Evidence | Implemented | A Search's description says that a row with `profile_source` `unclassified` or `container`, or with `multi_agency_source` assumed, is the conservative compatibility result and not an evidenced, agency-specific derivation. | The memo forbids describing it as evidenced. |
| req-stackarmor-vdr-search-7 | Runner Keys | Implemented | The runners are registered as `tap_plugin.stackarmor_vdr.searches.pain:stackarmor-pain` and `tap_plugin.stackarmor_vdr.searches.pain:stackarmor-assets`, the keys the instance's Searches name. | |
| req-stackarmor-vdr-search-8 | Dependency Floor | Implemented | `depends_on` and the dependency floor name `fedramp_20x_vdr` at v0.1.2 (the release that ships `reach_rows`, `reduce_profiles`, `exposure_column`, `backed_factors` and `deadline_hours`), `computing_core` at v0.10.2 and `compliance_core` at v0.8.7. | Released pins as of 2026-10-21. |
| req-stackarmor-vdr-search-9 | Stamps Are Read Through The Edge | Implemented | The Search reads a program's profile only from `asset_profile` nodes reached by `PROFILES_PROGRAM` with the Search's `scheme`, and their archetypes only through `USES_ARCHETYPE`, and from no dimension key. | |
| req-stackarmor-vdr-search-11 | One Vulnerability | Implemented | The optional input `vuln_id` limits `stackarmor-pain` to the rows of that vulnerability. | Lets a page show one CVE across different assets. |
| req-stackarmor-vdr-search-10 | Rows Carry Their Scheme | Implemented | Every row of both Searches carries `scheme`, the Search input. | So the result can be compared with another scheme's. |
| req-stackarmor-vdr-search-14 | Parameters Are Validated | Implemented | Weights and thresholds outside the method's domain are refused with a named error before any row is scored: impact weights `0 <= none < low < high <= 1`, requirement weights `0 < low <= medium <= high`, impact high times requirement high at most 1, `0 < u1 < u2 <= D_H`, `0 < theta3 <= 1`, EPSS thresholds in `[0, 1]`. | All-zero impact weights divided 0 by 0, and impact 1 with requirement 3 scored U = -3. A what-if run may pass its own weights inside this domain; the defaults are the governed policy. |
| req-stackarmor-vdr-search-15 | Rows Say They Are Uncapped | Implemented | Every `stackarmor-pain` row carries `uncapped` true while the intended-use ceiling (`req-stackarmor-vdr-ceiling`) is Backlog, including a row whose profile and agency flag are fully stamped. | A stamp supplies the requirements, it does not derive them from the agency's intended use. |

### Summary Counts
----
RID: `req-stackarmor-vdr-summary`

Status: `Implemented`

A chart or a card needs counts, and `stackarmor-pain` returns one row per finding and owner. `stackarmor-summary` is the `module` Search runner that counts those rows, using the same computation (`pain_rows`) so the counts can never differ from the rows.

#### Implementation

Inputs: those of `stackarmor-pain` except `entity_id`, `vuln_id` and `max_results`, plus `view` (`by_pain` default, or `assumptions`). It stores nothing.

| View | Rows |
| --- | --- |
| `by_pain` | Five rows, N1 to N5, each with `pain`, `rows` (the count, 0 when none) and `percent` (of all rows to one decimal, null when there are none). |
| `assumptions` | One row: `rows`, `unclassified`, `container_owned`, `archetype`, `override` (by `profile_source`), `assumed_impact`, `assumed_agency` and `stamped_agency`. |

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-stackarmor-vdr-summary-1 | Counts Match The Rows | Implemented | The `by_pain` counts sum to the number of `stackarmor-pain` rows for the same inputs, and every N-level is listed, with 0 where none. | |
| req-stackarmor-vdr-summary-2 | Assumptions Are Counted | Implemented | The `assumptions` row counts rows by `profile_source`, rows whose `impact_source` is `assumed`, and rows whose `multi_agency_source` is `assumed` and `stamp`, from the same rows. | |
| req-stackarmor-vdr-summary-3 | Registered | Implemented | The runner is registered as `tap_plugin.stackarmor_vdr.searches.pain:stackarmor-summary` and writes nothing. | |
| req-stackarmor-vdr-summary-4 | Bad Input Refused | Implemented | An unknown input or a `view` other than the two is refused with a `ValueError` naming it. | |

### Trace
----
RID: `req-stackarmor-vdr-trace`

Status: `Implemented`

A page that explains the method wants to show the objects the score was computed from, not only the numbers. `stackarmor-trace` returns them as a graph envelope (`nodes` and `edges`, no rows) so a graph panel can draw it.

#### Implementation

Inputs: `entity_id` (required, a finding) and `scheme` (default `stackarmor`). It uses the base's reach to name the owner, the container and the programs, then returns those nodes, the finding's vulnerability and component, each program's `RUNS_PACKAGE` roots, the stamps of the scheme that point at the programs and the archetypes they name, with every live edge among them. It stores nothing. A component's route to a program is drawn only as far as the grid's own edges between these objects go.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-stackarmor-vdr-trace-1 | The Objects Behind The Score | Implemented | The result holds the finding, its vulnerability, the component, the owner and container, the programs, their stamps and the archetypes the stamps name, and the edges among them. | |
| req-stackarmor-vdr-trace-2 | One Scheme | Implemented | Only stamps of the input `scheme` are shown. | |
| req-stackarmor-vdr-trace-3 | No Owner Is Said | Implemented | A finding the grid ties to no owner returns the finding alone and a `no_owner` warning. | |
| req-stackarmor-vdr-trace-4 | Bad Input Refused | Implemented | A missing or non-string `entity_id` and an unknown input are refused with a `ValueError` naming the input. | |
| req-stackarmor-vdr-trace-5 | Registered, Read Only | Implemented | The runner is registered as `tap_plugin.stackarmor_vdr.searches.pain:stackarmor-trace` and writes nothing. | |

### The Prose Panel
----
RID: `req-stackarmor-vdr-panel-prose`

Status: `Implemented`

A page that explains the method wants the explanation set as prose, not as a pre-wrapped block of text. `stackarmor_prose` is a panel type that takes only config: it runs no Search and reads no node, so a page can mount it with nothing but text.

#### Implementation

`tap_plugin/stackarmor_vdr/panels/prose.py` defines `StackarmorProsePanelType` (slug `stackarmor_prose`, view `stackarmor_vdr/panels/prose.html`, css `stackarmor_vdr/css/prose.css`), registered in `apps.py` `ready()` on `tap_web.registry.panel_type_registry`; the manifest has no panel field in v0 (`req-tap-plugin-manifest-v0-nongoals-2`). The module imports no Django: the text is parsed into plain strings and the template renders them with autoescaping, so no markup in the text is ever run. An instance is a `panel` node whose `view` is `stackarmor_vdr/panels/prose.html` and whose `config` is `{"text": ..., "variant": ..., "hide_header": ...}` (`PROSE_PANEL_CONFIG_SCHEMA`: every property described, unknown keys refused, `text` required).

| Variant | Text is read as | Set as |
| --- | --- | --- |
| `plain` (default) | Blank-line-separated blocks, each a paragraph that keeps its lines. | Sans paragraphs on a tinted card. |
| `method` | Blocks as above; the first is the lead. A line `Label: text` (label at most 40 characters) has the label run in as a small head; an unlabelled line holding ` = ` is a formula, and a block of formulas is set in a monospace inset. | A serif, magazine-style card with a lead, a line length of at most 46rem and one accent rule. |
| `steps` | Lines `1. Title: description`, `2) Title: description` or `- Title: description` are the steps (the numbering is counted, not read); text before the first step is an intro and text after the last is a note. With no such line every blank-line-separated block is a step. A step with no `Title:` shows its description alone. | A numbered vertical stepper: badges on a connecting line, a title line and a description. |

Every colour is a theme token (`rgb(var(--tap-...))` from `tap_web/static/tap_web/css/theme.css`), which the theme redefines for dark, so the stylesheet has no literal colour and needs no dark block (`req-web-theme-scope`). The wording is the config's: the panel never edits, reorders or drops text; whitespace, a step's leading number or dash and the colon after a step's title are the only characters it does not show.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-stackarmor-vdr-panel-prose-1 | Registered With A Described Config | Implemented | The panel type is registered under `stackarmor_prose` in `apps.py`, and its config schema describes every property, requires `text` and refuses unknown keys. | |
| req-stackarmor-vdr-panel-prose-2 | Variants Are An Allowlist | Implemented | `variant` accepts `plain`, `method` and `steps`; any other value is refused, and a config with no `variant` renders as `plain`. | |
| req-stackarmor-vdr-panel-prose-3 | Text Is Escaped | Implemented | `<script>` and other markup in the text renders as text in every variant, and the template uses no `safe` filter or `autoescape off`. | |
| req-stackarmor-vdr-panel-prose-4 | The Steps Are Parsed | Implemented | Numbered and dash lines become ordered steps with a title where one is given, a step without a title keeps its whole text, an intro and a note are kept apart from the steps, and a text with no step lines becomes one step per block. | |
| req-stackarmor-vdr-panel-prose-5 | The Method Is Parsed | Implemented | The first block is the lead, a labelled line gives its label and text, and a block of unlabelled ` = ` lines is a formula. | |
| req-stackarmor-vdr-panel-prose-6 | Every Word Survives | Implemented | The words of the text, in order, are the words rendered in every variant, with only a step's leading number or dash and the colon after its title left out. | |
| req-stackarmor-vdr-panel-prose-7 | Theme Tokens Only | Implemented | The stylesheet holds no hex or rgb literal and reads every colour from `--tap-*` tokens. | Both themes were checked by screenshot on 2026-10-22. |
| req-stackarmor-vdr-panel-prose-8 | Bad Config Is Shown, Not Raised | Implemented | An invalid config renders a visible message and raises nothing, so one bad panel does not take the page down. | |

### Finding Walk-Through
----
RID: `req-stackarmor-vdr-finding`

Status: `In Development`

The basic unit of the method is one vulnerability on one component under one owner: vulnerability X in library Y as used by program Z. `stackarmor-pain` already returns exactly that grain, one row for each finding, component and owner (a row's container is part of it). `stackarmor-finding` explains one such row: how each number came from the one before it, so a reader meets the method in the context of a real vulnerability. Ruled by George, 2026-10-26 (the unit is finding, component and owner; container rows are linkable; StackArmor only).

#### Implementation

Inputs: `finding_id`, `component_id` and `owner_id` (all required), `container_id` (optional; it tells apart one owner reached through two containers), the `scheme` and `evaluation_scheme` of `stackarmor-pain`, and the same scoring parameters with the same defaults, taken from the one `INPUT_SCHEMA`. The runner runs the same computation as `stackarmor-pain` (`pain_rows`) for that finding, keeps the one row whose key matches, and builds the walk-through from that row, so every number it shows is the row's own and is never recomputed by a second routine. It adds, from the same reads, what the row does not carry: the programs behind a container owner and which of them set each requirement, the per-dimension products, the thresholds, and the raw vector and observations. It writes nothing and stores nothing.

The result has two kinds of row, told apart by `kind`:

- `breakdown`: one row per field, in order, with `key`, `label`, `value` (the human text), `assumed` (true when the value rests on a default, a missing input or an unclassified owner) and `step` (the number of the step that explains it). The fields are the PAIN level, the word, U, S, the affected-agency flag, the profile and its source, impact (C, I, A), likely exploitable, the exposure column, and the deadline allowance.
- `step`: one row per step, in order, with `step`, `title`, `summary` (the pithy sentence or two), `detail` (the longer text, shown on request), `inputs` and `results` (each a list of `{label, value, assumed}`), and `anchor`. A step's `inputs` repeat the `results` of the steps it reads, so the values carry down the page.

The steps, with what each shows:

| # | Step | Inputs | Results |
| --- | --- | --- | --- |
| 1 | The Finding | the finding, its vulnerability (CVE, title, KEV, EPSS), the component (type, name, version) | the finding on the component |
| 2 | The Owner | the owner, its kind, the container; for a container, the programs behind it | the owner the profile is read from |
| 3 | The Profile | the stamp or archetype, per program for a container, with the origin of each of CR, IR and AR | CR, IR, AR and the profile source |
| 4 | The Impact | the CVSS vector and version | C, I and A and the impact source |
| 5 | The Products | each impact weight and the requirement weight of its dimension | one product per dimension |
| 6 | The Score | the products, D_H | U and S |
| 7 | The Word | U, S, u1, u2, theta3 | Minimal, Narrow, Disruptive or Debilitating, and the bound that decided it |
| 8 | The Agency Flag | the stamps' `multi_agency`, the input default | m and whether it was stamped or assumed |
| 9 | The PAIN Level | the word and m | N1 to N5 |
| 10 | Likely Exploitable | KEV, EPSS, the reachability and its thresholds, the evaluation's backed factors | LEV, reachability and the exposure column |
| 11 | The Deadline | the class, the PAIN level, the column | the allowance in hours |
| 12 | What Is Assumed | every step's assumed values | the list of assumptions, the uncapped note and the local choices |

The `summary` of all twelve steps together holds at most 550 words, which is one printed page: a step's summary is at most two sentences and 45 words. Everything longer is the step's `detail`. The wording is a constant of the plugin, versioned with it, filled with the row's own values; it names no one and quotes nothing it cannot source: each step's detail cites the memo section it follows and the local choice where the plugin departs from the memo (`req-stackarmor-vdr-nongoals`).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-stackarmor-vdr-finding-1 | One Row Is The Subject | Implemented | The runner returns the walk-through of the one `stackarmor-pain` row whose `finding_id`, `component_id`, `owner_id` and, when given, `container_id` match the inputs, for a program owner and for a container owner alike. | The grain of the method. |
| req-stackarmor-vdr-finding-2 | The Same Numbers As The Row | Implemented | Every figure in the breakdown and the steps equals the field of that `stackarmor-pain` row under the same inputs, and the runner holds no second scoring routine. | One computation (`req-stackarmor-vdr-search-2`). |
| req-stackarmor-vdr-finding-3 | Values Carry Down | Implemented | Each step's `inputs` are the `results` of the steps it reads, so no value first appears in a step without having been a result above it or a stated input. | Reads like working an equation. |
| req-stackarmor-vdr-finding-4 | A Container Shows Its Programs | Implemented | For a container owner, step 3 lists the programs behind it with each one's stamp or archetype and names, per requirement, the program whose level was taken. | `profile_source` `container`. |
| req-stackarmor-vdr-finding-5 | Assumed Is Marked | Implemented | A value that rests on an unclassified owner, an assumed impact, an assumed agency flag or an unset exposure factor has `assumed` true in its breakdown row and its step, and step 12 lists each one; a result that assumes nothing says so. | Missing data is not evidence. |
| req-stackarmor-vdr-finding-6 | Every Breakdown Field Has A Step | Implemented | Each breakdown row's `step` names a step that exists, and the two lists are in the order of the steps. | |
| req-stackarmor-vdr-finding-7 | One Page Of Summaries | Implemented | The twelve `summary` texts total at most 550 words and none exceeds two sentences or 45 words. | If it cannot be said on one page it is not understood. |
| req-stackarmor-vdr-finding-8 | Detail On Request | Implemented | Every step carries a `detail` text longer than its `summary`, which cites the memo section followed and names any local choice. | Local choices: `req-stackarmor-vdr-nongoals`. |
| req-stackarmor-vdr-finding-9 | The Row Is Not Found | Implemented | A key that matches no row returns no rows and a `not_found` warning; a missing required input or an unknown one is refused with a `ValueError` naming it. | As `req-stackarmor-vdr-trace-4`. |
| req-stackarmor-vdr-finding-10 | Registered, Read Only | Implemented | The runner is registered as `tap_plugin.stackarmor_vdr.searches.finding:stackarmor-finding`, writes nothing, and takes its parameter defaults from the one `INPUT_SCHEMA`. | |
| req-stackarmor-vdr-finding-11 | Memo Examples Walk Through | In Development | The five worked examples of the memo, run through the runner, give steps whose U, S, word and N-level are the memo's printed values. | The same five as `req-stackarmor-vdr-score`. |

### The Finding Panel
----
RID: `req-stackarmor-vdr-panel-finding`

Status: `In Development`

`stackarmor_finding` draws the result of `stackarmor-finding` for a page: the breakdown a person reads first, and below it the walk-through. Like `stackarmor_prose` it is a panel type of this plugin, so the plugin stays self-contained and a page mounts it with config alone.

#### Implementation

`tap_plugin/stackarmor_vdr/panels/finding.py` defines `StackarmorFindingPanelType` (slug `stackarmor_finding`, view `stackarmor_vdr/panels/finding.html`, css `stackarmor_vdr/css/finding.css`, no JavaScript), registered in `apps.py` `ready()`. Its config holds `part` (`breakdown` or `walkthrough`, required). The panel runs the one Search the panel node is linked to by `USES_SEARCH`, with the page's query parameters (`finding_id`, `component_id`, `owner_id`, `container_id`) passed as inputs, once per render, and writes nothing. A page mounts the panel twice, once for each part, so a layout can place the breakdown above the walk-through.

- **Breakdown:** one line per field, the label at the left and the value at the right, set as plain lines and never as a table. Each value is a link to `#step-<n>`, the step that explains it; an assumed value carries a visible mark and the word, never colour alone.
- **Walk-through:** one band per step. The left column holds the step's number, title and `summary`, then a closed `details` element holding the `detail`. The right column holds the step's `inputs` and then its `results`, each as label and value, the results set apart from the inputs, so that reading down the right column follows the arithmetic from the finding to the deadline.
- The text is the Search's, rendered through Django autoescaping with no `safe` filter; the panel computes nothing.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-stackarmor-vdr-panel-finding-1 | Registered With A Described Config | Implemented | The panel type is registered under `stackarmor_finding`, its config schema describes every property, requires `part`, allows only `breakdown` and `walkthrough`, and refuses unknown keys. | As `req-stackarmor-vdr-panel-prose-1`. |
| req-stackarmor-vdr-panel-finding-2 | One Line To A Field | Implemented | The breakdown renders one line for each `breakdown` row, label and value, in the Search's order, and holds no `table` element. | |
| req-stackarmor-vdr-panel-finding-3 | Values Jump To Their Step | Implemented | Each breakdown value is a link whose target is the element of the step it names, and every such element exists once on the page, in the walk-through part. | Same-document anchors; no script. |
| req-stackarmor-vdr-panel-finding-4 | Two Columns | In Development | Each step renders its description in a left column and its inputs and results in a right column, the steps in order down the page; at a narrow width the right column follows the left. | |
| req-stackarmor-vdr-panel-finding-5 | Detail Is Expandable | Implemented | Each step holds one closed native `details` element carrying the step's `detail`, and the summaries stay visible with every `details` closed. | No script. |
| req-stackarmor-vdr-panel-finding-6 | Assumed Is Marked In Words | Implemented | An assumed value is marked with the word `assumed` beside it in the breakdown and in the step, not by colour alone. | |
| req-stackarmor-vdr-panel-finding-7 | Text Is Escaped | Implemented | Markup in any field renders as text, and the template uses no `safe` filter or `autoescape off`. | |
| req-stackarmor-vdr-panel-finding-8 | The Panel Does No Arithmetic | Implemented | Every figure shown is a field of the Search result, formatted only; the panel and its template compute none. | |
| req-stackarmor-vdr-panel-finding-9 | Not Found And Failure Are Shown | Implemented | A Search that fails or finds no row renders a visible message naming which, and raises nothing. | As `req-stackarmor-vdr-panel-prose-8`. |
| req-stackarmor-vdr-panel-finding-10 | Theme Tokens Only | Implemented | The stylesheet holds no hex or rgb literal and reads every colour from `--tap-*` tokens. | |
| req-stackarmor-vdr-panel-finding-11 | Prints On A Page | In Development | A `@media print` block sets the walk-through on portrait pages without splitting a step. | Checked in a print preview. |

#### Consumer

The plugin ships no page (`req-stackarmor-vdr-nongoals`). An instance builds the page: a route taking `finding_id`, `component_id`, `owner_id` and `container_id`, the two panels, one `USES_SEARCH` edge from each to `stackarmor-finding`, and a `row_url_template` on the StackArmor table that sends every row, program-owned or container-owned, to it. The playground's spec carries that page's requirements.

### The HTML Panel
----
RID: `req-stackarmor-vdr-panel-html`

Status: `Proposed`

A page sometimes wants rich text that no existing panel sets well: a styled explanation, a callout, a small table, a figure with a caption. When the markup comes from the grid, it comes from data somebody wrote or something collected, so it is untrusted however it got there. `stackarmor_html` shows such markup with the look of the plugin and the guarantee that it cannot run script, load anything from elsewhere, send anything anywhere or change how the rest of the page looks. Requested by George, 2026-10-27.

#### Threat Model

The HTML is attacker-influenced: a node field that a collector filled from a scanner or an advisory, a Search row, or a config string that anyone with edit access to the panel can change. What it must not be able to do:

| Threat | Example | Closed by |
| --- | --- | --- |
| Script execution | `<script>`, `onerror=`, `javascript:` URLs, `<svg onload>` | Tags and attributes outside an allowlist are dropped; only `http`, `https` and `mailto` URL schemes pass; no SVG or MathML. |
| Mutation XSS | Markup that is safe to the sanitizer and unsafe once the browser re-parses it | A maintained sanitizer built on a browser-grade HTML5 parser, no SVG, MathML or `template`, and the output checked by a second parser. |
| Loading from elsewhere | `<img src=https://x/pixel>`, CSS `url()`, `<link>`, `<iframe>` | No external resource: `img` may point only at this site; no `style`, `link`, `iframe`, `object`, `embed`, `audio` or `video`. |
| Sending data out | `<form action=https://x>`, `<meta http-equiv=refresh>`, `<a ping>` | No `form`, `input`, `button`, `meta` or `base`; no `ping`. |
| Restyling or covering the page | `style="position:fixed;inset:0"`, a fake sign-in box over the real page | No `style` attribute and no `<style>`; `class` limited to a fixed list the plugin styles; the panel's own CSS contains the content to its box. |
| Name collisions | `<a id=config>`, `name=location` shadowing a script's globals | No `id`, `name` or `form` attribute passes. |
| Tab-napping | `target=_blank` without `rel` | No `target`; every link gets `rel="noopener noreferrer nofollow"`. |
| Resource exhaustion | A very large or deeply nested document | A size limit, an element limit and a depth limit, each refusing the whole document. |
| A bypass that comes back | A sanitizer fix that never reaches stored content | Cleaning is done on every render, never once on write, so a fixed sanitizer fixes what is already stored. |

#### Implementation

`tap_plugin/stackarmor_vdr/htmlsafe.py` holds the cleaning and imports no Django: `clean(html, *, max_bytes, max_elements, max_depth)` returns the cleaned markup and the number of things it removed, or raises `HtmlRefused` for an over-limit document. `tap_plugin/stackarmor_vdr/panels/html_panel.py` defines `StackarmorHtmlPanelType` (slug `stackarmor_html`, view `stackarmor_vdr/panels/html.html`, css `stackarmor_vdr/css/html.css`, no JavaScript), registered in `apps.py` `ready()`.

- **Source.** The config names exactly one of `html` (a string written in the panel's config) or `field` (the row field of the panel's one linked Search that holds the markup, with an optional `row` index, default 0). The Search is run once per render with the page's query parameters, as `stackarmor_finding` does. Both sources are cleaned the same way: where the markup came from earns it no trust.
- **The cleaning.** An allowlist, not a blocklist. Tags: `p`, `br`, `hr`, `h2` to `h4`, `strong`, `em`, `b`, `i`, `u`, `s`, `sub`, `sup`, `code`, `pre`, `kbd`, `blockquote`, `ul`, `ol`, `li`, `dl`, `dt`, `dd`, `table`, `thead`, `tbody`, `tr`, `th`, `td`, `caption`, `figure`, `figcaption`, `a`, `img`, `span`, `div`, `details`, `summary`. Attributes: `href` and `title` on `a`; `src`, `alt`, `width` and `height` on `img`; `colspan`, `rowspan` and `scope` on table cells; `class` on any tag, filtered to the list below; `lang` and `dir`. Everything else is dropped, together with the content of `script`, `style` and similar tags, not only the tags. Comments, processing instructions and doctype are dropped. `img` `src` must be a path on this site (starts with `/` but not `//`); `a` `href` must be a path on this site, `http`, `https` or `mailto`, or a `#fragment`. The class list is the plugin's: `sa-lead`, `sa-muted`, `sa-callout`, `sa-callout-note`, `sa-callout-warning`, `sa-columns`, `sa-badge`, `sa-figure`, `sa-table`, `sa-quote`.
- **The one trusted step.** The cleaned string is marked safe in exactly one place, the panel's context builder, and nowhere else in the plugin; the template prints that one variable and every other variable with Django's autoescaping.
- **Fails closed.** If cleaning raises, the library is missing or the document is over a limit, the panel shows a message saying so and no content; it never falls back to the raw markup or to the markup as text.
- **Styling.** The panel's stylesheet scopes every rule under `.tap-panel--sa-html`, sets the typography for the allowed tags and the ten classes from theme tokens only (no colour literals), contains its content (`overflow` clipped, `contain: content`), and has a print block. It needs no inline style and no script, so it works under a Content Security Policy that forbids `unsafe-inline`.
- **Dependency.** The sanitizer is a library, not code written here: the leading candidate is `nh3` (Python bindings for Rust's `ammonia`, built on the `html5ever` parser), which has no cryptography and no network access. Adding it needs approval, and the comparison with the alternatives recorded in this spec before the build (the dependency rule, `build-collector` Step 1.5): exact distribution name and provenance checked on the index, advisories checked, pinned to a version range, FIPS posture declared.
- **Reading is the Search's.** The panel adds no access of its own; what a viewer can see through it is what the linked Search returns to them.

Not in v0, and why: a sandboxed `iframe` mode (the strongest isolation, but it cannot inherit the theme or link to the page's anchors); Markdown input; `style` through a vetted property list; and any write path. They are Backlog if wanted.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-stackarmor-vdr-panel-html-1 | Registered With A Described Config | Proposed | The panel type is registered under `stackarmor_html`; its config schema describes every property, requires exactly one of `html` and `field`, refuses unknown keys, and bounds `html` to the size limit. | As `req-stackarmor-vdr-panel-prose-1`. |
| req-stackarmor-vdr-panel-html-2 | Allowlist Only | Proposed | Every tag in the output is in the tag allowlist and every attribute is allowed on its tag; the test parses the output with a second, independent parser and walks every element. | A check that does not trust the cleaner it checks. |
| req-stackarmor-vdr-panel-html-3 | Script Cannot Run | Proposed | The published XSS evasion corpus (OWASP filter-evasion vectors), a set of event-handler, `javascript:`, `data:` and `vbscript:` URL vectors, and SVG and MathML vectors, run through the panel, leave no `script` element, no `on*` attribute and no URL with a scheme outside `http`, `https` and `mailto`. | The corpus is a test fixture with its source named. |
| req-stackarmor-vdr-panel-html-4 | Mutation Vectors | Proposed | A set of known mutation-XSS payloads (nested `noscript`, `style` and `select`, namespace confusion, `<math>` and `<svg>` breakouts) is cleaned to the same output when the output is cleaned again. | Idempotence: `clean(clean(x)) == clean(x)`. |
| req-stackarmor-vdr-panel-html-5 | Nothing Is Fetched | Proposed | No output element has a `src` or `href` that points off this site except an `a` `href` to `http`, `https` or `mailto`; there is no `style`, `link`, `iframe`, `object`, `embed`, `form`, `meta` or `base`, and no `ping`. | Beacons and exfiltration. |
| req-stackarmor-vdr-panel-html-6 | Links Are Safe | Proposed | Every `a` in the output has `rel="noopener noreferrer nofollow"` and no `target`. | |
| req-stackarmor-vdr-panel-html-7 | No Names | Proposed | No output element has `id`, `name` or `form`. | DOM clobbering. |
| req-stackarmor-vdr-panel-html-8 | Classes Are The Plugin's | Proposed | Only the ten listed classes survive, and a class outside them is removed without removing its element. | |
| req-stackarmor-vdr-panel-html-9 | Limits Refuse | Proposed | A document over the byte, element or depth limit raises `HtmlRefused` and the panel shows a message and no content. | A depth bomb must not reach the browser or exhaust the parser. |
| req-stackarmor-vdr-panel-html-10 | Cleaned Every Render | Proposed | The panel cleans the markup each time it renders and stores nothing cleaned; a fixture whose cleaner is changed between two renders shows the second cleaner's output. | |
| req-stackarmor-vdr-panel-html-11 | Fails Closed | Proposed | When the cleaner raises, or the library cannot be imported, the panel renders a visible message and no content, and neither the raw markup nor an escaped copy of it appears. | |
| req-stackarmor-vdr-panel-html-12 | One Trusted Step | Proposed | The plugin contains exactly one `mark_safe`, in the panel's context builder, applied to the cleaner's output; the templates use no `safe` filter and no `autoescape off`. | A grep test. |
| req-stackarmor-vdr-panel-html-13 | The Same From Both Sources | Proposed | The same markup given as the `html` config string and as the `field` of a linked Search's row yields identical output. | The source earns no trust. |
| req-stackarmor-vdr-panel-html-14 | Failures Of The Search | Proposed | A Search that fails, or a row or field that is missing or not text, renders a visible message and raises nothing; the error text is logged by class only. | As `req-stackarmor-vdr-panel-finding-9`. |
| req-stackarmor-vdr-panel-html-15 | Needs No Script Or Inline Style | Proposed | The template holds no `script` element and no `style` attribute or element, and the stylesheet is the only style source, so the panel works under a policy that forbids `unsafe-inline`. | |
| req-stackarmor-vdr-panel-html-16 | Theme Tokens Only | Proposed | The stylesheet holds no hex or rgb literal, scopes every rule under `.tap-panel--sa-html`, and has a print block. | As `req-stackarmor-vdr-panel-prose-7`. |
| req-stackarmor-vdr-panel-html-17 | The Dependency Is Recorded | Proposed | The sanitizer library is named in `pyproject`, declared in the FIPS posture, and the comparison with the alternatives, the verified distribution name, its provenance and the advisory check, dated, are recorded in this spec. | Approved before the build. |

### v0 Non-Goals
----
RID: `req-stackarmor-vdr-nongoals`

Status: `Implemented`

This version does not:

- store PAIN, an owner or a profile (`req-stackarmor-vdr-search-5`);
- decide which asset a finding belongs to, or compute reachability: both are the base's;
- implement the memo's intended-use ceiling, mitigation ladder, per-asset agency flag or per-library profile (the Backlog rows), or the memo's cross-system aggregation of CVSS v4.0 subsequent-system impact, which the memo itself does not specify;
- ship pages, or any panel that reads the grid: the Searches are the surface other pages read (its one panel type, `stackarmor_prose`, takes only config, `req-stackarmor-vdr-panel-prose`);
- ship any model or edge beyond the stamp, the archetype and their two edges.

Local choices, named so they are not read as exact conformance to the memo: an evidence-backed `likely_exploitable` false overrides KEV true (`req-stackarmor-vdr-exposure`), where the memo reads KEV or EPSS; the agency flag is stamped on a program or assumed, not derived per finding; and `deadline_hours` is the PVR table allowance for the row's class, PAIN and exposure column, not a due date or an SLA verdict. The method source is the stackArmor memo at `stackArmor/rfc-fedramp-vdr` commit `e3368d72d4354d107d6002cdc881a1d8110d617f`.

The model catalog and edge list above are unchanged by v0.2.0; the stamp gains one field (`multi_agency`).

## Model catalog

| Model | Entity type | Category | Rationale |
| --- | --- | --- | --- |
| Asset Profile | `stackarmor_vdr__asset_profile` | Evaluation input | The method's judgment of what a program requires, kept apart from the program so the system's own nodes are untouched. |
| Archetype | `stackarmor_vdr__archetype` | Reference | A named set of requirements (CR, IR, AR) a stamp can point at, so the catalog is data a provider can read and change. |

## Edge types

| Edge | From → To | Properties | Rationale |
| --- | --- | --- | --- |
| `PROFILES_PROGRAM__stackarmor_vdr` | `asset_profile` → `computing_core__program` | none | The stamp points at the thing it describes; a program only, because the profile is stamped there. |
| `USES_ARCHETYPE__stackarmor_vdr` | `asset_profile` → `archetype` | none | The stamp names the archetype whose requirements it takes. |

## Reference data

The plugin seeds the sixteen archetype nodes of `req-stackarmor-vdr-archetypes-1` and nothing else. Stamps are the instance's.
