# DLP Composer — Universal Rule Composition Engine

> **Status:** Working draft
> **Document structure:** 11 sections, designed as tabs for Google Docs

---

# Tab 1: Executive Summary

## The Problem

DLP policy authoring and maintenance is a nightmare.

Security teams spend more time fighting their DLP tools than fighting data loss. A compliance analyst who understands HIPAA cannot create a DLP rule — they need a DLP engineer to translate their intent into vendor-specific configuration across 5-8 admin screens. That engineer maintains hundreds of rules across multiple channels (email, web, USB, cloud, print), each channel often requiring its own copy of the same rule in a different format. When a false positive is reported — and they're reported constantly, at rates of 15-40% — the fix is manual: edit the rule, repackage, redeploy, hope it doesn't break something else. There are no automated tests. There is no regression suite. There is no version history worth the name.

When the organization decides to switch DLP vendors, the migration takes 6-12 months — not because the detection logic changes, but because every rule must be manually rewritten in the new vendor's proprietary format.

## What We Built

DLP Composer is a **universal rule composition engine** that solves this at the architectural level:

**Separation of concerns.** Detection (what to find) is cleanly separated from Rule (when to act), RuleSet (how to organize), and Policy (where to deploy). A detection is written once and reused across any number of rules, channels, and enforcement modes — without duplication.

**Composable entity system.** Every building block — a regex pattern, a dictionary, a validator, a user group, a sensitivity label, a compliance regulation — is a first-class entity referenced by ID. Never inline a value in a rule; always reference an entity. Change it once, every rule that references it updates across all layers.

**Seven-layer false positive elimination.** Not just regex — validators (Luhn, Mod97, SSN range), ignore expressions, proximity context, negative-weight scoring, breadth control, scope exclusions, and boilerplate stripping. Each layer operates independently. Together they reduce FP rates from industry-typical 15-40% to below 10%, with a path to below 5% as the test corpus matures.

**Testing by construction.** Every rule carries a test corpus — true positive and true negative samples that define what the rule should and should not match. A WASM engine runs tests in the browser during authoring. A Vectorscan engine validates in CI. The gate blocks untested rules from deployment. There is no "skip testing" escape hatch.

**GenAI-powered authoring.** Inline regex validation, match explainability (step-by-step score breakdown), AI-recommended validators and ignore expressions, auto-generated test fixtures. Non-technical compliance analysts author rules directly; DLP engineers review.

**Vendor portability via transpilation.** The canonical rule model transpiles to vendor-specific formats — Trellix, Proofpoint, Symantec, Palo Alto, and others. Write once, deploy to any vendor. Migration becomes re-transpile, not re-author.

**Label integration with DSPM.** Labels from any source — MIP, Macie, GCP DLP, Snowflake tags, data catalogs, user-applied — normalize to a unified SensitivityTier and DataCategory. Rules compose label conditions with content detection, tier comparisons, and category hierarchy matching. DLP Composer consumes labels; DSPM tools own the label lifecycle.

## Conservative Target Outcomes

| Metric | Industry baseline | Conservative target |
|--------|------------------|-------------------|
| Rule authoring time (complex, multi-condition) | 1-3 days | Hours (not minutes — includes test corpus and review) |
| False positive rate per rule | 15-40% | < 10% initially; path to < 5% with 6+ months corpus maturity |
| Vendor migration time (full rule corpus) | 6-12 months | 4-8 weeks (varies by vendor integration complexity) |
| Rules deployed with zero test coverage | > 50% | 0% for new rules (gate enforced); existing rules require backfill |
| Rules authored by non-technical analysts | ~5% | > 50% over time (requires template library and training) |
| Audit preparation time | Weeks (manual) | Hours (auto-generated from entity graph) |

## Who Benefits

**CISO / Security Leadership** — DLP program credibility rises. FP rates drop, analysts trust alerts, the program demonstrates measurable risk reduction instead of being a cost center. Vendor leverage improves when migration is weeks instead of months.

**Compliance Analyst / Privacy Officer** — Author rules directly through visual forms. See the regulation link on every detection. Test immediately in the browser. No DLP engineering expertise required for standard rule types.

**DLP Engineer** — Shift from author to reviewer. FP tuning is surgical (five detection layers + scope exclusions). Automated testing replaces manual email-and-USB testing. Impact analysis shows what a change affects before it's committed.

**Security Architect** — Vendor-neutral rule corpus. Evaluate new vendors by transpiling existing rules and measuring fidelity. Extensible entity system grows with new channels and data types without breaking existing rules.

## Key Risks (details in Tab 9)

Three risks that leadership should be aware of:

1. **Transpilation fidelity is not 100%.** Vendor capability gaps mean some rules require manual post-transpile editing. We provide a fidelity report per transpile (lossless/adapted/degraded/unsupported) so authors know before committing what translates and what doesn't. Conservative estimate: >70% of conditions transpile losslessly.

2. **Vendor integration effort varies widely.** API-first platforms (Proofpoint, Palo Alto) are significantly easier to integrate than closed legacy systems (Trellix ePO, Symantec Enforce). Budget 3-6 months per legacy vendor integration. Recommend targeting modern vendors first.

3. **FP improvement is progressive, not instant.** The test corpus starts small (hand-written fixtures). Production feedback enriches it over 3-6 months. Set expectations: FP rate improves continuously, it doesn't drop to target on day 1.

---

# Tab 2: Challenges

DLP rule management is broken at a structural level. The problems below are ordered by depth — the deepest architectural failures come first because they cause everything that follows.

## 2.1 False positives destroy DLP programs

This is the single biggest reason DLP deployments fail, get scaled back, or get turned off entirely.

A credit card regex flags every 16-digit number — loyalty card IDs, tracking numbers, internal reference codes. An SSN pattern matches ITINs, EINs, test sequences, and 9-digit ZIP+4 codes. A "confidential" keyword rule fires on every email signature that says "This message is confidential."

The tools give you regex and keyword matching. That's it. Everything else is your problem.

**What's missing from every major vendor:**

| FP reduction technique | What it does | Vendor support |
|------------------------|-------------|----------------|
| **Algorithmic validators** (Luhn, Mod97, SSN range) | Mathematically verify that a match is structurally valid — not just pattern-shaped | Trellix has Luhn. Others: manual regex workarounds or nothing. |
| **Ignore/exclusion expressions** | Subtract known false patterns from matches (e.g., `000-XX-XXXX` is never a valid SSN) | Trellix has "Ignored Expressions." Others: write a second rule to except. |
| **Proximity context** | Card number near "expiry" or "CVV" = real. Card number in a product catalog = not. | Trellix/Symantec have proximity. Others: no support or fixed-distance only. |
| **Negative-weight scoring** | "Press release" or "public announcement" in the same document actively suppresses the score | Palo Alto supports negative weights. Others: no concept of score suppression. |
| **Breadth control** | Narrow (strict format only) vs wide (catch variants) — same data type, different confidence | Symantec Data Identifiers have breadth. Others: maintain two separate rules. |
| **Multi-layer scoring** | Per-expression weights + group thresholds + occurrence counts + distinct-vs-all counting | Fragmented: each vendor implements 1-2 of these. None has the full stack. |

The result: organizations run at 15-40% false positive rates. Security teams triage hundreds of false incidents per week. Users learn to ignore DLP warnings. Executives question the ROI. The program shrinks to a handful of "safe" rules that catch obvious cases and miss everything else.

**The compounding effect:** High FP rates make teams afraid to deploy new rules, which means real data loss goes undetected, which means the DLP program can't demonstrate value, which means budget gets cut.

## 2.2 Monolithic rule definitions prevent reuse, testing, and reasoning

Vendor rule definitions are opaque blobs. A single "rule" or "policy" object bundles together:
- What content to detect (regex, keywords, file types)
- Who it applies to (users, groups, realms)
- Where it applies (channels, direction, source, destination)
- What to do when it triggers (block, notify, log)
- How the endpoint agent behaves (scan depth, archive handling, OCR settings)

This monolithic design creates cascading problems:

**No reuse.** The same "detect PCI credit card numbers" logic is copy-pasted into the email rule, the USB rule, the web upload rule, and the cloud sync rule. Four copies. When the regex improves, you update four places — or more likely, you update one and forget the others.

**No independent testing.** You can't test "does this detection find credit cards?" without also configuring users, channels, and enforcement actions. Detection accuracy and deployment scope are tangled — a test failure could be the regex or the scoping, and you can't tell which.

**No separation of change.** Updating who a rule applies to (scope change — low risk) touches the same object as updating what it detects (detection change — high risk). Every change is a full redeployment. There's no way to say "the detection is stable, only the scope changed."

**No composability.** You can't build a detection from reusable parts. If three rules all need Luhn-validated credit card regex, each carries its own copy. If they all need the same dictionary of financial keywords, each embeds it. The entity graph doesn't exist — everything is inline.

**No reasoning about coverage.** With monolithic rules you can't answer: "Which detections cover PCI?" or "Which rules use this dictionary?" or "If I change this pattern, what breaks?" There's no dependency graph to query.

## 2.3 Channel fragmentation — the same rule, rewritten per product

DLP vendors don't sell one product. They sell:
- Endpoint DLP (agent on the laptop — email, USB, clipboard, print, screen capture)
- Network DLP (appliance/proxy — web uploads, FTP, IM)
- Cloud DLP (API — SaaS apps, cloud storage, collaboration platforms)
- Discovery DLP (scanner — file shares, databases, SharePoint, Exchange)

Each product often has **its own rule format, its own management console, and its own enforcement model.** The "same" PCI credit card rule in Symantec Endpoint DLP is a different object, in a different admin UI, with different configuration options, than the "same" rule in Symantec Network DLP.

Organizations with 200 rules across 12 channels maintain 200 x N channel-specific copies — often with subtle drift because they were edited independently. Nobody knows if the email version and the USB version of "PCI Credit Card Block" still detect the same thing.

## 2.4 No production feedback loop — rules never learn

DLP rules are write-once. After deployment:
- Matches happen in production
- Analysts triage them (manually, one by one)
- Most false positives are mentally noted but never fed back to the rule
- The rule stays exactly the same until someone rewrites it months later

There is no mechanism to:
- Record whether a match was TP or FP
- Turn an FP into a permanent test case
- Aggregate FP patterns to identify systemic tuning opportunities
- Detect when a rule's FP rate is drifting upward
- Suggest ignore expressions or validators based on FP clusters

Rules don't improve. The same false positives repeat forever. Analysts develop "alert fatigue" and start ignoring categories of matches entirely. Actual data loss hides in the noise.

## 2.5 Testing is manual, slow, and scales exponentially

Rule testing in DLP today means: create a test document, send a test email, copy a test file to USB, paste test content to a browser form — and manually observe what happens. There is no automated test harness. There is no test corpus. There is no regression suite.

**The scale problem is brutal:**

A single rule assigned to 12 channels x 3 directions x 4 modes = 144 test permutations. Add 5 file types and it's 720. Add 3 user group scoping scenarios and it's 2,160. For one rule.

Multiply by 200 rules. That's 432,000 test scenarios — for the initial deployment. Every rule change re-opens the matrix.

What actually happens:
- Rules are tested on 1-2 channels (usually email) and assumed to work everywhere
- Edge cases (encrypted files, nested archives, OCR-dependent scans) are never tested
- Cross-rule interactions (Rule A and Rule B both fire on the same content with contradictory actions) are never tested
- Regression testing doesn't exist — changing Rule A might break Rule B and nobody notices
- More than 50% of rules ship to production with zero testing

## 2.6 Authoring requires deep vendor expertise

The people who understand the regulations (compliance analysts, legal, privacy officers) cannot author DLP rules. The tools require:
- Knowledge of the vendor's proprietary UI (5-8 screens per rule in Trellix)
- Understanding of vendor-specific terminology ("Classification" vs "Smart Identifier" vs "Data Profile")
- Ability to write and debug regex
- Understanding of hidden interdependencies (this reaction rule only works with that policy group on this channel)
- Familiarity with the vendor's endpoint agent behavior and its configuration knobs

A single PCI credit card rule in Trellix requires configuring a Classification, an Advanced Pattern, a Validator, proximity context, a Reaction Rule, and a Policy — across 5 different admin screens with no unified view of the complete rule.

The result: a bottleneck on 1-2 DLP engineers who translate compliance requirements into vendor config. Compliance analysts describe what they need in email or meetings. The DLP engineer interprets and implements. Translation errors are common. The feedback cycle is days to weeks.

When that DLP engineer leaves, institutional knowledge leaves with them. Tribal knowledge about why rules are configured the way they are — which ignore expressions were added for which false positives, why certain user groups are excluded — is lost.

## 2.7 Vendor lock-in — the hidden migration tax

Every vendor invented its own vocabulary for the same concepts:

| Concept | Trellix | Proofpoint | Symantec | Palo Alto | Forcepoint | Skyhigh |
|---------|---------|------------|----------|-----------|------------|---------|
| Content match | Classification | Smart Identifier | Detection Rule | Data Profile | Content Classifier | Classification |
| Policy rule | Rule | DLP Rule | Policy Rule | DLP Policy Rule | Policy Rule | Policy Rule |
| Rule grouping | Rule Set | Rule Set | Policy Group | Rule Profile | Policy | Policy |
| Regex definition | Advanced Pattern | Custom Pattern | Content Matches | Regex | Regex Classifier | Regex |
| Keyword list | Dictionary | Dictionary | Keyword Match | Keyword List | Dictionary | Keyword |
| User scope | Source/Destination | Directory Group | Policy Target | User Group | Policy Scope | User Group |
| Channel | Vector | Channel | Server/Agent | App / Channel | Channel | Channel |
| Enforcement | Reaction | Action | Response Rule | Action | Action | Action |
| Sensitivity label | Tag | Classification Label | MIP Label | Label | Classification | Tag |

There is no portable DLP rule format. No import/export standard. No interoperability. Migration from one vendor to another means: catalog all existing rules (manually), rewrite them in the new vendor's format (manually), test them all (manually). This takes 6-12 months for a mid-sized deployment — even when the underlying detection logic is identical.

This lock-in also prevents multi-vendor strategies. Organizations that want Proofpoint for email and Palo Alto for cloud maintain two completely separate rule sets with no shared truth.

## 2.8 No versioning, no audit trail, no rollback

Rules change constantly — regulations update, FP patterns emerge, business scope shifts, new channels get added. But most DLP tools have:
- No version history (or a shallow "last modified by" timestamp with no diff)
- No way to compare "what this rule was last quarter" to "what it is now"
- No rollback to a previous version without manual reconstruction
- No approval workflow beyond the admin's own discipline
- No provenance chain from regulation to detection to rule to policy

Compliance audits are painful. Auditors ask: "Show me the change history for your PCI rules." The answer is screenshots, emails, and memory. "Show me that every rule was approved before deployment." The answer is "we have an internal process" backed by nothing machine-readable.

When a bad rule change causes production incidents (blocking legitimate emails, for example), rollback means: log into the admin console, remember what the old configuration was, manually reconfigure, hope you get it right. There's no "revert to v7."

## 2.9 Policy sprawl and rule conflicts

Over time, DLP deployments accumulate rules. Rules get cloned instead of reused. Exceptions get added as new rules rather than modifying existing ones. Nobody deletes deprecated rules because nobody is sure what they do or whether something depends on them.

The result:
- **Duplicate detections** — 5 different rules all detect credit card numbers with slightly different regex, different thresholds, different scoping
- **Conflicting actions** — Rule A says "block this email" while Rule B says "allow with notification." Which wins? Depends on evaluation order, which varies by vendor and is rarely documented.
- **Orphaned rules** — rules still in "enforce" mode for user groups that no longer exist, or channels that have been decommissioned
- **No impact analysis** — "If I disable this rule, what stops being protected?" is unanswerable without reading every rule manually

There is no dependency graph, no coverage map, no conflict detector. The rule set is a list of opaque objects, and the only way to understand it is to read every single one.

## 2.10 Compliance is bolted on, not built in

DLP rules detect sensitive data. Regulations mandate how that data must be handled. But the connection between the two is maintained entirely in human heads and spreadsheets.

There's no machine-readable link between "HIPAA §164.514 requires protection of SSN" and "this SSN detection rule." Regulation references, jurisdiction scoping, data subject types, retention requirements, breach notification timelines — all of this is metadata that should drive rule behavior but instead lives in separate compliance documentation that drifts out of sync with the actual rule configuration.

When a regulation changes (PCI-DSS v3.2 to v4.0), identifying which rules are affected requires manual review of every rule against the regulation delta. When an auditor asks "show me all rules that protect GDPR Article 9 special category data," the answer requires a human to review every rule and determine applicability.

---

# Tab 3: Design Principles & Considerations

## 3.1 Architectural Principles

**Separation of concerns — each layer does one thing.**
Detection defines what to find. Rule defines when to act. RuleSet defines evaluation order. Policy defines where to deploy. No layer leaks into another. This is the single most important design decision — it's what makes reuse, independent testing, and transpilation possible. Every vendor violates this by conflating 2-3 of these layers into one object.

**Composition over monolith — never inline, always reference.**
A rule never contains a regex string. It references a Pattern entity. A detection never embeds a dictionary. It references a Dictionary entity. A rule never lists user emails. It references a UserGroup entity. This means: change a pattern once, every detection that references it updates. Query the dependency graph: "what uses this dictionary?" Delete an entity and the system tells you what breaks. This is not a preference — it's the mechanism that makes the entire system work.

**Vendor neutrality — vendors are deployment targets, not the source of truth.**
The canonical rule model is the source of truth. Trellix, Proofpoint, Symantec, Palo Alto are output formats — like compiling C to x86 or ARM. The rule author never thinks in vendor terms. The transpiler handles the translation. This eliminates lock-in and enables multi-vendor strategies.

**Testability by construction — not as an afterthought.**
Every rule carries a test corpus. The gate blocks untested rules from approval. The WASM engine runs tests in the browser during authoring. The Vectorscan engine validates in CI. Testing is not a phase — it's embedded in the authoring experience and enforced by the pipeline. There is no way to ship an untested rule.

**FP reduction as architecture, not tuning.**
False positive reduction is not "tune the regex until it works." It's seven architectural layers — each operating independently, each at a different level of the system (policy, detection, scope). An author who uses all layers produces rules with FP rates far below what any amount of regex tuning could achieve.

**Consumer of classifications, producer of incidents.**
DLP Composer does not create labels, assign labels, manage label lifecycle, discover data assets, or route incidents. It consumes labels and classifications from DSPM and classification tools. It produces incidents for SIEM and SOAR systems. This boundary is deliberate — label governance is a different problem with different complexity.

## 3.2 Scope Boundaries — What We Own vs What We Consume

| Responsibility | Owner | DLP Composer's role |
|---------------|-------|-------------------|
| Content detection and enforcement logic | **DLP Composer** | Core — we own this end-to-end |
| Rule authoring, testing, approval workflow | **DLP Composer** | Core — we own this end-to-end |
| Transpilation to vendor-native formats | **DLP Composer** | Core — we own this end-to-end |
| Label creation, assignment, lifecycle | DSPM / classification tools | Consumer — we ingest via connectors, never produce |
| Data asset discovery and cataloging | DSPM platform | Consumer — we ingest discovered assets |
| Label audit trail (who labeled what, when) | Label source system | We include label context in DLP incidents |
| Permission management (who can access what) | IAM / data catalog | Consumer — we use permissions for rule scope |
| Incident routing and response | SIEM / SOAR | Producer — we create incidents with full context |
| User and group identity | Identity provider | Consumer — we sync via IdP connector |

## 3.3 Integration Philosophy

DLP Composer sits between two ecosystems: classification systems that tell us what data is sensitive, and enforcement systems that act on our rules.

**Inbound (from classification):** ExternalLabelConnectors and DataCatalogConnectors normalize vendor-specific labels, findings, and classifications into two internal entity types: SensitivityTier and DataCategory. Rules reference these internal entities — never vendor-specific label strings. When an organization changes its DSPM platform (from BigID to Cyera, or from Macie to Wiz), they update the connector configuration. No rules change.

**Outbound (to enforcement):** The transpiler converts the canonical rule model into vendor-native formats. Each vendor has a transpiler module that produces importable configuration (ePO XML for Trellix, API payloads for Proofpoint, etc.). A fidelity report accompanies every transpile run so authors know what translates cleanly and what requires attention.

**The connector model:** Every external system integrates through a connector entity. Connectors handle authentication, polling/streaming, caching, conflict resolution, and normalization. The rule engine never sees vendor-specific data — it only sees normalized internal entities.

## 3.4 Constraints

| Constraint | Requirement | Rationale |
|-----------|-------------|-----------|
| Enforcement latency | < 5ms per match | Inline enforcement (email, web upload) cannot add perceptible delay |
| WASM compatibility | Detection engine runs in browser | Authoring-time testing requires in-browser execution without server round-trips |
| Multi-tenant isolation | Every entity scoped by tenant_id | SaaS deployment model; tenant data must never leak |
| Schema-first | Go structs → JSON Schema → UI forms | Single source of truth for validation; prevents schema drift between backend and frontend |
| Regex engine parity | WASM results must match Vectorscan results | Rules tested in browser must behave identically in production |

## 3.5 Non-Goals

These are explicitly out of scope. Not because they're unimportant, but because they're different problems best solved by purpose-built tools:

- **Not a DSPM platform.** We don't discover data assets, scan cloud storage, or manage data posture. We consume what DSPM tools produce.
- **Not a data classification tool.** We don't assign labels to documents or manage label taxonomy. We consume labels from classification tools.
- **Not a SIEM or SOAR.** We don't correlate incidents, route alerts, or orchestrate response. We produce incidents for SIEM/SOAR consumption.
- **Not an IAM system.** We don't manage user permissions or access policies. We consume identity and permission data for rule scoping.
- **Not a CASB.** We don't proxy traffic or provide inline cloud access control. We produce rules that CASB-like enforcement points consume.

---

# Tab 4: Objectives

## 4.1 Business Objectives

| Objective | What it means | Why it matters |
|-----------|--------------|----------------|
| **ROI** | Reduce rule authoring from days to hours. Reduce FP triage from hours per day to minutes. Fewer false incidents = fewer analyst hours wasted. | DLP programs fail on cost-to-operate. If ongoing maintenance costs exceed perceived risk reduction, budgets get cut. |
| **Operational efficiency** | One rule definition covers all channels. One test corpus validates everything. One approval workflow tracks all changes. | Eliminates the N-channel multiplication problem. 200 rules stay 200 rules, not 200 x 12. |
| **Vendor unlocking** | Write once in canonical format, transpile to any target DLP system. Migration = re-transpile, not re-author. | De-risks vendor selection. Organizations can evaluate, switch, or run multi-vendor without rewriting their rule corpus. |
| **Extensibility** | New channels, new condition types, new validators — add without rewriting existing rules. Entity system is open for extension. | DLP scope grows every year (new SaaS apps, new collaboration tools, new data types). The rule engine must grow without breaking what exists. |

## 4.2 Capability Objectives

Each objective traces to a specific challenge from Tab 2.

| # | Objective | Challenge addressed | How (one line) |
|---|-----------|-------------------|----------------|
| 1 | **Eliminate false positives at the source** | 2.1 — FP rates 15-40% | Seven-layer FP stack: validators, ignore expressions, proximity, negative scoring, breadth, scope exclusions, boilerplate stripping |
| 2 | **One rule definition, all channels** | 2.3 — Channel fragmentation | Detection is channel-agnostic; Rule binds detection to 1-22 channels via `channels[]` |
| 3 | **Composable entity system** | 2.2 — Monolithic definitions | 95+ entity types referenced by ID; never inline, always reference; change once, propagate everywhere |
| 4 | **Automated testing with living corpus** | 2.4, 2.5 — No feedback, manual testing | Test corpus per rule; WASM in-browser testing; Vectorscan CI validation; gate blocks untested rules |
| 5 | **Production feedback loop** | 2.4 — Rules never learn | FP/TP classification feeds back as test cases and suppression patterns; corpus grows from production data |
| 6 | **Accessible authoring** | 2.6 — Vendor expertise bottleneck | GenAI-powered no-code UI; reusable templates; live test-in-browser; compliance analysts author, engineers review |
| 7 | **Generalized approval workflow** | 2.8 — No versioning or audit | Every entity versioned; approval states: draft → pending_review → approved → deprecated; same workflow across all entity types |
| 8 | **Full provenance chain** | 2.8, 2.10 — Audit and compliance gaps | Machine-readable chain: regulation → detection → rule → ruleset → policy; query any direction |
| 9 | **Safe rollout with mode progression** | 2.5 — Untested rules hit production | A/M/E/D modes (Analysis → Monitor → Detect → Enforce); mandatory progression with time-in-mode |
| 10 | **Vendor portability via transpilation** | 2.7 — Lock-in | Canonical model transpiles to vendor formats; fidelity report per transpile; write once, deploy anywhere |
| 11 | **Policy hygiene** | 2.9 — Sprawl and conflicts | Dependency graph enables impact analysis, conflict detection, orphan identification, coverage mapping |

## 4.3 Self-Learning Maturity Model

Rules should improve over time, not decay. The maturity progression from manual tuning to autonomous improvement:

```
Level 0: Static            Rules don't change after deployment. FPs repeat forever.
         (industry status   This is where most DLP programs are today.
          quo)
            |
            v
Level 1: Manual feedback   Analyst marks FP → human edits rule → human adds test case
         (Day 1)            → regression runs. Corpus grows, but slowly.
                            Even at L1, the corpus is permanent and regression-tested.
            |
            v
Level 2: Assisted tuning   System clusters FPs by root cause. "17 FPs this week all
         (ML-assisted)      match pattern X with no nearby context keywords — suggest
                            enabling proximity requirement." Human approves.
                            Fix + test case added automatically.
            |
            v
Level 3: Guided evolution  System detects new data patterns in production.
         (proactive)        "New card number prefix 6XXX appearing — not covered by
                            current regex. Suggest adding UnionPay pattern + 3 new
                            TP fixtures." Human reviews and approves.
            |
            v
Level 4: Autonomous        System proposes rule changes, runs full regression,
         (with guardrails)  shows impact analysis, queues for human approval.
                            Approval is the only manual step.
```

## 4.4 ML-Augmented Workflows (Planned)

| Workflow | What it does | Data it needs (generated by the platform) |
|----------|-------------|------------------------------------------|
| **Pre-deployment quality review** | Reviews rules for missing validators, overly broad regex, no proximity on high-FP data types, conflicting scope, missing test corpus edge cases | Entity graph, test corpus, historical FP rates per condition type |
| **Pattern suggestion** | Given a data category ("Brazilian CPF"), generates regex variants, validators, ignore patterns, proximity keywords, and seed test corpus | Global format database, existing entity library |
| **FP root cause analysis** | Clusters production FPs by rule and root cause. Recommends specific fix per cluster. Shows projected FP reduction. | Production match stream, FP classification labels |
| **Coverage gap analysis** | Identifies data types with no detection, channels with no coverage, regulations with no corresponding rules | Regulation entities, rule corpus, entity graph |
| **Anomaly detection** | Surfaces new data formats, FP rate drift, potential evasion patterns, business process changes | Production match stream, baseline statistics |
| **Documentation generation** | Auto-generates rule documentation, compliance mapping tables, channel coverage reports, change summaries | Entity graph, version history, regulation mappings |

## 4.5 Platform Opportunity

The combination of canonical model + composable entities + test corpus + transpiler creates something larger than a tool:

**Shareable detection library.** A "PCI Credit Card" detection with TP/TN fixtures, Luhn validation, proximity context, and ignore expressions for known FP patterns — this is valuable to every organization running DLP. It can be packaged, versioned, and distributed as a reusable entity bundle.

**Regulation starter packs.** "HIPAA Compliance Pack: 15 detections, 25 rules, 200 test fixtures, covering all 18 PHI identifiers across 12 channels." An organization adopts the pack, customizes scope (their user groups, their channels), and deploys. Time to initial compliance coverage drops dramatically.

**Cross-tenant intelligence (anonymized).** Which validators are most effective for which data types? Which proximity keywords produce the highest TP rates for financial data? What FP patterns are universal across organizations? Anonymized, aggregated data from the platform improves everyone's rules.

**Community-contributed test corpus.** The hardest part of DLP testing is creating realistic test fixtures. A shared corpus of TP/TN samples per data type — maintained by the community, validated by regression — is a moat that grows with adoption.

---

# Tab 5: Metrics

## 5.1 False Positive Reduction

| Metric | Baseline (industry) | Conservative target | Measurement method |
|--------|---------------------|--------------------|--------------------|
| FP rate per rule (FP / total matches) | 15-40% | < 10% (path to < 5% with corpus maturity) | Production match classification (TP/FP) per rule |
| FP rate — rules with validators | No baseline | < 5% | Subset: rules using Luhn, Mod97, SSN range, etc. |
| FP rate — rules with proximity | No baseline | < 5% | Subset: rules with proximity conditions enabled |
| FP rate — rules with ignore expressions | No baseline | < 7% | Subset: rules with active ignore/exclusion patterns |
| Time from FP report to rule fix deployed | 2-8 hours | < 30 minutes | Timestamp: FP report → updated rule version live |
| Mean time to FP resolution (ticket lifecycle) | Days to weeks | < 1 business day | Ticket open → rule updated + redeployed + regression passed |
| FP-driven rule corpus decay | Common (analysts disable noisy rules) | 0 rules disabled due to FPs | Count of rules moved to disabled state with FP as reason |

## 5.2 Authoring Efficiency

| Metric | Baseline | Conservative target | Measurement method |
|--------|----------|--------------------|--------------------|
| Time to author a simple rule | 2-4 hours | < 1 hour | Stopwatch: requirement statement to "approved" state |
| Time to author a complex rule (multi-condition, multi-channel) | 1-3 days | < 4 hours | Stopwatch: includes test corpus creation and review |
| Rules authored per analyst per week | 2-5 | 10-15 | Count of rules reaching "approved" state per analyst per week |
| % of rules authored by non-technical analysts | ~5% | > 50% (with template library maturity) | Role tag on created_by field |
| Detection reuse rate | ~0% (copy-paste) | > 40% | Detections referenced by 2+ rules / total detections |
| Entity reuse rate (patterns, dictionaries, validators) | ~0% | > 40% | Entities referenced by 2+ detections / total entities |
| Onboarding time for new rule author | Weeks (vendor training) | < 3 days | Time from account creation to first rule reaching "approved" |

## 5.3 Testing Effectiveness

| Metric | Baseline | Conservative target | Measurement method |
|--------|----------|--------------------|--------------------|
| Rules with zero test coverage (new rules) | > 50% | 0% (gate enforced) | Rules in "approved" state without test corpus = gate failure |
| Test corpus size per rule | 0-3 ad-hoc samples | 8+ TP, 6+ TN minimum | Fixture count per rule in test corpus directory |
| Channel coverage per rule | 1-2 channels tested manually | 100% of declared channels | Automated: channels exercised in test suite vs channels in rule |
| Full regression suite duration | Hours-days (manual) or never | < 10 minutes (automated) | CI pipeline wall-clock time for full corpus |
| Cross-rule conflict detection | Not done | Every commit | Automated: overlapping scope + contradictory actions flagged |
| Test cases sourced from production FPs | 0 | Grows continuously | Count of TN fixtures with `source: production_fp` tag |
| WASM vs Vectorscan parity | Not applicable | 100% match | CI check: WASM results == Vectorscan results for full corpus |

## 5.4 Vendor Portability

| Metric | Baseline | Conservative target | Measurement method |
|--------|----------|--------------------|--------------------|
| Vendor migration time (full rule corpus) | 6-12 months | 4-8 weeks (varies by vendor) | Calendar days: decision to transpiled + validated on target |
| Transpilation fidelity (% lossless) | N/A | > 70% of conditions | Fidelity report: lossless / total conditions per transpile |
| Rules needing manual post-transpile editing | 100% | < 25% | Rules with fidelity warnings requiring human review |
| Supported target vendors | 1 (whatever you bought) | 4+ within 18 months | Count of implemented VendorTranspiler interfaces |
| Bi-directional sync accuracy (import + export) | N/A | > 80% round-trip fidelity | Import vendor config → export → diff against original |

## 5.5 Compliance and Audit Readiness

| Metric | Baseline | Conservative target | Measurement method |
|--------|----------|--------------------|--------------------|
| Audit preparation time | Weeks (manual) | < 1 day (auto-generated) | Time to produce: regulation coverage matrix, change history, approval records |
| Rules with complete provenance chain | < 10% | 100% (for new rules) | Automated: rules missing any link in regulation → detection → rule → policy chain |
| Change traceability | Screenshots + emails | 100% machine-readable | Every entity version: author, timestamp, justification, diff, approval |
| Regulation-to-rule coverage | Unknown (manual mapping) | 100% queryable | "Show me all rules covering PCI-DSS Req 3.4" returns immediately |
| Orphan detection | Not tracked | 0 orphans | Rules without regulation_ref flagged for review |
| Time to assess regulation change impact | Days-weeks | < 4 hours | Regulation entity updated → dependent detections/rules listed |

## 5.6 Risk Reduction and Operational Safety

| Metric | Baseline | Conservative target | Measurement method |
|--------|----------|--------------------|--------------------|
| Production incidents from untested rules | Common | 0 (for new rules) | Incidents traced to rules that bypassed test gate |
| Rules using A/M progression before Enforce | < 10% | > 70% | Rules with mode transition history showing A or M before E |
| Mean time in Monitor before Enforce | 0 (straight to enforce) | > 2 weeks | Mode transition timestamps on rule version history |
| Rollback time | Hours (manual) | < 5 minutes | Version revert: select previous version → deploy |
| Blast radius visibility | None | Always available | Impact analysis shown before approval |
| Duplicate/conflicting rule detection | Not done | Every commit | Automated: detections with >80% overlap flagged |

## 5.7 Self-Learning and Corpus Evolution

| Metric | Baseline | Conservative target | Measurement method |
|--------|----------|--------------------|--------------------|
| Test corpus growth rate | 0 (static) | Positive monthly | Count of new TP/TN fixtures added per month |
| % of corpus sourced from production data | 0% | > 20% after 6 months | Fixtures tagged `source: production_fp` or `source: production_tp` |
| Suggested rule improvements accepted (ML-assisted) | N/A | > 40% acceptance rate | ML suggestions accepted / total suggestions |
| Mean time from pattern emergence to detection | Weeks-months | < 2 weeks (anomaly-flagged) | Time from first occurrence of new format to rule updated |
| FP rate trend over time (per rule) | Flat or unknown | Decreasing | Monthly FP rate per rule, tracked over rule lifetime |

---

# Tab 6: Proposal — The Technical Solution

## 6.1 The Canonical Model — Detection → Rule → RuleSet → Policy

*[See Diagram 1: The Canonical Hierarchy]*

DLP Composer defines a vendor-neutral rule hierarchy where each layer has exactly one job:

```
Detection      WHAT to find in content (pure content logic — no actions, no scoping)
     |
Rule           WHEN to act (detection + scope + mode + severity)
     |
RuleSet        HOW to organize (ordered group of rules, evaluation strategy)
     |
Policy         WHERE to deploy (deployment package — realms, agent config)
```

**Detection** is pure content logic. It defines what patterns, dictionaries, file types, labels, or ML classifiers to look for. It carries no information about users, channels, or actions. This means a detection can be tested in complete isolation — "does this regex with this validator find credit card numbers?" — without configuring anything else. A single detection can power an Enforce rule on email, a Monitor rule on USB, and an Analysis rule on cloud sync — all without duplication.

**Rule** binds a detection to operational context: who it applies to (users, groups), where (channels, direction), from/to (senders, recipients, destinations), what operations (copy, upload, paste), when (schedule), and what happens when it triggers (mode + action). Same detection, different rules = different behavior. A scope change (add a user group) is a low-risk edit to the Rule entity. It never touches the Detection entity (high-risk, affects match accuracy).

**RuleSet** is an ordered list of rules with an evaluation strategy: first-match (stop at first triggering rule) or all-matches (evaluate all, most severe wins). No logic lives here — just ordering and compliance purpose metadata.

**Policy** is a deployment artifact. It assigns rulesets to realms/agents and carries policy-wide exceptions (privileged users exempt from all rules, boilerplate text stripping). No detection logic, no scoping — pure assignment to infrastructure.

**Why this separation matters for the rest of the proposal:** Every capability that follows — entity composition, FP reduction, label integration, testing, transpilation — depends on this clean layering. If detection and scope were tangled (as they are in every vendor), you couldn't test detection independently, reuse it across channels, or transpile it to different vendor formats.

## 6.2 The Entity System — Why Entities, Not Values

*[See Diagram 4 (entity composition) in second-pass diagrams]*

The core design philosophy: **never reference a value directly in a rule — always reference an entity.**

A rule doesn't say `validator: "luhn"`. It says `validator_ref: { entity_id: "val_luhn", entity_type: "validator" }`. A detection doesn't embed a regex string. It references a Pattern entity by ID. A rule doesn't list user email addresses. It references a UserGroup entity.

Every entity in the system — a regex pattern, a dictionary, a validator, a user group, a file type, a network range, a cloud service, a sensitivity tier, a compliance regulation — is a first-class managed object with:

```go
type EntityMeta struct {
    ID          string     // globally unique, immutable
    Name        string     // unique within tenant + entity_type
    TenantID    string     // multi-tenant isolation
    Tags        []string   // free-form organizational tags
    Enabled     bool       // soft-disable without deletion
    Version     string     // monotonic version for change detection
}
```

Entities reference each other through `EntityRef{EntityID, EntityType}`. This is the composition primitive — the mechanism that makes everything else work.

**Why this matters — five concrete benefits:**

**1. Change once, propagate everywhere.** When the US Social Security Administration changes its numbering rules (as it did in 2011 with randomization), you update the `val_ssn_range` validator entity once. Every detection that references it — SSN detection, HIPAA PHI detection, W-2 form detection, bulk PII scanner — picks up the change automatically. In vendor tools, you update each rule separately, or more likely, you update one and forget the others. With 200 rules, "forgot to update" is not negligence — it's inevitability.

**2. Dependency graph is always queryable.** The entity system creates a complete graph. Every detection knows its patterns, dictionaries, and validators. Every rule knows its detections. Every entity knows its consumers. This enables:
- "What rules use dict_financial_keywords?" — answered before you edit it
- "If I delete pat_ssn_dashed, what breaks?" — answered before you delete it
- "What detections cover PCI?" — answered for the auditor

**3. Reuse is structural, not copy-paste.** 15 detections can share the same Luhn validator entity, the same PCI regulation reference, the same financial keywords dictionary. When the dictionary adds a new keyword, all 15 detections benefit. In vendor tools, each rule embeds its own copy. 15 copies means 15 places to update — and 15 opportunities to introduce drift.

**4. Versioning is per-entity, per-concern.** The detection version history shows detection changes (regex updated, validator added). The rule version history shows scope changes (user group added, channel removed). These are separate entities with separate version histories. In vendor tools, a scope change and a detection change are the same "rule was modified" event — you can't tell what changed or why.

**5. Transpilation resolves refs, not values.** The same `dict_pci_keywords` entity ref becomes a Trellix Dictionary ID when transpiling to Trellix, or a Palo Alto Keyword List ID when transpiling to Palo Alto. Entity resolution is the transpiler's job. The rule author never thinks about vendor-specific object types.

**Concrete example — SSN detection composition:**

```
Pattern: "pat_ssn_dashed"                    ──> reused by 3 detections
  expression: \b\d{3}-\d{2}-\d{4}\b
  weight: 5

Validator: "val_ssn_range"                   ──> reused by 4 detections
  algorithm: ssn_range
  (validates 001-899, excludes 000, 666, 900-999)

Dictionary: "dict_pii_context"               ──> reused by 6 detections
  keywords: [SSN, social security, tax ID, SSA, taxpayer, W-2, I-9, ...]

Regulation: "reg_hipaa"                      ──> reused by 12 detections
  name: HIPAA
  section: §164.514

Detection: "det_pii_ssn_strict"
  Group 1 (logic: OR):
    Condition: pattern_ref → pat_ssn_dashed + validator_ref → val_ssn_range
    Condition: pattern_ref → pat_ssn_nodash + validator_ref → val_ssn_range
  Group 2 (logic: AND):
    Condition: proximity → context_dictionary_ref → dict_pii_context
  regulation_refs → [reg_hipaa, reg_ccpa, reg_glba]
```

Six independently versioned, reusable entities compose into one detection. Each entity is shared across multiple detections. Each can be updated independently without touching the others.

**Entity domains — 95+ entities across 17 domains:**

| Domain | Count | Key entities |
|--------|-------|-------------|
| Identity | 3 | User, UserGroup, Realm |
| Communication | 4 | EmailAddress, EmailAddressList, DomainName, EmailDomainList |
| Network | 9 | IPAddress, IPRange, CIDRBlock, Subnet, Hostname, NetworkAddressList, Port, GeoLocation, NetworkSharePath |
| URL | 4 | DomainList, URL, URLList, URLCategory |
| Application | 3 | Application, CloudService, BrowserProfile |
| Device | 3 | DeviceType, PrinterDefinition, DeviceWhitelistEntry |
| Content Detection | 9 | Pattern, Dictionary, ProximityRule, DataIdentifier, Validator, EDMDataset, IDMProfile, MLClassifier, ClassificationLabel |
| File | 7 | FileTypeGroup, FileTypeEntry, FileExtensionList, FilePropertyMatcher, FileSizeRange, FileNamePattern, ContentType |
| Channel/Operation | 6 | ChannelDefinition, ProtocolDefinition, HTTPMethodList, FileOperation, EmailOperation, CloudOperation |
| Scan Config | 4 | ScanConfig, EncryptionHandling, IgnoredTextList, ContentExtractionConfig |
| Endpoint Config | 18 | Agent, Email, Web, Removable, CloudSync, ITM, Clipboard, Print, ScreenCapture, Share, Discover, Comms, ContentProcessing, TamperProtection, Notification, Group, SyncClient, BrowserExtension |
| Scan Targets | 5 | FileSystemPath, DiscoveryScanTarget, SharePoint, Database, ExchangeMailbox |
| Policy Advanced | 5 | CumulativePolicy, RiskAdaptiveMapping, SeverityDefinition, ComplianceRegulation, PolicyTemplate |
| DSPM / Governance | 6 | DataAsset, DataCategory, SensitivityTier, DataCatalogConnector, RetentionPolicy, GeoFence |
| Label Connectors | 3 | ExternalLabelConnector, ClassificationLabel, IdentityProviderConnector |
| Cloud / SaaS | 4 | CloudAppRegistry, DomainTrustList, SIEMConnector, ThreatIntelFeed |
| AI / Advanced | 2 | SuppressionRule, AIGovernancePolicy |

## 6.3 The Detection Grammar — Conditions, Groups, and Scoring

A Detection is built from **groups of conditions** with boolean logic:

```
Detection
  |-- InterGroupLogic: AND | OR
  |
  |-- Group 1 (logic: AND — all conditions must match)
  |     |-- Condition: pattern (regex + validator + scoring)
  |     |-- Condition: proximity (context keywords within N chars)
  |
  |-- Group 2 (logic: OR — any condition triggers)
  |     |-- Condition: dictionary (weighted keyword match)
  |     |-- Condition: file_type (magic bytes)
  |
  |-- ScoreThreshold: 25 (aggregate score across all groups to trigger)
  |-- OccurrenceCount: 3 (minimum total matches required)
```

### 12 Condition Types

| Type | What it matches | Key fields | Vendor universality |
|------|----------------|------------|-------------------|
| `pattern` | Regex with validation | expressions[], ignore_expressions[], validator, score, required, breadth, look_in[], case_sensitive | Universal — all 6 vendors |
| `dictionary` | Weighted keyword lists | dictionary_ref, score_threshold, min_match_count, look_in[] | Universal |
| `proximity` | Spatial context near a match | primary_ref, context_keywords[], distance_chars, context_required, score_boost | Trellix/Symantec native; others vary |
| `file_type` | True file type (magic bytes) | file_type_group_refs[] | Universal |
| `file_extension` | File extension | file_extension_ref, inline_extensions[] | Universal |
| `file_property` | Document metadata | property_name, operator, value | Trellix, Symantec, Forcepoint; Palo Alto limited |
| `file_size` | Size range | min_size_kb, max_size_mb | Universal |
| `file_name` | Name/wildcard/regex | pattern, match_type | Universal |
| `edm` | Exact Data Match | dataset_ref, match_threshold, required_columns[] | All enterprise vendors; implementations differ |
| `idm` | Indexed Document Match | profile_ref, match_threshold, match_mode | Symantec (IDM), Trellix (Registered Docs) |
| `ml_classifier` | ML-based classification | classifier_ref, confidence_threshold | Symantec (VML), Palo Alto (ML) |
| `classification_label` | Sensitivity labels | label_ref/sensitivity_tier_ref/category_ref, operator, source filtering | All support MIP; depth varies |

### Unified Scoring Model

Our scoring model unifies three vendor approaches that are normally incompatible:

| Vendor approach | How they do it | Our equivalent |
|----------------|---------------|----------------|
| **Trellix:** Required/Optional + Score threshold | Condition is required (must match) or optional (contributes score). Threshold at classification level. | `required: true/false` + `score_threshold` on Detection |
| **Palo Alto:** Per-expression weights (including negative) | Each regex has a weight. Negative weights suppress. Aggregate score vs threshold. | `expressions[].weight` (positive or negative) + `score_threshold` |
| **Symantec:** Breadth + occurrence count + distinct counting | Narrow/medium/wide. Count unique values vs all occurrences. Minimum matches. | `breadth` + `count_mode` + `min_matches` + `occurrence_count` |

All three coexist on the same condition. The transpiler maps to whichever model the target vendor uses — Trellix gets Required/Optional, Palo Alto gets weighted expressions, Symantec gets breadth + counting. The canonical form captures all of them.

## 6.4 FP Elimination — The Seven-Layer Stack

*[See Diagram 3: Seven-Layer FP Elimination Stack]*

False positives are not a tuning problem. They're an architecture problem. DLP Composer provides seven layers of FP reduction operating at three architectural levels — content, scope, and policy. Each layer is independent. Each is additive.

### The layers, with a concrete walkthrough

The input email contains:
```
From: orders@logistics-corp.com
Body: "Order ref: 4532015112830366 — see tracking page for delivery status."
Footer: "This email and any files transmitted with it are confidential..."
```

**Layer 7 (Policy level): Boilerplate stripping.** The policy's IgnoredTextList strips the "This email is confidential..." disclaimer before any detection runs. Without this, the word "confidential" in the boilerplate triggers keyword rules on every single email. This layer eliminates universal noise across all detections.

**Layer 1 (Detection level): Pattern match.** Regex fires on `4532015112830366`. 16 digits starting with 4 — looks like a Visa card. Score: +10.

**Layer 2 (Detection level): Validator.** Luhn algorithm checks the number. In this case it passes (some order references accidentally pass Luhn). But for 30-60% of typical FPs, the number fails Luhn and is discarded here. Layer 2 alone is the single biggest FP reducer for numeric data types.

**Layer 3 (Detection level): Ignore expressions.** The pattern `"order ref: + digits"` matches a known FP suppression expression. The match is subtracted. Score drops to 0. **Detection stops here — no alert.**

**Layer 4 (Detection level): Proximity context.** If Layer 3 hadn't caught it: are any financial context keywords ("expiry," "CVV," "card") within 300 characters? The surrounding text says "tracking page for delivery" — no financial keywords. With `context_required: true`, the match is discarded.

**Layer 5 (Detection level): Negative scoring.** If Layers 3-4 hadn't caught it: "tracking" (-8) and "delivery" (-8) = -16. Combined with the pattern match (+10), aggregate score is -6. Below the threshold.

**Layer 6 (Scope level): Rule scope exclusions.** If Layers 3-5 hadn't caught it: the sender `orders@logistics-corp.com` matches the `el_finance_automated` exclusion list on the Rule. The match is real, but the source is a known automated logistics system. Action suppressed.

### Suppression lifecycle

Every suppression starts as a production false positive. The routing principle: **suppression scope must match problem scope.**

| FP root cause | Correct layer | Example |
|---------------|---------------|---------|
| Pattern matches non-sensitive data | Layer 3 (ignore expression) | Order refs matching credit card regex |
| Number fails mathematical check | Layer 2 (validator) | 16-digit number failing Luhn |
| Match is real but no context | Layer 4 (proximity) | Card number in product SKU catalog |
| Counter-indicators present | Layer 5 (negative scoring) | Card numbers in published compliance report |
| User/destination is legitimate | Layer 6 (scope exclusion) | Payment team sending cards to Stripe |
| Boilerplate triggers keyword rules | Layer 7 (IgnoredTextList) | "This email is confidential" in signatures |

## 6.5 Labels and DSPM Integration

*[See Diagram 4: Label Flow Architecture]*

DLP Composer consumes labels from four sources, normalizes them to a unified internal model, and makes them available as powerful conditions in rule composition.

### Where labels come from

**Source 1: Document-embedded labels** — MIP/AIP metadata in Office docs, Google Workspace labels, Titus/Boldon James markings, S3 object tags, email X-headers. Travel with the document. Highest trust, zero latency.

**Source 2: Cloud platform findings** — AWS Macie, GCP DLP, Azure Purview Data Map, SQL Server classifications, Snowflake tags, Databricks Unity tags. Ingested via ExternalLabelConnector. Cached locally with configurable TTL.

**Source 3: Data catalog classifications** — AWS Glue, Snowflake, Databricks Unity, Azure Purview, Google Data Catalog, Collibra, Alation, Atlan, Apache Atlas, OpenMetadata, or custom (S3/SQL/API). Ingested via DataCatalogConnector. Syncs classifications, permissions, schema, lineage, and ownership.

**Source 4: User-applied labels** — Manual classification, classify-on-save prompts, default labels. Variable trust — some organizations trust user labels fully, others verify with content detection.

### Label normalization

All sources normalize to two internal entity types:

**SensitivityTier** — the organization's sensitivity framework with numeric level (for comparison operators), cross-framework equivalence (ISO 27001, FIPS 199, PSPF Australia, NATO, CUI), and handling guidance.

**DataCategory** — hierarchical data classification taxonomy (PII > PII_Direct > SSN). Carries regulation refs, jurisdiction, and GDPR special category flag.

Conflict resolution when multiple sources disagree: `highest_sensitivity_wins`, `most_recent_wins`, or `connector_priority`. Unmapped vendor labels are flagged for admin review.

### The expanded LabelCondition

The LabelCondition supports three matching dimensions:

| Dimension | Matches by | Operator | Use case |
|-----------|-----------|----------|----------|
| **Specific label** | Vendor label ref (MIP GUID, Titus field) | equals, contains, exists, not_exists + match_children (hierarchy) | "Document carries this specific MIP label" |
| **Sensitivity tier** | Organizational tier level (numeric) | equals, gte, lte, gt, lt | "Any document at or above Confidential" |
| **Data category** | Category in hierarchy | equals + category_match_children | "Any PII — SSN, credit card, DOB, any sub-type" |

**Source filtering** across all dimensions: `label_sources: ["mip", "aws_macie"]` — "only trust automated classification, ignore user-applied labels."

Compound label matching uses existing group AND/OR logic — no special entity needed:
```yaml
# "Labeled Confidential+ AND categorized as PII AND from automated source"
group:
  logic: AND
  conditions:
    - condition_type: "classification_label"
      label_config:
        sensitivity_tier_ref: { entity_id: "tier_confidential" }
        tier_operator: "gte"
    - condition_type: "classification_label"
      label_config:
        category_ref: { entity_id: "cat_pii" }
        category_match_children: true
        label_sources: ["mip", "aws_macie", "gcp_dlp"]
```

### Labels at rule scope

Beyond detection conditions, labels serve as scope filters on Rules:

```go
type Rule struct {
    // ... existing scope fields ...
    IncludeLabels  []LabelCondition  // rule only applies to documents matching these
    ExcludeLabels  []LabelCondition  // rule skips documents matching these
}
```

Use case: "Only run the expensive PCI regex detection against Confidential+ documents. Don't scan Public documents." Label scope pre-filters before detection runs — saving processing and reducing noise.

### The DSPM producer-consumer model

DLP Composer consumes labels. It does not create them, assign them, propagate them, manage their lifecycle, or audit their changes. That's DSPM's responsibility. The boundary is clean:

- DSPM discovers data, classifies it, assigns labels, manages label lifecycle
- DLP Composer ingests labels via connectors, normalizes to internal entities, uses them in rules
- Changing DSPM vendor = update connector configuration, not rules

### Composition examples

**Tiered enforcement:** Same detection, three rules at different sensitivity levels. Enforce on Restricted+, Detect on Confidential, Monitor on Internal and below. Tier comparison (`gte`) means new tiers auto-apply.

**Cross-system detection:** Label (from DSPM) + content (from DLP) + permission (from catalog) in one detection group. "User downloading Restricted Snowflake data containing SSNs, without full_access catalog permission."

**Trust differentiation:** Same data category (PII), different enforcement by label source. Automated Macie classification → immediate encrypt. User-applied label → monitor and verify with content detection.

**Gap detection:** DLP finds sensitive content with no label → prompt user to classify → DSPM completes the loop. DLP and DSPM each do what they're best at.

## 6.6 GenAI-Powered Authoring Experience

Testing is not a phase that happens after authoring. Testing IS authoring. The composition surface is a continuous feedback loop where the author writes, the engine evaluates, and GenAI assists — all in real-time.

### Step 1: Pattern authoring with inline validation

The author types or selects a regex. The system responds immediately: syntax validation, engine compatibility (WASM and Vectorscan), estimated match rate, and live preview against the test corpus. Problem patterns are flagged with specific, actionable recommendations ("Estimated match rate: HIGH — add validator to reduce false positives").

### Step 2: Match explainability

Every match and non-match is explainable. The author clicks a result and sees the full score breakdown: which layer matched, what the score was at each step, why it was classified as TP or FP. The AI interprets the result and suggests concrete fixes ("This match is likely a false positive — no SSN context keywords nearby. Suggest enabling proximity requirement.").

### Step 3: Proactive AI recommendations

As the detection takes shape, the AI suggests improvements: missing validators, incomplete ignore expressions, proximity keywords for this data type, test corpus gaps. A real-time quality score (e.g., 6/10) updates as conditions are added. "After applying all recommendations: estimated 9/10."

### Step 4: Test corpus generation

When the author accepts AI recommendations, the system generates test fixtures — TP samples covering format variants and edge cases, TN samples covering common FP patterns for this data type. The author reviews, accepts, or modifies.

### Step 5: Continuous validation

Every condition change re-runs the full corpus. Live results update in the authoring surface. All TPs still match? All TNs excluded? Quality score updated. The author never leaves the composition surface to test.

**Three pillars:**
- **GenAI-assisted authoring** — AI recommends improvements as conditions are built
- **Testing at every step** — every keystroke re-evaluates the corpus with full explainability
- **FP reduction by construction** — the seven-layer stack + AI recommendations + test gating make it structurally difficult to ship a high-FP rule

## 6.7 Testing Framework

### Test corpus per rule

Every rule carries a test corpus — true positive (TP) and true negative (TN) samples. Minimum: 8 TP + 6 TN per rule. The TP set covers format variants, file types, and edge cases. The TN set covers common FP patterns. A production FP section grows continuously from real-world feedback.

The gate blocks rules without a corpus from reaching "approved." The corpus is not documentation — it's executable specification.

### Dual-engine testing

**WASM engine (browser, authoring time):** Go stdlib regexp compiled to WASM. Runs in-browser, < 50ms per corpus run. Instant feedback on every keystroke. Shows match/no-match per sample, highlights matched regions, shows score breakdown.

**Vectorscan engine (CI, deploy time):** Production-grade DFA engine. Full corpus, all file types, archive extraction, OCR. Checks WASM parity (any divergence = bug). Performance validation: must complete in < 5ms per match.

### Production feedback loop

Production matches are classified by analysts as TP or FP. Every FP is classified by root cause (pattern too broad, missing validator, no context, known safe source, threshold too low). The appropriate fix is applied (ignore expression, validator, proximity, scope exclusion). The FP sample becomes a permanent TN fixture in the test corpus. Regression re-runs confirm all existing TPs still pass.

**The compounding effect:** Every FP makes the rule permanently stronger. After 6 months, a rule's TN corpus contains dozens of real-world FP patterns. The FP rate trends monotonically downward over the rule's lifetime.

### Regression and cross-rule safety

| Check | What it prevents |
|-------|-----------------|
| Full corpus per changed rule | Edit didn't break TP/TN contract |
| Full corpus for rules sharing changed entities | Changing `dict_financial_keywords` re-tests every rule using it |
| Cross-rule conflict scan | Two rules fire on same content with contradictory actions |
| Score boundary analysis | Matches near threshold flagged as fragile |
| Coverage gap detection | Scope change removed a channel but corpus only tests old channels |

## 6.8 Approval Workflow, Versioning, and Compliance

Every entity type flows through the same lifecycle:

```
draft → pending_review → approved → deprecated
              |                |
              v                v
         (rejected)      (new version → draft)
```

Every transition records: who, when, justification, and what changed (diff against previous version). The same workflow applies regardless of entity type, vendor target, or channel.

The provenance chain is machine-readable and bidirectional:

```
Regulation (PCI-DSS Req 3.4)
    ↓
Detection (PCI Credit Card Numbers)
    ↓
Rule (PCI CC - External Email - Block)
    ↓
RuleSet (PCI Compliance Rules)
    ↓
Policy (Production - All Realms)
```

Query forward: "What rules enforce PCI-DSS Req 3.4?" Query backward: "Why does this rule exist? What regulation requires it?" Both are instant, automated, always current.

Detections carry first-class compliance metadata — not tags, but behavioral fields: `regulation_refs`, `jurisdiction`, `data_subject_type`, `legal_basis`, `cross_border_restriction`, `breach_notify_override_hours`. No vendor carries compliance context at the detection level.

## 6.9 Safe Rollout — A/M/E/D Mode Progression

Every rule has exactly one mode:

| Mode | What happens | User impact |
|------|-------------|-------------|
| **A** (Analysis) | Collect statistics only. No incidents. No logs visible to SOC. | Invisible |
| **M** (Monitor) | Create incidents, log to SIEM. No user notification. | Invisible to user. Visible to SOC. |
| **D** (Detect) | Notify user (popup/banner). User CAN proceed. | User sees warning. Can dismiss. |
| **E** (Enforce) | Block / quarantine / encrypt. User CANNOT proceed. | User is blocked. |

Standard rollout: A → M → D → E. Each transition is a version change with approval. Time-in-mode is tracked. Organizations can mandate "rules must spend 2 weeks in Monitor before Enforce."

This eliminates the most dangerous pattern in DLP: shipping an untested rule straight to Enforce mode and blocking legitimate business activity on day one.

## 6.10 Transpiler Design

*[See Diagram 5: Transpiler Pipeline]*

The canonical model is vendor-neutral. Vendor-specific DLP products are deployment targets.

### Pipeline

```
Canonical JSON/YAML        →    Vendor IR (AST)      →    Vendor Native Output
(entity graph)                   (vendor-specific          (importable config)
                                  abstract syntax tree)
```

### Layer-by-layer transpilation

| Our layer | Transpiler maps to | Fidelity | Notes |
|-----------|-------------------|----------|-------|
| Detection conditions | Vendor content match definitions | Mostly lossless | Regex, dictionary, file type are universal. EDM/IDM differ. |
| Detection scoring | Vendor threshold model | Adaptation needed | Trellix: score threshold. Palo Alto: weights. Symantec: breadth. |
| Rule scope | Vendor policy targeting | Mostly lossless | All vendors have user/group scoping. Field names differ. |
| Rule channels | Vendor channel/vector config | Vendor-specific | Our 22 channels don't map 1:1 to every vendor. |
| Rule mode (A/M/E/D) | Vendor enforcement action | Adaptation needed | Some vendors have 3 modes, some 5. Map to closest. |
| RuleSet ordering | Vendor rule priority | Mostly lossless | first_match vs all_matches universally supported. |
| Entity refs | Vendor object references | Resolved at transpile | Refs become inline definitions or vendor-native IDs. |
| Compliance binding | Vendor metadata/tags | Lossy | No vendor carries compliance at detection level — becomes tags. |
| Label conditions | Vendor label matching | Vendor-specific | All support MIP; tier comparison and category matching vary. |

### Fidelity classes

| Class | Meaning | Example |
|-------|---------|---------|
| **Lossless** | 1:1 mapping, no information lost | Regex pattern → Trellix Advanced Pattern |
| **Adapted** | Semantically equivalent, structurally different | Score threshold → Palo Alto weighted expressions |
| **Degraded** | Partial support, some features dropped | Proximity 300 chars → vendor with fixed 200 char window |
| **Unsupported** | Vendor cannot express this concept | ML classifier → vendor without ML support |

### Transpiler interface (conceptual)

```go
type VendorTranspiler interface {
    TranspilePolicy(policy Policy, graph EntityGraph) (VendorExport, error)
    TranspileDetection(det Detection, graph EntityGraph) (VendorDetection, error)
    TranspileRule(rule Rule, graph EntityGraph) (VendorRule, error)
    SupportedChannels() []ChannelType
    SupportedConditionTypes() []ConditionType
    SupportedModes() []RuleMode
    FidelityReport() TranspileFidelityReport
}
```

### Worked example: PCI Credit Card → Trellix + Proofpoint

**Canonical:**
```yaml
detection:
  id: "det_pci_credit_card"
  groups:
    - group_name: "Card Number + Context"
      logic: AND
      conditions:
        - condition_type: "pattern"
          pattern_config:
            expressions:
              - expression: "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\\b"
                weight: 10
            validator_algorithm: "luhn"
            required: true
        - condition_type: "proximity"
          proximity_config:
            context_keywords: ["expir", "CVV", "CVC", "card"]
            distance_chars: 300
            context_required: true

rule:
  mode: "E"
  channels: ["email"]
  direction: ["outbound"]
  enforce_action: "block"
```

**→ Trellix:** Classification (Advanced Pattern + Luhn Validator + Proximity 300 chars) + Rule (Email, Outbound) + Reaction (Prevent). **Fidelity: LOSSLESS** — all conditions map directly.

**→ Proofpoint:** Smart Identifier (Custom Detector + Luhn + Proximity Keywords) + DLP Rule (Email DLP, Outbound, Block). **Fidelity: LOSSLESS** — Custom Detector supports regex + Luhn.

**→ Symantec:** Detection Rule (Content Matches + Validator) + Policy Rule + Response Rule. **Fidelity: ADAPTED** — proximity window fixed at 200 chars (ours: 300). Functional but not identical.

### Why transpilation generalizes

**Boolean algebra is universal.** Every vendor's detection logic reduces to AND/OR groups of conditions. Our group-of-groups model is the canonical boolean form.

**Entity refs decouple data from logic.** Entity resolution is the transpiler's job, not the rule author's. The same dictionary ref resolves to different vendor object types.

**Channel abstraction hides agent plumbing.** Our 22 channels are a superset. The transpiler maps to the vendor's subset and reports unsupported channels.

**Modes map to every vendor's enforcement model.** A → "No Action"/"Log Only", M → "Monitor"/"Log", D → "Notify", E → "Prevent"/"Block".

---

# Tab 7: Benefits Matrix

| Challenge (Tab 2) | Solution capability (Tab 6) | Key metric (Tab 5) | Conservative target |
|---|---|---|---|
| **2.1** FP rates 15-40% | Seven-layer FP stack: validators, ignore expressions, proximity, negative scoring, breadth, scope exclusions, boilerplate stripping | FP rate per rule | < 10% (path to < 5%) |
| **2.2** Monolithic definitions, no reuse | Entity system: 95+ types, never inline values, always reference entities. Change once, propagate everywhere. | Detection reuse rate | > 40% |
| **2.3** Channel fragmentation (N copies per channel) | One rule definition, all channels. Detection is channel-agnostic. Rule binds to channels via `channels[]`. | Rules maintained | N rules, not N x channels |
| **2.4** No feedback loop, rules never learn | Production FP → classified → fix applied → TN fixture added → corpus grows → rule improves | Test corpus growth rate | Positive monthly |
| **2.5** Manual testing, >50% untested | Automated test corpus per rule, dual-engine (WASM + Vectorscan), CI regression, gate blocks untested rules | Untested new rules deployed | 0% (gate enforced) |
| **2.6** Authoring requires DLP engineer | GenAI-powered no-code UI, reusable templates, live test-in-browser, AI recommendations | Non-technical author % | > 50% |
| **2.7** Vendor lock-in, 6-12 month migration | Transpiler: canonical → vendor format. Fidelity report per transpile. Write once, deploy anywhere. | Migration time | 4-8 weeks |
| **2.8** No versioning or audit trail | Entity versioning, approval workflow (draft → review → approved), provenance chain, diff on every change | Audit prep time | < 1 day |
| **2.9** Policy sprawl, conflicts, orphans | Dependency graph: impact analysis, conflict detection, orphan identification, coverage mapping | Orphan/conflict rules | 0 (automated detection) |
| **2.10** Compliance bolted on | Regulation refs on detections, bidirectional provenance queries, jurisdiction scoping, data subject types | Full provenance chain % | 100% (new rules) |

**How to read this table:** Every challenge from Tab 2 has a corresponding solution in Tab 6, a measurable metric in Tab 5, and a conservative target. No challenge is left unaddressed. No solution exists without a corresponding challenge.

---

# Tab 8: Implementation Considerations

## 8.1 Technology Stack

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| Backend | Go | 1.22+ | Rule engine, API, schema generation, transpiler |
| Frontend | React + TypeScript | 18 / 5 | Authoring UI |
| UI Forms | react-jsonschema-form (RJSF) | 5 | Auto-generated entity forms from JSON Schema |
| Code Editor | Monaco Editor | latest | Regex editing with syntax highlighting |
| Regex engine (production) | Vectorscan | 5.4 (CGo) | DFA compilation for < 5ms enforcement |
| Regex engine (WASM) | Go regexp | stdlib | Browser-compatible authoring-time testing |
| Dictionary engine | cloudflare/ahocorasick | pure Go | O(n) multi-pattern keyword matching |
| Schema generation | invopop/jsonschema | Go | Go structs → JSON Schema |
| Schema validation (server) | santhosh-tekuri/jsonschema/v6 | Go | Server-side entity validation |
| Schema validation (browser) | Ajv | 8 | Client-side entity validation |
| Serialization | Protobuf | v3 | Bundle format for enforcement |
| Bundle signing | ed25519 | stdlib | Tamper-proof bundles |
| Publishing | JFrog Artifactory | semver | Per-tenant, per-channel bundle distribution |

## 8.2 Rule Definition Language

Rules are defined in **canonical JSON** (machine-readable) with **YAML** as the human-friendly alternative. Both are validated against JSON Schema at write time.

There is no custom DSL. Standard JSON means: portable, diffable, toolable, and integrable with any CI/CD pipeline, version control system, or API. The schema is the language specification.

**Schema-first pipeline:** Go structs are the single source of truth. `go generate` produces JSON Schema from struct tags. RJSF renders forms from JSON Schema. Ajv validates in the browser. santhosh-tekuri validates on the server. One definition, four consumers, zero drift.

## 8.3 Runtime Engine Architecture

**Compilation pipeline:** Canonical JSON → Vectorscan DFA bundle (per-tenant, per-channel). All regex patterns for a channel are compiled into a single deterministic finite automaton. This is what enables < 5ms matching regardless of pattern count — the DFA scans content once, matching all patterns simultaneously.

**Bundle format:** Signed Protobuf containing compiled patterns, dictionaries, validators, and scoring rules. ed25519 signature ensures tamper-proof delivery from publisher to enforcement point.

**WASM engine:** Go regexp compiled to WebAssembly for in-browser authoring. Same detection logic, different regex engine. CI parity check verifies WASM results match Vectorscan results for every corpus on every commit.

## 8.4 Performance Considerations

| Component | Performance characteristic | Why |
|-----------|--------------------------|-----|
| **Vectorscan DFA** | O(content_length), independent of pattern count | All patterns compiled to single DFA; scanned once |
| **Aho-Corasick dictionaries** | O(content_length), independent of dictionary size | Multi-pattern matching automaton |
| **Proximity** | Post-match filter only | Only runs when primary pattern matches; not applied to full content |
| **Scoring** | Arithmetic | Weight accumulation + threshold comparison; negligible cost |
| **Validators** | Per-match | Luhn = 16 iterations; SSN range = 3 comparisons; trivial |
| **Label resolution** | Cached lookup | TTL-based local cache; no API call at enforcement time |
| **Target budget** | < 5ms per match | Inline enforcement (email, web upload) cannot add perceptible delay |

## 8.5 Transpiler Implementation Considerations

**Per-vendor modules.** Each vendor has a dedicated transpiler module implementing the common `VendorTranspiler` interface. Modules are independent — adding a new vendor doesn't affect existing ones.

**Vendor capability matrix.** Each module declares what the vendor supports natively (`SupportedChannels`, `SupportedConditionTypes`, `SupportedModes`). The transpiler uses this to determine fidelity class per condition before generating output.

**Fidelity reporting.** Every transpile run produces a fidelity report: per-condition classification (lossless/adapted/degraded/unsupported), aggregate fidelity score, and human-readable warnings for anything that isn't lossless. The author reviews this before committing.

**Vendor regression suite.** Each vendor module has its own test suite: canonical input → expected vendor output. When the vendor updates their product (new API version, changed import format), the regression suite catches the break before it reaches production.

**Version pinning.** Transpiler outputs are pinned to specific vendor product versions. "Trellix ePO 5.10" and "Trellix ePO 5.12" may require different output formats. The transpiler version-selects based on target.

**Export-first strategy.** Import (vendor → canonical) is significantly harder than export (canonical → vendor) because vendor formats are often underdocumented and inconsistent. Recommend building export first, import as a follow-on.

## 8.6 Vendor Integration Specifics

| Vendor | Integration surface | Complexity | Key limitations | Recommended priority |
|--------|-------------------|-----------|----------------|---------------------|
| **Proofpoint** | DLP API (JSON, well-documented) | Medium | No native proximity (compound rule workaround) | First — API-first, fastest integration |
| **Palo Alto (Prisma)** | Prisma Cloud API (modern, REST) | Medium | Limited file property matching | First — modern API, well-documented |
| **Microsoft Purview** | Graph API + PowerShell | Medium | Tightly coupled to M365 ecosystem | Second — large market, good docs |
| **Trellix** | ePO REST API + policy XML | High | Legacy, opaque; no catalog integration; proprietary fingerprinting | Third — large installed base but integration is complex |
| **Broadcom Symantec** | Enforce Server REST API + policy XML | High | IDM/VML proprietary; limited label write-back | Third — legacy, significant reverse-engineering |
| **Forcepoint** | Manager API + XML | Medium-High | Proprietary fingerprinting | Later |
| **Skyhigh** | API | Medium | Cloud channels only | Later |

**Recommendation:** Target Proofpoint and Palo Alto first. Both are API-first with reasonable documentation. This validates the transpiler architecture against real vendors before investing in the significantly harder legacy integrations (Trellix, Symantec). Budget 3-6 months per legacy vendor.

## 8.7 Open Questions

- [ ] Import (vendor → canonical) — build as follow-on to export, or skip initially?
- [ ] Vendor-specific features with no canonical equivalent (Symantec VML, Trellix fingerprinting) — map to closest condition type with degraded fidelity, or expose as vendor extension?
- [ ] Bundle update delivery — push from publisher or pull from enforcement point?
- [ ] Multi-tenant bundle isolation — separate bundles per tenant, or shared bundles with tenant-scoped evaluation?
- [ ] Transpiler output format — vendor-native import files, direct API calls, or both?

---

# Tab 9: Risks and Mitigations

## 9.1 Transpilation Fidelity Loss

**Risk:** Vendor capability gaps mean not every canonical rule translates 1:1 to vendor-native format. Some conditions degrade or are unsupported.

**Impact:** Rules require manual post-transpile editing on some vendors, reducing the speed promise of "write once, deploy anywhere."

**Likelihood:** High — every vendor has proprietary limitations and missing features.

**Mitigation:** The fidelity report is the primary defense. Every transpile run classifies each condition as lossless, adapted, degraded, or unsupported. The author sees this before committing and can decide to accept the degradation or restructure the rule. Conservative claim: >70% of conditions transpile losslessly (not >85%). The remaining 30% are mostly "adapted" (functionally equivalent, structurally different) rather than "unsupported."

## 9.2 Vendor Integration Effort Varies Widely

**Risk:** Closed legacy systems (Trellix ePO, Symantec Enforce) require significantly more reverse-engineering and maintenance than API-first modern platforms (Proofpoint, Palo Alto Prisma).

**Impact:** Integration timeline per vendor is unpredictable. Legacy vendors may require 2-3x the effort. Vendor-specific bugs and undocumented behavior consume engineering time.

**Likelihood:** High — legacy DLP products are notoriously opaque with limited API documentation.

**Mitigation:** Tier vendors into integration complexity classes (Tab 8.6). Target API-first vendors first to validate the transpiler architecture. Budget 3-6 months per legacy vendor integration. Vendor regression suites catch format changes on vendor updates. Accept that some vendors may have lower fidelity than others.

## 9.3 Vendor API Instability

**Risk:** Vendor product updates can change or break import/export formats without notice, requiring transpiler maintenance.

**Impact:** Transpiler module breaks on vendor upgrade. Rules stop deploying until fixed.

**Likelihood:** Medium — vendors typically maintain backward compatibility but not always.

**Mitigation:** Vendor-specific regression suite runs against each vendor version. Version-pin transpiler outputs. Monitor vendor release notes. Maintain relationships with vendor partner teams when possible.

## 9.4 Label Normalization Accuracy

**Risk:** External labels from multiple sources may not map cleanly to internal SensitivityTier. Edge cases in multi-source conflict resolution could assign incorrect sensitivity.

**Impact:** Incorrect sensitivity assignment leads to wrong enforcement — either over-blocking (false positive) or under-protecting (false negative).

**Likelihood:** Medium — most mappings are straightforward, but edge cases exist (label systems with different granularity, overlapping categories).

**Mitigation:** `highest_sensitivity_wins` as default conflict resolution (fail-safe — over-protect, not under-protect). Unmapped vendor labels are flagged for admin review, not silently ignored. Manual review queue for ambiguous mappings. Source filtering on LabelCondition allows rules to trust only specific sources.

## 9.5 WASM/Vectorscan Engine Parity

**Risk:** The browser engine (Go regexp) and production engine (Vectorscan DFA) have different regex feature sets. A rule that passes in authoring could fail in production, or vice versa.

**Impact:** Author thinks rule works (browser says so) but it fails in production deployment. Trust in authoring-time testing erodes.

**Likelihood:** Low — CI parity check catches divergences on every commit.

**Mitigation:** CI parity check: every commit runs the full corpus through both engines and fails if results differ. Restrict regex features to the intersection of both engines. Flag unsupported constructs at authoring time before the author can save. Document the feature intersection clearly.

## 9.6 Adoption Resistance

**Risk:** Compliance analysts may resist a new tool. DLP engineers may see it as threatening their expertise and role. Organizations may default to existing vendor tools out of inertia.

**Impact:** Low adoption leads to low ROI, which leads to program stall.

**Likelihood:** Medium — organizational change resistance is real, especially when existing tools are "good enough" in perception.

**Mitigation:** Position as "review instead of author" for DLP engineers — they become quality gatekeepers, not bottlenecked implementers. Start with new rules, not migration of existing rules (lower friction). Target quick wins: show a PCI credit card rule authored in 30 minutes with a test corpus, vs 4 hours in the vendor tool. Build template library so early adoption requires minimal learning.

## 9.7 Corpus Cold Start

**Risk:** New rules have no production FP data. The test corpus starts as hand-written fixtures. FP rates are higher in the first months before production feedback accumulates.

**Impact:** Early FP rates may not meet target metrics immediately. Stakeholder expectations must be managed.

**Likelihood:** High for every new deployment and every new rule.

**Mitigation:** Seed corpus from known FP patterns per data type (credit card: order refs, tracking numbers, loyalty IDs; SSN: ITINs, EINs, phone numbers). AI-generated initial fixtures based on data type. Set expectations clearly: FP rate improves over 3-6 months as production feedback enriches the corpus. Track FP rate trend per rule to demonstrate continuous improvement.

---

# Tab 10: False Positive Optimization — Continuous Learning Pipeline

DLP programs live or die by false positive rates. A rule that blocks 40% legitimate traffic is worse than no rule — analysts stop trusting alerts, end users escalate, and the security team loses credibility. The seven-layer FP elimination stack (Tab 6.4) handles authoring-time prevention. This section covers what happens **after deployment** — how production FP signals feed back into rule improvement through two complementary workflows.

## 10.1 Workflow 1: User-Driven FP Feedback with Intelligent Recommendations

When an analyst marks an alert as a false positive, the system doesn't just log it — it analyzes the blocked content to recommend specific suppression tags that would prevent similar FPs in the future, with the analyst approving each recommendation before it takes effect.

### How It Works

**Step 1: Analyst marks an alert as false positive.**
The analyst reviews a blocked transaction in the incident queue and marks it FP. The system captures the analyst verdict (true_positive / false_positive / false_negative / inconclusive), free-form notes, and time-to-review — all stored in the retroactive decision record for ML training eligibility.

**Step 2: System analyzes the blocked content and generates suppression recommendations.**
Three recommendation algorithms run in parallel against the content surrounding the matched value:

| Algorithm | What It Does | Confidence | Example |
|-----------|-------------|------------|---------|
| **Near-miss labels** | Extracts 1-3 token phrases from the context window and compares against the entity type's existing suppression list using root-word matching and edit-distance similarity (<40% Levenshtein). Surfaces candidates that are *close to* but *not yet in* the suppression set. | Medium | Rule suppresses "order number" but context contains "order ref" — suggested as a near-miss variant |
| **Proximity labels** | Extracts the phrase immediately before the matched value (40-char window). High-confidence signal — if a field label like "tracking #" or "reference id" precedes the matched digits, that label is almost certainly the reason for the FP. | High | Content: `Job Token: 576-84-1234` — "job token" extracted as proximity label |
| **KB cross-entity history** | Checks whether any label already approved by a human for a *different* entity type appears in the current context. A label validated for SSN suppression that also appears near a credit card match is strong evidence it's a benign domain phrase. | Highest | "customer id" was approved for SSN → now appears near a credit card match → suggested with "previously approved for SSN" note |

**Step 3: Analyst reviews and approves recommendations (human-in-the-loop).**
Each suggestion is presented with:
- The candidate label and why it was recommended
- The context snippet showing where it appeared relative to the match
- The source signal (near-miss, proximity, midlane downgrade, Luhn failure, KB history)
- The similar existing label it was compared against (if any)

The analyst approves, modifies, or rejects each suggestion. No suppression is applied without explicit human approval.

**Step 4: Approved label takes effect immediately and durably.**
On approval, three stores update atomically:
1. **FastLane runtime overlay** — the suppression label is pushed to the detection engine's in-process memory via hot-reload. Takes effect on the next scan — no restart, no redeployment.
2. **In-memory learned labels** — future suggestion runs reflect the new label immediately, preventing duplicate recommendations.
3. **OPA policy store** — the authoritative durable record. Hydrated on startup, auditable, tagged with who approved it and when.

The label is normalized to the entity family root (e.g., CREDIT_CARD_VISA → CREDIT_CARD) so a single approval covers all sub-type variants.

### Signal Amplification from ML

The recommendation engine gains additional signal from the MidLane ML classifier. When the ML model classifies a FastLane BLOCK as a false positive (action=DOWNGRADE), the system:
- Elevates all suggestions for that finding to `midlane_downgrade` source (higher confidence)
- Activates proximity label extraction even for findings that wouldn't normally qualify
- Includes the ML model's reasoning in the suggestion note (e.g., "MidLane: content classified as benign business document")

Similarly, Luhn validation failures for credit card patterns are treated as high-confidence FP signals — a sequence that looks like a credit card number but fails the Luhn checksum is almost certainly not a real card number, and the surrounding context likely contains a suppression-worthy label.

## 10.2 Workflow 2: ML-Driven Suppression Discovery via Clustering

While Workflow 1 is reactive (analyst marks FP → system recommends), Workflow 2 is **proactive** — the system periodically analyzes accumulated FP data to identify systemic suppression opportunities that no individual analyst would notice.

### The Problem It Solves

An analyst reviewing a single FP sees one context. But across thousands of FP events, patterns emerge:
- 200 SSN FPs all have "employee id" or "badge number" in the context — but neither label is in the suppression list
- Credit card FPs cluster around invoice templates from three specific vendors
- Driver's license FPs spike every Monday morning when HR runs a batch report

Individual analysts can't see these patterns. Clustering can.

### How It Works

**Stage 1: Feature extraction from FP corpus.**
For every confirmed FP (analyst verdict or ML downgrade), the system extracts:
- Context tokens (1-3 word phrases from the surrounding text)
- Entity type and sub-type
- Channel (email, web, USB, cloud, print)
- Content structure (email header, table cell, code block, URL, file path)
- Temporal features (time of day, day of week, recurring patterns)
- Source metadata (sender domain, application, file type)

**Stage 2: Clustering to identify suppression candidates.**
The extracted features feed into unsupervised clustering:

| Technique | Purpose | Output |
|-----------|---------|--------|
| **TF-IDF + K-Means on context tokens** | Group FPs with similar surrounding text | Clusters of FPs that share the same context phrase (e.g., "patient mrn", "case number") — each cluster centroid is a candidate suppression label |
| **DBSCAN on temporal-channel features** | Detect recurring FP bursts | Scheduled jobs or batch processes that trigger FPs at predictable intervals — candidates for time-based or source-based scope exclusions |
| **Hierarchical clustering on entity+context** | Find cross-entity suppression opportunities | Labels that cause FPs across multiple entity types (e.g., "reference" triggers FPs for SSN, credit card, and phone number) — candidates for global suppression rules |

**Stage 3: Leverage existing suppressors.**
Before recommending new suppression tags, the system cross-references against:
- The existing `pattern_fp_labels.json` database (1,000+ entity-specific suppression rules with context windows and confidence deltas)
- Previously approved learned labels in OPA
- Cross-entity approval history (a label approved for one entity type is pre-validated for others)

This prevents duplicate recommendations and surfaces gaps — "you suppress 'order number' and 'order ref' for credit cards, but not 'order id' which appears in 47 FPs this month."

**Stage 4: Recommendation generation with evidence.**
Each cluster that exceeds a configurable threshold (e.g., 10+ FPs with the same context pattern) generates a recommendation:

```
RECOMMENDATION: Add "badge number" as suppression label for SSN
  Evidence: 234 FPs in last 30 days with "badge number" in context
  Cluster size: 234 events across 12 channels
  Affected rules: SSN-US-BASIC, SSN-US-ENHANCED
  Existing similar labels: "employee id" (already suppressed)
  Estimated FP reduction: ~2.1% of total SSN FPs
  Confidence: HIGH (consistent context, single phrase, cross-channel)
```

**Stage 5: Human review and batch approval.**
Recommendations are surfaced in the Composer UI as a periodic "FP Optimization Report" — not auto-applied. The security team reviews each recommendation with full evidence, approves or rejects in batch, and approved labels flow through the same three-store update path as Workflow 1.

### Active Learning Integration

The clustering pipeline connects to the broader active learning loop:

1. **Uncertainty sampling** — Findings where the ML classifier confidence falls between 0.4-0.7 are routed to the analyst review queue (maximizes information gain per human review)
2. **Disagreement sampling** — When FastLane says BLOCK but MidLane says ALLOW, the disagreement is prioritized for analyst review (these are the most informative training examples)
3. **Diversity sampling** — Embedding-based clustering ensures the analyst queue covers all content archetypes, not just the most frequent patterns
4. **Feedback cadence** — Weekly batch retraining of the ML classifier incorporates all analyst verdicts from the past week; daily micro-updates adjust confidence thresholds

### Drift Detection

The clustering pipeline also monitors for **rule drift** — an established rule whose FP rate is rising over time:
- Per-rule FP rate tracked as a time series
- Alert when FP rate exceeds 2x the 30-day moving average
- Root cause analysis: is it a new data source, a format change, a seasonal pattern, or a genuine rule degradation?
- Recommendation: add suppressions, adjust thresholds, or flag for manual rule review

## 10.3 The Three Maturity Levels

These two workflows operate at different maturity levels, deployed incrementally:

| Level | Workflow | Human Involvement | FP Rate Impact |
|-------|----------|-------------------|----------------|
| **Level 1: Manual + Recommendations** | Analyst marks FP → system recommends suppression labels → analyst approves | High — every label requires approval | Reduces FP investigation time from ~15 min to ~2 min per incident |
| **Level 2: ML-Assisted Clustering** | Clustering identifies systemic FP patterns → batch recommendations with evidence → security team reviews weekly | Medium — batch review, not per-incident | Catches patterns invisible to individual analysts; estimated 30-50% FP reduction over 6 months |
| **Level 3: Autonomous with Guardrails** | High-confidence recommendations (KB cross-entity, >100 FP cluster, <0.3 ML confidence) auto-apply with 24-hour rollback window | Low — review-by-exception, auto-applied labels flagged in audit log | Continuous improvement without analyst bottleneck; target <5% FP rate |

Level 3 is the long-term vision. Level 1 is implemented and validated in prototype. Level 2 is designed and partially implemented (feature extraction and suggestion algorithms exist; clustering pipeline is specified but not yet in production).

## 10.4 Data Architecture

The feedback loop requires specific data capture at each stage:

```
┌─────────────────────────────────────────────────────────────────┐
│                    PRODUCTION SCAN                              │
│  FastLane BLOCK → MidLane classify → Deep Lane (if needed)     │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│               RETROACTIVE DECISION RECORD                      │
│  analyst_verdict · analyst_notes · time_to_review              │
│  training_eligible · policy_gap_identified · new_rule_suggested │
│  ClickHouse: dlp_decisions table (append-only, partitioned)    │
└──────────┬────────────────────────────────┬─────────────────────┘
           │                                │
     ┌─────▼──────┐                  ┌──────▼──────┐
     │ Workflow 1  │                  │ Workflow 2  │
     │ Per-incident│                  │ Batch ML    │
     │ suggestions │                  │ clustering  │
     └─────┬──────┘                  └──────┬──────┘
           │                                │
           ▼                                ▼
┌─────────────────────────────────────────────────────────────────┐
│              HUMAN-IN-THE-LOOP APPROVAL                        │
│  Per-label approval (Wf1) · Batch review (Wf2)                │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│              THREE-STORE ATOMIC UPDATE                          │
│  1. FastLane runtime overlay (immediate, in-process)           │
│  2. Learned labels mirror (future suggestions reflect it)      │
│  3. OPA policy store (durable, auditable, hydrated on startup) │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│              ML RETRAINING PIPELINE                             │
│  Weekly batch retrain · Daily micro-updates                    │
│  Analyst verdicts → SLM fine-tuning (LoRA)                     │
│  Approved labels → Suppression corpus enrichment               │
│  Drift detection → Per-rule FP rate monitoring                 │
└─────────────────────────────────────────────────────────────────┘
```

## 10.5 Why This Matters

No DLP vendor today implements a closed-loop FP feedback pipeline. Every vendor we evaluated (Trellix, Proofpoint, Symantec, Palo Alto, Netskope, Zscaler, Skyhigh, Forcepoint) treats FP handling as a manual, per-incident process: analyst sees FP → analyst edits rule → analyst redeploys. There is no systemic learning, no cross-entity knowledge transfer, no clustering-based discovery.

This is the gap. A DLP system that gets **measurably better over time** — not because an engineer manually tuned it, but because every analyst interaction and every ML classification feeds back into the suppression corpus — is fundamentally different from a system that stays as good as its last manual update.

The conservative target: FP rates below 10% initially (seven-layer prevention), declining to below 5% within 6 months of production deployment as the feedback loop matures. The mechanism is concrete: more analyst verdicts → richer suppression labels → fewer FPs → less analyst time per remaining FP → faster verdicts → more training data → better ML → cycle continues.

---

# Tab 11: Label Architecture — Integration, Data Flow, Rule Composition, and Runtime Enforcement

Tab 6.5 introduced labels and DSPM integration at a conceptual level. This section provides the **detailed technical architecture** — how labels get into the system, how they flow through normalization and caching layers, how analysts compose rules against them, and how the runtime engine evaluates label conditions at enforcement time across 22 data loss channels.

## 11.1 The Label Problem in DLP

Labels are the bridge between "what kind of data is this?" and "what should we do about it?" But in practice, labels come from wildly different systems with incompatible formats, trust levels, and availability guarantees:

| Label Source | Format | Where It Lives | Latency | Trust Level |
|-------------|--------|---------------|---------|-------------|
| MIP/AIP | OOXML custom property, PDF XMP, SMTP header (`msip_labels`) | Embedded in document/email | Zero — travels with file | High — cryptographically signed by Azure AD |
| Google Workspace | Drive Labels API response | Cloud-only — does NOT travel with downloaded file | API call or cache lookup | High — set by Workspace admin or automated policy |
| Titus/Fortra | Custom document property (`bjDocumentSecurityLabel`) or SMTP header | Embedded in document/email | Zero — travels with file | High — applied by classification agent |
| Boldon James | SISL markup string in document property | Embedded in document | Zero — travels with file | High — applied by classification agent |
| AWS Macie | EventBridge findings (JSON) | Cloud event stream | Minutes to hours (async scan) | Medium — ML-based, confidence varies |
| GCP DLP | Pub/Sub findings or API response | Cloud event stream or API | Minutes (async) or seconds (API) | Medium — ML-based |
| Azure Purview | Event Grid findings or Data Map API | Cloud event stream or API | Minutes (async) or seconds (API) | Medium-High — hybrid ML + rules |
| Snowflake tags | `SYSTEM$GET_TAG()` or `TAG_REFERENCES` view | Database metadata | Query-time | High — set by data owner |
| Databricks Unity | Unity Catalog tags API | Catalog metadata | Query-time | High — set by data owner |
| S3 object tags | `GetObjectTagging` API | Object metadata | API call | Variable — depends on tagging source |
| Data catalogs (Collibra, Alation, Atlan) | REST API | Governance platform | API call or bulk sync | High — curated by data stewards |
| User-applied | Manual selection at save/send/print | Document property or email header | Zero | Low-Medium — depends on training and enforcement |

The challenge: a single DLP rule like "block Confidential+ documents containing PII from being sent to external recipients" must work regardless of whether the label came from MIP on an Office doc, Google Workspace on a Drive file, or Macie on an S3 object — and regardless of whether the label is embedded in the file, cached from a cloud API, or looked up in real-time.

## 11.2 Integration Points — How Labels Enter the System

Labels enter DLP Composer through five distinct read methods, each handled by an **ExternalLabelConnector** entity that encapsulates the source system, authentication, parsing format, and mapping rules.

### 11.2.1 File Metadata (Document-Embedded Labels)

```
┌─────────────────────────────────────────────────────────┐
│ Document (OOXML, PDF, MSG)                              │
│                                                         │
│   Custom Properties / XMP Metadata / Headers            │
│   ┌──────────────────────────────────────────────┐      │
│   │ MSIP_Label_{GUID}_Enabled = true             │      │
│   │ MSIP_Label_{GUID}_SiteId = {tenant}          │      │
│   │ MSIP_Label_{GUID}_Method = Privileged        │      │
│   │ bjDocumentSecurityLabel = RESTRICTED          │      │
│   │ Titus_Classification = CONFIDENTIAL           │      │
│   └──────────────────────────────────────────────┘      │
└──────────────────────┬──────────────────────────────────┘
                       │ Agent/proxy intercepts file
                       ▼
┌─────────────────────────────────────────────────────────┐
│ ExternalLabelConnector (read_method: file_metadata)     │
│                                                         │
│   metadata_format: mip_ooxml | mip_pdf_xmp |           │
│                    titus_plain | boldon_james_sisl |     │
│                    spirion_tag | custom_property         │
│   metadata_property_name: "MSIP_Label_*"                │
│                                                         │
│   Parsing: Extract label GUID/name from property value  │
│   Mapping: GUID → ClassificationLabel → SensitivityTier │
└─────────────────────────────────────────────────────────┘
```

**How it works:** The DLP agent (endpoint or proxy) intercepts a file at the enforcement point (email send, USB copy, cloud upload, print). Before running content detection, the agent reads the file's metadata properties. For OOXML files (Word, Excel, PowerPoint), labels are stored in custom XML parts. For PDFs, in XMP metadata. For emails, in SMTP headers.

**MIP label parsing:** MIP embeds labels as `MSIP_Label_{GUID}_Enabled=true` with additional fields for method (Privileged/Standard), timestamp, and content marking. The connector extracts the GUID, matches it against the `mip_label_guid` field on registered ClassificationLabel entities, and resolves to a SensitivityTier + DataCategory via the LabelMapping.

**Trust model:** Document-embedded labels are the highest-trust source because they're cryptographically bound to the document (MIP labels are signed by Azure AD). The label travels with the document across all channels — email, USB, cloud, print — without requiring API calls or cache lookups.

### 11.2.2 Email Header Labels

```
┌────────────────────────────────────────────────────────────┐
│ Email (SMTP)                                               │
│                                                            │
│   Headers:                                                 │
│   ┌─────────────────────────────────────────────────────┐  │
│   │ msip_labels: MSIP_Label_{GUID}_Enabled=true;        │  │
│   │              MSIP_Label_{GUID}_SiteId={tenant};...   │  │
│   │ X-Protective-Marking: VER=2018.6,                    │  │
│   │   NS=gov.au, SEC=OFFICIAL:Sensitive, CAVEAT=SH:...  │  │
│   │ X-Titus-Classification: CONFIDENTIAL                 │  │
│   └─────────────────────────────────────────────────────┘  │
└──────────────────────┬─────────────────────────────────────┘
                       │ Mail gateway intercepts
                       ▼
┌────────────────────────────────────────────────────────────┐
│ ExternalLabelConnector (read_method: email_header)         │
│                                                            │
│   email_header_name: "msip_labels" | "X-Protective-Marking"│
│   email_header_format: mip_semicolon | pspf_key_value |   │
│                         titus_plain | custom_regex          │
│   email_header_regex: (optional custom extraction)         │
│                                                            │
│   Parsing: Header-format-specific parser                   │
│   Mapping: Extracted value → SensitivityTier               │
└────────────────────────────────────────────────────────────┘
```

**PSPF-specific:** Australian government protective marking headers follow the `X-Protective-Marking` standard with structured fields (version, namespace, security classification, caveats, access controls). The connector parses the key-value format and maps SEC values (UNOFFICIAL, OFFICIAL, OFFICIAL:Sensitive, PROTECTED, SECRET, TOP SECRET) to SensitivityTier entities.

### 11.2.3 Cloud API (Real-Time Label Lookup)

```
┌──────────────────────────────────────────────────────────┐
│ Cloud Platform                                            │
│                                                           │
│   Google Drive Labels API ─────────────────────┐          │
│   GCP DLP Inspect API ─────────────────────────┤          │
│   Snowflake SYSTEM$GET_TAG() ──────────────────┤          │
│   Databricks Unity Catalog API ────────────────┤          │
│   Azure Purview Data Map API ──────────────────┘          │
└──────────────────────────┬───────────────────────────────┘
                           │ API call at enforcement time
                           ▼
┌──────────────────────────────────────────────────────────┐
│ ExternalLabelConnector (read_method: cloud_api)          │
│                                                          │
│   api_endpoint: platform-specific URL                    │
│   auth_method: oauth2 | service_account | api_key        │
│   response_format: json (platform-specific schema)       │
│                                                          │
│   Caching: Response cached with configurable TTL         │
│   Fallback: cache_miss_action if API unavailable         │
│   Mapping: API response → SensitivityTier + DataCategory │
└──────────────────────────────────────────────────────────┘
```

**Latency consideration:** Real-time API calls add 50-500ms to enforcement decisions. Acceptable for cloud uploads and email where the user can tolerate a brief delay. Not acceptable for USB copy or print where inline enforcement must complete in <5ms. For latency-sensitive channels, use hash correlation (11.2.5) or event stream pre-caching (11.2.4) instead.

### 11.2.4 Event Stream (Async Findings Cache)

```
┌──────────────────────────────────────────────────────────┐
│ Cloud Security Service                                    │
│                                                           │
│   AWS Macie → EventBridge ─────────────────────┐          │
│   GCP DLP → Pub/Sub ──────────────────────────┤          │
│   Azure Purview → Event Grid ──────────────────┘          │
└──────────────────────────┬───────────────────────────────┘
                           │ Async findings (minutes after scan)
                           ▼
┌──────────────────────────────────────────────────────────┐
│ ExternalLabelConnector (read_method: event_stream)       │
│                                                          │
│   event_source: eventbridge | pubsub | azure_event_grid  │
│   event_filter: finding type / severity filter           │
│   finding_cache_ttl: 1h to 30d                           │
│                                                          │
│   Ingestion: Subscribe → parse finding → extract         │
│     classifications → cache as {resource_id → labels}    │
│   Mapping: Finding severity/type → SensitivityTier       │
└──────────────────────────────────────────────────────────┘
```

**How it works:** Cloud security services (Macie, GCP DLP, Purview) scan data assets asynchronously and publish findings to event buses. The connector subscribes to the event stream, extracts classification information from findings, and caches the result as a mapping from resource identifier (S3 ARN, BigQuery table, Azure blob path) to label. When a DLP rule evaluates, it looks up the resource in the local cache.

**Trade-off:** Event stream labels have latency — a file scanned by Macie at 2:00 AM won't have findings until the scan completes. A file created at 3:00 PM won't have Macie findings until the next scan window. Rules using event stream labels should combine with content detection as a safety net.

### 11.2.5 Hash Correlation (For Labels That Don't Travel)

```
┌──────────────────────────────────────────────────────────┐
│ Google Workspace                                          │
│                                                           │
│   Drive file "Q3-report.xlsx"                             │
│     Label: "Confidential - Financial"                     │
│     SHA-256: a1b2c3d4...                                  │
│                                                           │
│   User downloads file → label stripped from local copy    │
└──────────────────────────┬───────────────────────────────┘
                           │ CASB connector pre-caches
                           ▼
┌──────────────────────────────────────────────────────────┐
│ Hash Correlation Cache                                    │
│                                                           │
│   { "a1b2c3d4...": {                                      │
│       "label": "Confidential - Financial",                │
│       "tier": "confidential",                             │
│       "category": "FINANCIAL",                            │
│       "cached_at": "2026-06-05T10:00:00Z",               │
│       "ttl": "24h"                                        │
│   }}                                                      │
└──────────────────────────┬───────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│ DLP Agent intercepts file (USB copy, email attachment)    │
│                                                           │
│   1. Compute SHA-256 of file                              │
│   2. Lookup hash in correlation cache                     │
│   3. If hit → resolve label → evaluate rule               │
│   4. If miss → cache_miss_action:                         │
│      allow | block | query_api_realtime | apply_default   │
└──────────────────────────────────────────────────────────┘
```

**Why this exists:** Google Workspace labels are metadata in Google Drive, not embedded in the file. When a user downloads a Google Doc as .docx, the Workspace label is gone. The hash correlation connector solves this by pre-caching file hashes and their associated labels. A CASB connector periodically crawls the Drive (configurable: 15m to 24h), hashes each file, records the label, and populates the cache. When the DLP agent intercepts the downloaded file at any channel (USB, email, cloud upload, print), it hashes the file and looks up the cached label.

**Configuration:**
- `hash_algorithm`: SHA-256 (default), SHA-1, MD5, or SHA-256+MD5 (for backward compatibility)
- `cache_ttl`: 1 hour to 90 days (balances coverage vs staleness)
- `cloud_scan_scope`: All files, labeled files only, or specific drives
- `cache_miss_action`: What to do when hash isn't in cache — allow (permissive), block (strict), query_api_realtime (fallback to API), or apply_default_tier (treat as default sensitivity)

## 11.3 Normalization — How Labels Become Comparable

Raw labels from different sources are incomparable. "Confidential" in MIP, "HIGHLY_SENSITIVE" in Snowflake, and "SEC=PROTECTED" in PSPF headers all mean roughly the same thing — but a rule can't compare them without normalization.

### The Normalization Pipeline

```
┌───────────────────────────────────────────────────────────┐
│ Raw Label Input                                            │
│                                                            │
│   MIP: MSIP_Label_{GUID}_Enabled=true                      │
│   Titus: CONFIDENTIAL                                      │
│   PSPF: SEC=PROTECTED                                      │
│   Macie: severity=HIGH, category=FINANCIAL                  │
│   Snowflake: tag "pii_level" = "restricted"                 │
└──────────────────────┬────────────────────────────────────┘
                       │
                       ▼
┌───────────────────────────────────────────────────────────┐
│ LabelMapping (per ExternalLabelConnector)                   │
│                                                            │
│   source_label_id: "{GUID}" | "CONFIDENTIAL" | "PROTECTED" │
│   match_type: exact | contains | regex | starts_with        │
│   sensitivity_ref: → SensitivityTier entity                 │
│   category_ref: → DataCategory entity                       │
│   priority: integer (conflict resolution order)             │
│   bidirectional: false (read-only by default)               │
└──────────────────────┬────────────────────────────────────┘
                       │
                       ▼
┌───────────────────────────────────────────────────────────┐
│ Internal Normalized Model                                  │
│                                                            │
│   SensitivityTier:                                         │
│   ┌────────────────────────────────────────────────────┐   │
│   │ tier_code: "confidential"                          │   │
│   │ tier_level: 3 (numeric, for comparison operators)  │   │
│   │ framework: "enterprise"                            │   │
│   │ equivalent_tiers:                                  │   │
│   │   iso_27001: "C2"                                  │   │
│   │   fips_199: "moderate"                             │   │
│   │   pspf_australia: "PROTECTED"                      │   │
│   │   nato: "CONFIDENTIAL"                             │   │
│   └────────────────────────────────────────────────────┘   │
│                                                            │
│   DataCategory:                                            │
│   ┌────────────────────────────────────────────────────┐   │
│   │ category_code: "PII_DIRECT"                        │   │
│   │ parent_category_ref: → "PII"                       │   │
│   │ default_sensitivity_ref: → tier_confidential       │   │
│   │ regulation_refs: [GDPR, CCPA, HIPAA]               │   │
│   │ is_special_category: true (GDPR Art. 9)            │   │
│   └────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────┘
```

### Conflict Resolution

When multiple label sources provide classifications for the same document:

| Strategy | Logic | Use Case |
|----------|-------|----------|
| `highest_sensitivity_wins` | Compare `tier_level` numerically, take the highest | Default — fail-safe, over-protect rather than under-protect |
| `most_recent_wins` | Compare timestamps, take the latest | Useful when labels are actively being reclassified |
| `connector_priority` | Each connector has a priority rank, highest-priority connector's label wins | When the organization trusts certain sources over others (e.g., Macie over user-applied) |

### Unmapped Labels

When a vendor label doesn't match any LabelMapping entry:

| Action | Behavior |
|--------|----------|
| `ignore` | Label is silently skipped — document treated as unlabeled |
| `flag` | Label is logged to admin review queue, document treated as unlabeled |
| `apply_default` | Document receives the connector's `default_sensitivity_ref` tier |

## 11.4 Rule Composition — How Analysts Use Labels in Rules

### The ClassificationLabel Condition

Labels are available as a first-class condition type in the detection engine. An analyst composing a rule in the visual UI can add a label condition alongside pattern, proximity, validator, and ML classifier conditions.

```yaml
# Detection: "Document carries a Confidential or higher label from an automated source"
detection:
  name: "labeled-confidential-plus"
  conditions:
    - condition_type: "classification_label"
      label_config:
        sensitivity_tier_ref: { entity_id: "tier_confidential" }
        tier_operator: "gte"           # >= Confidential (includes Restricted, Secret, etc.)
        label_sources: ["mip", "aws_macie", "gcp_dlp", "azure_purview"]  # trust filter
```

### Three Matching Dimensions

**Dimension 1: Specific label matching.**
Match a vendor-specific label by reference. Used when the organization has specific label policies.

```yaml
# "Document carries the MIP 'Highly Confidential - All Employees' label"
condition_type: "classification_label"
label_config:
  labels:
    - { entity_id: "mip_highly_confidential_all_employees" }  # ClassificationLabel ref
  operator: "any_of"
```

**Dimension 2: Sensitivity tier comparison.**
Match by the normalized sensitivity level. Tier comparison uses numeric `tier_level` values, which means adding new tiers (e.g., inserting "Internal-Plus" between Internal and Confidential) automatically applies to existing rules without modification.

```yaml
# "Any document at or above Confidential"
condition_type: "classification_label"
label_config:
  sensitivity_tier_ref: { entity_id: "tier_confidential" }
  tier_operator: "gte"    # gte | lte | equals | gt | lt
```

**Dimension 3: Data category matching.**
Match by hierarchical data category. With `category_match_children: true`, a rule targeting "PII" automatically covers PII_Direct, PII_Indirect, SSN, Credit_Card, DOB, and any future sub-categories.

```yaml
# "Any document categorized as PII (including all sub-types)"
condition_type: "classification_label"
label_config:
  category_ref: { entity_id: "cat_pii" }
  category_match_children: true
```

### Label + Content Compound Rules

The most powerful rules combine label conditions with content detection conditions using the standard group AND/OR logic:

```yaml
# Rule: "Block Confidential+ documents containing credit card numbers sent to external recipients"
detection:
  name: "confidential-pci-external"
  conditions:
    - group:
        logic: AND
        conditions:
          # Label condition: document is Confidential or higher
          - condition_type: "classification_label"
            label_config:
              sensitivity_tier_ref: { entity_id: "tier_confidential" }
              tier_operator: "gte"

          # Content condition: contains credit card numbers (with validators)
          - condition_type: "pattern"
            pattern_ref: { entity_id: "regex_credit_card_all_networks" }
            min_matches: 1
            validator_refs:
              - { entity_id: "validator_luhn" }

          # Scope condition: external recipient (evaluated at channel level)
          - condition_type: "recipient_scope"
            scope_config:
              recipient_type: "external"

rule:
  detection_ref: { entity_id: "confidential-pci-external" }
  enforcement_mode: "enforce"
  actions:
    - action_type: "block"
      notify_user: true
      incident_severity: "high"
```

### Label Scope on Rules (Pre-Filtering)

Beyond detection conditions, labels serve as **scope pre-filters** — evaluated before content detection runs:

```yaml
rule:
  name: "pci-scan-confidential-only"
  # Only run this rule against Confidential+ documents
  include_labels:
    - sensitivity_tier_ref: { entity_id: "tier_confidential" }
      tier_operator: "gte"
  # Never scan Public documents (fast skip, saves processing)
  exclude_labels:
    - sensitivity_tier_ref: { entity_id: "tier_public" }
      tier_operator: "equals"

  detection_ref: { entity_id: "pci_full_detection" }  # expensive regex + ML
```

**Why this matters:** Content detection is expensive — regex matching, ML classification, and validation consume CPU. If the organization only cares about PCI data in Confidential+ documents, running the full PCI detection pipeline on every Public document wastes processing and generates noise. Label scope pre-filtering short-circuits before detection, reducing both latency and false positives.

### Tiered Enforcement Pattern

Same detection, different enforcement by sensitivity level — the canonical label use case:

```yaml
# Rule 1: Enforce (block) on Restricted+
rule:
  detection_ref: { entity_id: "pci_detection" }
  include_labels:
    - sensitivity_tier_ref: { entity_id: "tier_restricted" }
      tier_operator: "gte"
  enforcement_mode: "enforce"
  actions: [{ action_type: "block" }]

# Rule 2: Detect (alert) on Confidential
rule:
  detection_ref: { entity_id: "pci_detection" }   # SAME detection, reused
  include_labels:
    - sensitivity_tier_ref: { entity_id: "tier_confidential" }
      tier_operator: "equals"
  enforcement_mode: "detect"
  actions: [{ action_type: "alert", incident_severity: "medium" }]

# Rule 3: Monitor (log) on Internal and below
rule:
  detection_ref: { entity_id: "pci_detection" }   # SAME detection, reused
  include_labels:
    - sensitivity_tier_ref: { entity_id: "tier_internal" }
      tier_operator: "lte"
  enforcement_mode: "monitor"
  actions: [{ action_type: "log" }]
```

Three rules, one detection, three enforcement levels. Adding a new sensitivity tier between Confidential and Restricted automatically applies to the correct rule because the comparison is numeric (`gte` / `lte` / `equals`).

## 11.5 Runtime Execution — How Labels Are Evaluated at Enforcement Time

### The Enforcement Pipeline

When content transits a DLP enforcement point (email gateway, endpoint agent, cloud proxy, print spooler), the label evaluation happens as part of the standard detection pipeline:

```
┌─────────────────────────────────────────────────────────────┐
│ 1. INTERCEPTION                                             │
│    Agent/proxy intercepts content at enforcement point       │
│    (email send, USB copy, cloud upload, print, IM paste)    │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. LABEL EXTRACTION                                         │
│    For each active ExternalLabelConnector:                   │
│                                                             │
│    file_metadata → Parse document properties                │
│    email_header  → Parse SMTP headers                       │
│    hash_correlation → Compute hash, lookup cache            │
│    cloud_api     → Call API (if latency budget permits)     │
│    event_stream  → Lookup resource in findings cache        │
│                                                             │
│    Result: Set of raw labels per source                     │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. LABEL NORMALIZATION                                      │
│    For each raw label:                                      │
│      Match against LabelMappings (exact/contains/regex)     │
│      Resolve to SensitivityTier + DataCategory              │
│    Conflict resolution across multiple sources              │
│                                                             │
│    Result: Resolved sensitivity_tier + data_categories[]    │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. LABEL SCOPE PRE-FILTER                                   │
│    For each candidate Rule:                                 │
│      Evaluate include_labels → skip if no match             │
│      Evaluate exclude_labels → skip if match                │
│                                                             │
│    Result: Filtered set of applicable rules                 │
│    (rules for wrong sensitivity level are eliminated early)  │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. CONTENT DETECTION (only for surviving rules)             │
│    Pattern matching (Vectorscan DFA, <5ms)                  │
│    Validators (Luhn, Mod97, SSN range)                      │
│    Proximity context, suppression rules                     │
│    ML classification (if configured)                        │
│    Label conditions evaluated alongside content conditions  │
│                                                             │
│    Result: Detection verdict per rule (match/no-match)      │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. ENFORCEMENT                                              │
│    Highest-severity matching rule determines action          │
│    block > quarantine > encrypt > redact > alert > log      │
│                                                             │
│    Result: Enforcement action applied to content             │
└─────────────────────────────────────────────────────────────┘
```

### Label Evaluation in the Condition Engine

At step 5, the classification_label condition evaluates against the resolved labels from step 3:

```
ClassificationLabelCondition.Evaluate(resolvedLabels):

  IF tier_operator is set:
    resolved_tier_level = resolvedLabels.sensitivity_tier.tier_level
    config_tier_level = lookup(sensitivity_tier_ref).tier_level
    RETURN compare(resolved_tier_level, config_tier_level, tier_operator)

  IF category_ref is set:
    resolved_categories = resolvedLabels.data_categories
    target_category = lookup(category_ref)
    IF category_match_children:
      RETURN any(c in resolved_categories where c == target OR c.is_descendant_of(target))
    ELSE:
      RETURN target in resolved_categories

  IF labels[] is set:
    resolved_label_ids = resolvedLabels.classification_labels[].entity_id
    SWITCH operator:
      any_of: RETURN intersection(resolved_label_ids, config_label_ids) is non-empty
      all_of: RETURN config_label_ids is subset of resolved_label_ids
      none_of: RETURN intersection(resolved_label_ids, config_label_ids) is empty

  IF label_sources is set:
    Filter resolvedLabels to only those from specified sources before evaluating
```

### Channel-Specific Label Availability

Not all label sources are available at all enforcement channels. The runtime must handle this gracefully:

| Channel | file_metadata | email_header | hash_correlation | cloud_api | event_stream |
|---------|:---:|:---:|:---:|:---:|:---:|
| Email (gateway) | Yes | Yes | No (no file hash yet) | Latency OK | Yes |
| Email (endpoint) | Yes | Yes | Yes | Latency OK | Yes |
| USB/removable media | Yes | N/A | Yes | Too slow | Yes |
| Cloud upload (CASB) | Yes | N/A | Yes | Yes (same cloud) | Yes |
| Print | Yes | N/A | Yes | Too slow | Yes |
| Clipboard/IM | No (text only) | N/A | No | N/A | N/A |
| Web upload (proxy) | Yes (for files) | N/A | Yes | Latency OK | Yes |
| API/DLP-as-a-service | Depends on payload | N/A | Yes | Latency OK | Yes |

**Fallback behavior:** When a label source is unavailable at a channel, the rule doesn't fail — the label condition evaluates against available sources only. If no sources are available, the label condition evaluates to "unlabeled" (which matches `none_of` conditions and fails `any_of` / `gte` conditions). This fail-safe means label-dependent rules degrade to content-only enforcement when labels are unavailable, rather than silently passing.

### Performance Budget

Label evaluation must fit within the overall enforcement latency budget:

| Operation | Budget | Notes |
|-----------|--------|-------|
| File metadata parsing | <1ms | In-process, no I/O — parse document properties from already-opened file |
| Email header parsing | <0.1ms | String parsing, no I/O |
| Hash computation (SHA-256) | 1-10ms | Depends on file size; cached after first computation |
| Hash correlation cache lookup | <0.1ms | In-memory hash map |
| Cloud API call | 50-500ms | Only for latency-tolerant channels |
| Event stream cache lookup | <0.1ms | In-memory hash map |
| Normalization + mapping | <0.1ms | Pre-compiled lookup tables |
| Tier/category comparison | <0.01ms | Numeric comparison |
| **Total (embedded labels)** | **<2ms** | **Within 5ms inline enforcement budget** |
| **Total (with cloud API)** | **50-500ms** | **Only for email/cloud channels** |

### Caching Strategy

| Cache | Scope | TTL | Invalidation |
|-------|-------|-----|-------------|
| Hash correlation cache | Per-connector | 1h to 90d (configurable) | CASB re-crawl replaces entries |
| Event stream findings cache | Per-connector | 1h to 30d (configurable) | New finding replaces old for same resource |
| Cloud API response cache | Per-resource | 5m to 24h (configurable) | TTL expiry or manual purge |
| Classification mapping cache | Global | Until connector config change | Connector save triggers recompile |
| Data catalog sync cache | Per-connector | Permission: 1m-6h, Classification: 1h-7d, Schema: 6h-30d | Sync run replaces stale entries |

## 11.6 Data Catalog Integration — Labels from Structured Data Platforms

Beyond document-level labels, organizations classify data at the **dataset, table, and column level** in data platforms. DLP Composer ingests these classifications via the **DataCatalogConnector** to enable rules like "block export of data from tables tagged as PII in Snowflake."

### Supported Catalogs

| Category | Catalogs | Integration Method |
|----------|----------|-------------------|
| **Platform catalogs** (built into data platform) | AWS Glue, Snowflake, Databricks Unity | Native API / SQL queries |
| **Governance catalogs** (external metadata layer) | Collibra, Alation, Atlan, Azure Purview, Google Data Catalog, Apache Atlas, OpenMetadata | REST API |
| **Custom catalogs** | S3 manifest (JSON/JSONL/CSV/Parquet), SQL query, REST API | Configurable field mapping |

### Sync Modes

| Mode | How It Works | Latency | Use Case |
|------|-------------|---------|----------|
| `import_bulk` | Periodic full/incremental sync into local DataAsset entities | Minutes to hours | Large catalogs where real-time isn't needed |
| `realtime_api` | Query catalog API at rule evaluation time | 50-500ms | Small catalogs or critical datasets |
| `hybrid` | Bulk sync for classifications + real-time for permissions | Varies | Best balance for most deployments |

### Classification + Permission Mapping

Catalog connectors map both classifications and permissions:

```yaml
data_catalog_connector:
  catalog_type: "snowflake"

  classification_mappings:
    - catalog_classification: "PII"
      sensitivity_ref: { entity_id: "tier_confidential" }
      category_ref: { entity_id: "cat_pii" }
    - catalog_classification: "HIGHLY_SENSITIVE"
      sensitivity_ref: { entity_id: "tier_restricted" }
    - catalog_classification: "PUBLIC"
      sensitivity_ref: { entity_id: "tier_public" }

  permission_mappings:
    - catalog_permission: "OWNER"
      dlp_access_tier: "full_access"
    - catalog_permission: "SELECT"
      dlp_access_tier: "read_only"
    - catalog_permission: "USAGE"
      dlp_access_tier: "restricted"
```

This enables permission-aware rules: "User downloading data from a Restricted Snowflake table without OWNER permission → block and alert."

## 11.7 Operational Scenarios

### Scenario 1: MIP-Labeled Excel File Sent via Email

1. User creates Excel workbook, applies MIP "Confidential - Finance" label in Office
2. MIP embeds `MSIP_Label_{GUID}_Enabled=true` in OOXML custom properties
3. MIP adds `msip_labels: MSIP_Label_{GUID}...` SMTP header when user sends via Outlook
4. Email gateway DLP agent intercepts → ExternalLabelConnector (file_metadata) parses OOXML → extracts GUID
5. LabelMapping: GUID → ClassificationLabel "MIP Confidential Finance" → SensitivityTier "confidential" (level 3) + DataCategory "FINANCIAL"
6. Rule "block-confidential-pci-external" has `include_labels: gte confidential` → rule is in scope
7. Content detection runs → finds credit card numbers in cells → Luhn validates → match
8. Enforcement: BLOCK, notify user, create incident (severity: high)

### Scenario 2: Google Drive File Downloaded and Copied to USB

1. User downloads "Q3-report.xlsx" from Google Drive → Workspace label "Confidential" stripped from local file
2. CASB connector had previously crawled Drive → computed SHA-256 → cached `{hash → "Confidential"}`
3. User copies file to USB → endpoint agent intercepts
4. Agent computes SHA-256 of file → looks up hash correlation cache → hit: "Confidential"
5. LabelMapping: "Confidential" → SensitivityTier "confidential" (level 3)
6. Rule "block-confidential-usb" has `include_labels: gte confidential` → rule is in scope
7. Content detection runs → confirms PII → match
8. Enforcement: BLOCK USB copy, notify user

### Scenario 3: Unlabeled Document with Sensitive Content (Gap Detection)

1. User creates a document outside the MIP ecosystem (plain text, no label)
2. Email gateway intercepts → ExternalLabelConnector finds no embedded label
3. No label → `include_labels: gte confidential` rules skip this document (not in scope)
4. But the "unlabeled-sensitive-content" rule has `include_labels: none` (no label condition) → in scope
5. Content detection runs → finds SSN patterns → validates → match
6. Enforcement: ALERT (not block — document hasn't been classified yet)
7. Alert triggers "classify-on-send" prompt → user selects "Confidential - PII"
8. MIP applies label → DSPM lifecycle begins → future sends evaluated with label

### Scenario 4: Cross-System Rule — Label + Content + Permission

1. Analyst composes rule: "Block download of Restricted data containing SSN from Snowflake tables where user has only SELECT permission"
2. Three conditions in AND group:
   - Label: `sensitivity_tier_ref: tier_restricted, tier_operator: gte` (from Snowflake tag via DataCatalogConnector)
   - Content: `pattern_ref: regex_ssn, validator_refs: [validator_ssn_range]`
   - Permission: `dlp_access_tier: read_only` (from catalog permission mapping)
3. At enforcement: catalog sync has cached table classification + user permissions
4. User runs `SELECT * FROM sensitive_table` → DLP proxy intercepts result set
5. Label check: table tagged "RESTRICTED" in Snowflake → tier_level 4 ≥ 4 → pass
6. Content check: SSN patterns in result set → validated → pass
7. Permission check: user has SELECT → "read_only" → pass
8. All three conditions true → BLOCK download, alert DBA

## 11.8 Design Decisions and Trade-offs

### Why consume labels instead of creating them?

DLP Composer deliberately does **not** create, assign, or manage labels. DSPM tools (MIP, Macie, Purview, Titus) own the classification lifecycle — they have the ML models, the scanning infrastructure, and the admin workflows for label management. DLP Composer's job is enforcement, not classification.

**Benefit:** Changing DSPM vendor (e.g., MIP → Google Workspace labels) requires updating connector configuration, not rewriting rules. Rules reference SensitivityTier and DataCategory entities, which remain stable across DSPM vendor changes.

### Why normalize instead of matching vendor-specific labels directly?

A rule that says `mip_label == "Confidential"` breaks when the organization renames the label, adds a sub-label, or migrates to a different vendor. A rule that says `tier_level >= 3` works regardless of the label's name, source, or vendor.

**Trade-off:** Normalization introduces a mapping maintenance burden — every new vendor label must be mapped to internal tiers. Mitigated by the `unmapped_label_action: flag` setting, which ensures new labels are surfaced to admins rather than silently ignored.

### Why five read methods instead of a unified API?

Each read method exists because the underlying label storage is fundamentally different. Document-embedded labels are available at zero latency with no external dependencies. Cloud API labels require network calls. Event stream labels are asynchronous. Hash correlation solves the specific problem of labels that don't travel with files. A unified API would paper over these differences but couldn't hide the latency, availability, and trust-level implications that rule authors need to understand.

---

*Last updated: 2026-06-05*
