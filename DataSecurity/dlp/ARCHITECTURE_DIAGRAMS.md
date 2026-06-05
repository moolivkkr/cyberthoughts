# DLP Composer — Architecture Diagrams

Working drafts for the proposal document. Mermaid format for iteration.

---

## Diagram 1: The Canonical Hierarchy (Tab 1 + Tab 6.1)

The single most important visual. Shows the four-layer separation and what each layer owns.

```mermaid
graph TB
    subgraph POLICY["<b>Policy</b> — WHERE to deploy"]
        P_DESC["Assigns RuleSets to Realms/Agents<br/>Deployment mode: active, staged, disabled<br/>Policy-wide exceptions (privileged users, boilerplate stripping)"]
    end

    subgraph RULESET["<b>RuleSet</b> — HOW to organize"]
        RS_DESC["Ordered group of Rules<br/>Evaluation: first_match or all_matches<br/>Compliance purpose (PCI, HIPAA, IP protection)"]
    end

    subgraph RULE["<b>Rule</b> — WHEN to act"]
        R_SCOPE["<b>Scope:</b> WHO (users/groups) | WHERE (channels/direction)<br/>FROM (senders/apps/geo) | TO (recipients/URLs/devices)<br/>WHAT (operations) | WHEN (schedule)"]
        R_MODE["<b>Mode:</b> Analysis | Monitor | Detect | Enforce"]
        R_LABELS["<b>Label Scope:</b> IncludeLabels | ExcludeLabels"]
        R_ACTIONS["<b>Actions:</b> block | quarantine | encrypt | notify | log"]
    end

    subgraph DETECTION["<b>Detection</b> — WHAT to find"]
        D_GROUPS["<b>Groups</b> (AND/OR between groups)"]
        D_COND["<b>Conditions:</b> pattern | dictionary | proximity<br/>file_type | edm | idm | ml_classifier | classification_label"]
        D_FP["<b>FP Reduction:</b> validators | ignore expressions<br/>proximity context | negative scoring | breadth"]
        D_COMPLIANCE["<b>Compliance:</b> regulation_refs | jurisdiction<br/>data_subject_type | legal_basis"]
    end

    POLICY --> RULESET
    RULESET --> RULE
    RULE --> DETECTION

    style DETECTION fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
    style RULE fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
    style RULESET fill:#fff3e0,stroke:#e65100,stroke-width:2px
    style POLICY fill:#fce4ec,stroke:#c62828,stroke-width:2px
```

**Key message:** Each layer does ONE thing. Detection is reusable across Rules. Rules bind detection to context. RuleSets order Rules. Policy assigns to infrastructure. No vendor cleanly separates these.

---

## Diagram 2: Scope Boundaries — System Context (Tab 3)

DLP Composer's position in the ecosystem. What we consume vs produce.

```mermaid
graph LR
    subgraph PRODUCERS["<b>Classification & Identity (Producers)</b>"]
        MIP["Microsoft MIP /<br/>Purview"]
        MACIE["AWS Macie /<br/>GCP DLP"]
        DSPM["DSPM Platform<br/>(Wiz, BigID, Cyera)"]
        CATALOG["Data Catalogs<br/>(Snowflake, Glue,<br/>Databricks, Collibra)"]
        IDP["Identity Provider<br/>(Azure AD, Okta)"]
        USER_LABEL["User-Applied<br/>Labels"]
    end

    subgraph DLP["<b>DLP Composer</b>"]
        CONNECTORS["Connectors<br/>(normalize to internal entities)"]
        ENTITIES["Entity Graph<br/>(95+ entity types)"]
        ENGINE["Rule Composition<br/>Engine"]
        TRANSPILER["Transpiler"]
        TESTING["Test Framework<br/>(corpus + regression)"]
    end

    subgraph CONSUMERS["<b>Enforcement & Response (Consumers)</b>"]
        TRELLIX["Trellix DLP"]
        SYMANTEC["Broadcom<br/>Symantec DLP"]
        PROOFPOINT["Proofpoint DLP"]
        PALOALTO["Palo Alto<br/>Prisma DLP"]
        SIEM["SIEM / SOAR<br/>(incidents)"]
    end

    MIP -->|"labels"| CONNECTORS
    MACIE -->|"findings"| CONNECTORS
    DSPM -->|"classifications"| CONNECTORS
    CATALOG -->|"classifications<br/>permissions<br/>schema"| CONNECTORS
    IDP -->|"users/groups"| CONNECTORS
    USER_LABEL -->|"manual labels"| CONNECTORS

    CONNECTORS --> ENTITIES
    ENTITIES --> ENGINE
    ENGINE --> TESTING
    ENGINE --> TRANSPILER

    TRANSPILER -->|"vendor-native<br/>rules"| TRELLIX
    TRANSPILER -->|"vendor-native<br/>rules"| SYMANTEC
    TRANSPILER -->|"vendor-native<br/>rules"| PROOFPOINT
    TRANSPILER -->|"vendor-native<br/>rules"| PALOALTO
    ENGINE -->|"incidents"| SIEM

    style DLP fill:#e8eaf6,stroke:#283593,stroke-width:3px
    style PRODUCERS fill:#f3e5f5,stroke:#6a1b9a,stroke-width:1px
    style CONSUMERS fill:#e0f2f1,stroke:#00695c,stroke-width:1px
```

**Key message:** DLP Composer sits between classification systems (producers) and enforcement systems (consumers). We normalize inbound, transpile outbound. Changing any producer or consumer = update connector, not rules.

---

## Diagram 3: Seven-Layer FP Elimination Stack (Tab 6.4)

The funnel showing how each layer reduces false positives.

```mermaid
graph TB
    INPUT["<b>Content Arrives</b><br/>Email with: 'Order ref: 4532015112830366'<br/>+ boilerplate disclaimer"]

    subgraph POLICY_LEVEL["POLICY LEVEL — before detection"]
        L7["<b>Layer 7: Boilerplate Stripping</b><br/>IgnoredTextList strips 'This email is confidential...'<br/>Prevents keyword FP on every email<br/><i>Eliminates: universal noise across all detections</i>"]
    end

    subgraph DETECTION_LEVEL["DETECTION LEVEL — content analysis"]
        L1["<b>Layer 1: Pattern Match</b><br/>Regex fires on 4532015112830366<br/>Score: +10<br/><i>Without other layers, this is an alert (FP)</i>"]
        L2["<b>Layer 2: Validator</b><br/>Luhn check — does the number pass?<br/>Eliminates 30-60% of numeric FPs<br/><i>Mathematical proof of structural validity</i>"]
        L3["<b>Layer 3: Ignore Expressions</b><br/>'order ref: + digits' matches suppression pattern<br/>Match subtracted — score drops to 0<br/><i>Surgical removal of known FP patterns</i>"]
        L4["<b>Layer 4: Proximity Context</b><br/>No financial keywords within 300 chars<br/>'tracking page for delivery' ≠ financial context<br/><i>No context = no detection</i>"]
        L5["<b>Layer 5: Negative Scoring</b><br/>'tracking' (-8) + 'delivery' (-8) = -16<br/>Aggregate: +10 - 16 = -6 (below threshold)<br/><i>Counter-indicators actively suppress score</i>"]
    end

    subgraph SCOPE_LEVEL["SCOPE LEVEL — after detection"]
        L6["<b>Layer 6: Rule Scope Exclusions</b><br/>Sender in excluded list (automated logistics)<br/>Match is real but context is legitimate<br/><i>Detection correct, enforcement not needed</i>"]
    end

    RESULT["<b>Result: No Alert</b><br/>6 independent layers caught this FP<br/>In vendor tools: only Layer 1 exists → false alert"]

    INPUT --> L7
    L7 --> L1
    L1 --> L2
    L2 --> L3
    L3 -->|"CAUGHT HERE"| RESULT
    L3 -.->|"if not caught"| L4
    L4 -.->|"if not caught"| L5
    L5 -.->|"if not caught"| L6
    L6 -.-> RESULT

    style POLICY_LEVEL fill:#fff3e0,stroke:#e65100,stroke-width:2px
    style DETECTION_LEVEL fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
    style SCOPE_LEVEL fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
    style RESULT fill:#c8e6c9,stroke:#2e7d32,stroke-width:3px
    style INPUT fill:#ffebee,stroke:#c62828,stroke-width:2px
```

**Key message:** Six independent chances to catch a false positive. Each layer operates at a different architectural level. In vendor tools, you get Layer 1 (regex) and maybe a manual exception list. Everything else is missing.

---

## Diagram 4: Label Flow Architecture (Tab 6.5)

How external labels flow into rule composition.

```mermaid
graph LR
    subgraph SOURCES["<b>Label Sources</b>"]
        S1["<b>Document Embedded</b><br/>MIP metadata<br/>S3 tags<br/>Email X-headers<br/><i>Highest trust, zero latency</i>"]
        S2["<b>Cloud Platforms</b><br/>AWS Macie findings<br/>GCP DLP findings<br/>Azure Purview<br/><i>High trust, cached</i>"]
        S3["<b>Data Catalogs</b><br/>Snowflake / Glue /<br/>Databricks / Collibra<br/><i>Medium trust, synced</i>"]
        S4["<b>User Applied</b><br/>Manual classification<br/>Classify-on-save prompts<br/><i>Variable trust</i>"]
    end

    subgraph NORMALIZE["<b>Normalization Layer</b>"]
        ELC["ExternalLabel<br/>Connector<br/>(12 label systems)"]
        DCC["DataCatalog<br/>Connector<br/>(12+ catalogs)"]
        RESOLVE["<b>Resolution</b><br/>Vendor label →<br/>SensitivityTier +<br/>DataCategory<br/><br/>Conflict: highest<br/>sensitivity wins"]
    end

    subgraph INTERNAL["<b>Internal Entities</b>"]
        TIER["<b>SensitivityTier</b><br/>Public (1) → Internal (2)<br/>→ Confidential (3)<br/>→ Restricted (4)<br/>→ Top Secret (5)<br/><br/>Cross-framework:<br/>ISO 27001 / FIPS 199<br/>PSPF / NATO"]
        CAT["<b>DataCategory</b><br/>PII → PII_Direct → SSN<br/>PII → PII_Indirect → IP<br/>PCI → payment_card<br/>PHI → medical_record<br/><br/>Hierarchical tree<br/>with regulation refs"]
    end

    subgraph RULES["<b>Rule Composition</b>"]
        DET_COND["<b>Detection Condition</b><br/>LabelCondition in group<br/>• Tier comparison (>=)<br/>• Category hierarchy<br/>• Source filtering"]
        RULE_SCOPE["<b>Rule Scope</b><br/>IncludeLabels /<br/>ExcludeLabels<br/>Pre-filter before<br/>detection runs"]
    end

    S1 --> ELC
    S2 --> ELC
    S3 --> DCC
    S4 --> ELC
    ELC --> RESOLVE
    DCC --> RESOLVE
    RESOLVE --> TIER
    RESOLVE --> CAT
    TIER --> DET_COND
    TIER --> RULE_SCOPE
    CAT --> DET_COND
    CAT --> RULE_SCOPE

    style SOURCES fill:#f3e5f5,stroke:#6a1b9a,stroke-width:1px
    style NORMALIZE fill:#fff3e0,stroke:#e65100,stroke-width:2px
    style INTERNAL fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
    style RULES fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
```

**Key message:** Labels from ANY source normalize to the same two internal entities (SensitivityTier + DataCategory). Rules reference internal entities, never vendor strings. Change your DSPM vendor = update connector, not rules.

---

## Diagram 5: Transpiler Pipeline (Tab 6.10 + Tab 8)

How canonical rules fan out to vendor-specific formats.

```mermaid
graph LR
    subgraph CANONICAL["<b>Canonical Model</b><br/>(single source of truth)"]
        DET["Detection<br/><i>PCI Credit Card</i><br/>pattern + luhn + proximity"]
        RULE_C["Rule<br/><i>Email Outbound Block</i><br/>channels + scope + mode"]
        ENT["Referenced Entities<br/><i>pat_visa_mc, val_luhn,<br/>dict_financial, ug_all_users</i>"]
    end

    subgraph TRANSPILE["<b>Transpilation</b>"]
        RESOLVE_E["Entity<br/>Resolution<br/><i>refs → inline or<br/>vendor object IDs</i>"]
        VENDOR_IR["Vendor IR<br/><i>vendor-specific<br/>abstract syntax tree</i>"]
        FIDELITY["Fidelity<br/>Report<br/><i>per-condition<br/>classification</i>"]
    end

    subgraph TRELLIX_OUT["<b>Trellix Output</b>"]
        T_CLASS["Classification<br/><i>Advanced Pattern +<br/>Luhn Validator</i>"]
        T_RULE["Rule + Reaction<br/><i>Email vector,<br/>Prevent action</i>"]
        T_FIDELITY["LOSSLESS"]
    end

    subgraph PROOFPOINT_OUT["<b>Proofpoint Output</b>"]
        P_DET["Smart Identifier<br/><i>Custom Detector +<br/>Luhn checksum</i>"]
        P_RULE["DLP Rule + Action<br/><i>Email DLP,<br/>Block delivery</i>"]
        P_FIDELITY["LOSSLESS"]
    end

    subgraph SYMANTEC_OUT["<b>Symantec Output</b>"]
        S_DET["Detection Rule<br/><i>Content Matches +<br/>Validator</i>"]
        S_RULE["Policy Rule +<br/>Response Rule<br/><i>Server detection,<br/>Block action</i>"]
        S_FIDELITY["ADAPTED<br/><i>proximity distance<br/>fixed at 200 chars<br/>(ours: 300)</i>"]
    end

    DET --> RESOLVE_E
    RULE_C --> RESOLVE_E
    ENT --> RESOLVE_E
    RESOLVE_E --> VENDOR_IR
    VENDOR_IR --> FIDELITY

    FIDELITY --> T_CLASS
    FIDELITY --> P_DET
    FIDELITY --> S_DET

    T_CLASS --- T_RULE
    T_RULE --- T_FIDELITY
    P_DET --- P_RULE
    P_RULE --- P_FIDELITY
    S_DET --- S_RULE
    S_RULE --- S_FIDELITY

    style CANONICAL fill:#e8eaf6,stroke:#283593,stroke-width:3px
    style TRANSPILE fill:#fff3e0,stroke:#e65100,stroke-width:2px
    style TRELLIX_OUT fill:#e8f5e9,stroke:#2e7d32,stroke-width:1px
    style PROOFPOINT_OUT fill:#e8f5e9,stroke:#2e7d32,stroke-width:1px
    style SYMANTEC_OUT fill:#fff9c4,stroke:#f57f17,stroke-width:1px
```

**Key message:** Write once, transpile to any vendor. Each vendor output includes a fidelity report — the author knows BEFORE committing what translates losslessly vs what degrades. Symantec example shows "ADAPTED" — functionally equivalent but with a structural difference (proximity window).

---

## Diagram 6: FP Optimization — Workflow 1: User-Driven Feedback Loop (Tab 10.1)

Per-incident flow: analyst marks FP → system recommends suppression labels → analyst approves → immediate enforcement.

```mermaid
graph TB
    subgraph INCIDENT["<b>1. Incident</b>"]
        BLOCK["DLP BLOCKS content<br/>FastLane: pattern match<br/>Score above threshold"]
    end

    subgraph ANALYST["<b>2. Analyst Review</b>"]
        REVIEW["Analyst opens incident<br/>Reviews blocked content<br/>Marks as FALSE POSITIVE"]
        VERDICT["Verdict stored:<br/>• analyst_verdict: false_positive<br/>• analyst_notes<br/>• time_to_review<br/>• training_eligible: true"]
    end

    subgraph RECOMMEND["<b>3. Recommendation Engine</b><br/><i>Three algorithms run in parallel</i>"]
        ALG1["<b>Near-Miss Labels</b><br/>Extract context tokens<br/>Compare vs existing labels<br/>Root-word + edit distance<br/><br/><i>Medium confidence</i><br/>'order ref' similar to<br/>existing 'order number'"]
        ALG2["<b>Proximity Labels</b><br/>Extract phrase immediately<br/>before the match (40 chars)<br/><br/><i>High confidence</i><br/>'job token:' precedes<br/>the matched digits"]
        ALG3["<b>KB Cross-Entity</b><br/>Labels already human-approved<br/>for other entity types<br/>that appear in this context<br/><br/><i>Highest confidence</i><br/>'customer id' approved<br/>for SSN, found near CC"]
    end

    subgraph APPROVE["<b>4. Human-in-the-Loop Approval</b>"]
        PRESENT["Each suggestion shown with:<br/>• candidate label + reason<br/>• context snippet<br/>• source signal<br/>• similar existing label"]
        DECISION["Analyst: APPROVE /<br/>MODIFY / REJECT<br/>per suggestion"]
    end

    subgraph UPDATE["<b>5. Three-Store Atomic Update</b>"]
        FAST["<b>FastLane Runtime</b><br/>Hot-reload to in-process<br/>memory — immediate effect<br/>on next scan"]
        LEARNED["<b>Learned Labels Mirror</b><br/>Future suggestions<br/>reflect new label<br/>(no duplicates)"]
        OPA["<b>OPA Policy Store</b><br/>Durable audit trail<br/>Hydrated on startup<br/>Who approved, when"]
    end

    RESULT["Next scan with same<br/>context pattern →<br/><b>NO FALSE POSITIVE</b><br/><br/>Label: 'job token'<br/>confidence_delta: -1.0<br/>action: disqualify"]

    BLOCK --> REVIEW
    REVIEW --> VERDICT
    VERDICT --> ALG1
    VERDICT --> ALG2
    VERDICT --> ALG3
    ALG1 --> PRESENT
    ALG2 --> PRESENT
    ALG3 --> PRESENT
    PRESENT --> DECISION
    DECISION -->|"APPROVED"| FAST
    DECISION -->|"APPROVED"| LEARNED
    DECISION -->|"APPROVED"| OPA
    FAST --> RESULT
    LEARNED -.->|"informs future<br/>suggestions"| ALG1
    OPA -.->|"hydrated<br/>on restart"| FAST

    style INCIDENT fill:#ffebee,stroke:#c62828,stroke-width:2px
    style ANALYST fill:#fff3e0,stroke:#e65100,stroke-width:2px
    style RECOMMEND fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
    style APPROVE fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
    style UPDATE fill:#f3e5f5,stroke:#6a1b9a,stroke-width:2px
    style RESULT fill:#c8e6c9,stroke:#2e7d32,stroke-width:3px
```

**Key message:** Every analyst FP verdict becomes a learning opportunity. The system doesn't just log the verdict — it analyzes the content, recommends specific suppression labels, and applies them immediately on approval. No rule editing, no redeployment, no restart.

---

## Diagram 7: FP Optimization — Workflow 2: ML Clustering Pipeline (Tab 10.2)

Batch flow: accumulated FP data → clustering → systemic suppression discovery → human review.

```mermaid
graph TB
    subgraph COLLECT["<b>1. FP Corpus Accumulation</b>"]
        SRC1["Analyst verdicts<br/>(false_positive)"]
        SRC2["ML downgrades<br/>(MidLane DOWNGRADE)"]
        SRC3["Luhn failures<br/>(structural FP)"]
        STORE["ClickHouse<br/>dlp_decisions table<br/><br/>Per-record:<br/>entity_type, context tokens,<br/>channel, content structure,<br/>temporal features, source"]
    end

    subgraph EXTRACT["<b>2. Feature Extraction</b>"]
        F1["Context tokens<br/>(1-3 word phrases<br/>from surrounding text)"]
        F2["Entity type<br/>+ sub-type"]
        F3["Channel + structure<br/>(email header, table cell,<br/>code block, URL, etc.)"]
        F4["Temporal features<br/>(time of day, day of week,<br/>recurring patterns)"]
    end

    subgraph CLUSTER["<b>3. Unsupervised Clustering</b>"]
        C1["<b>TF-IDF + K-Means</b><br/>on context tokens<br/><br/>Groups FPs with same<br/>surrounding text<br/><br/>Centroid = candidate<br/>suppression label"]
        C2["<b>DBSCAN</b><br/>on temporal-channel<br/><br/>Detects recurring<br/>FP bursts (batch jobs,<br/>scheduled reports)<br/><br/>Candidate: time/source<br/>scope exclusion"]
        C3["<b>Hierarchical</b><br/>on entity + context<br/><br/>Cross-entity labels<br/>('reference' triggers FPs<br/>for SSN, CC, and phone)<br/><br/>Candidate: global<br/>suppression rule"]
    end

    subgraph CROSSREF["<b>4. Cross-Reference Existing Suppressors</b>"]
        EXISTING["pattern_fp_labels.json<br/>(1,000+ rules)"]
        LEARNED_L["OPA learned labels"]
        KB["Cross-entity<br/>approval history"]
        GAP["Gap identification:<br/>'order number' and 'order ref'<br/>suppressed, but 'order id'<br/>appears in 47 FPs"]
    end

    subgraph OUTPUT["<b>5. Recommendation Report</b>"]
        REC["Per cluster (threshold: 10+ FPs):<br/><br/>• Candidate label<br/>• Evidence count (234 FPs)<br/>• Affected rules<br/>• Similar existing labels<br/>• Estimated FP reduction<br/>• Confidence level"]
    end

    subgraph REVIEW_B["<b>6. Human Batch Review</b>"]
        TEAM["Security team reviews<br/>weekly FP Optimization Report<br/><br/>Approve / reject in batch"]
        APPLY["Approved labels →<br/>Three-store update<br/>(same as Workflow 1)"]
    end

    SRC1 --> STORE
    SRC2 --> STORE
    SRC3 --> STORE
    STORE --> F1
    STORE --> F2
    STORE --> F3
    STORE --> F4
    F1 --> C1
    F2 --> C3
    F3 --> C2
    F4 --> C2
    F1 --> C3
    C1 --> CROSSREF
    C2 --> CROSSREF
    C3 --> CROSSREF
    EXISTING --> GAP
    LEARNED_L --> GAP
    KB --> GAP
    GAP --> REC
    REC --> TEAM
    TEAM --> APPLY

    style COLLECT fill:#ffebee,stroke:#c62828,stroke-width:2px
    style EXTRACT fill:#fff3e0,stroke:#e65100,stroke-width:2px
    style CLUSTER fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
    style CROSSREF fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
    style OUTPUT fill:#f3e5f5,stroke:#6a1b9a,stroke-width:2px
    style REVIEW_B fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
```

**Key message:** Individual analysts see one FP at a time. Clustering sees patterns across thousands — "badge number" appears in 234 SSN FPs but isn't in the suppression list. No individual analyst would notice this. The system surfaces it with evidence for batch approval.

---

## Diagram 8: FP Maturity Staircase — Three Levels (Tab 10.3)

Progressive automation from fully manual to autonomous with guardrails.

```mermaid
graph LR
    subgraph L1["<b>Level 1: Manual + Recommendations</b><br/><i>Implemented</i>"]
        L1_IN["Analyst marks FP"]
        L1_REC["System recommends<br/>suppression labels<br/>(3 algorithms)"]
        L1_APP["Analyst approves<br/>each label"]
        L1_EFF["Immediate effect<br/>via hot-reload"]

        L1_IN --> L1_REC --> L1_APP --> L1_EFF
    end

    subgraph L2["<b>Level 2: ML-Assisted Clustering</b><br/><i>Designed</i>"]
        L2_IN["FP corpus<br/>accumulates"]
        L2_ML["Clustering finds<br/>systemic patterns"]
        L2_REP["Weekly report<br/>with evidence"]
        L2_BATCH["Team reviews<br/>in batch"]

        L2_IN --> L2_ML --> L2_REP --> L2_BATCH
    end

    subgraph L3["<b>Level 3: Autonomous + Guardrails</b><br/><i>Vision</i>"]
        L3_IN["High-confidence<br/>signals only"]
        L3_AUTO["Auto-apply with<br/>24h rollback window"]
        L3_AUDIT["Flagged in<br/>audit log"]
        L3_REV["Review by<br/>exception only"]

        L3_IN --> L3_AUTO --> L3_AUDIT --> L3_REV
    end

    L1 -->|"corpus grows"| L2
    L2 -->|"confidence<br/>calibrated"| L3

    style L1 fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
    style L2 fill:#fff3e0,stroke:#e65100,stroke-width:2px
    style L3 fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
```

**Key message:** Start conservative (every label needs human approval), graduate to batch review (weekly clustering reports), then selective autonomy (only highest-confidence patterns auto-apply). Each level builds on the data and trust from the previous one.

---

## Diagram 9: FP Feedback Data Architecture (Tab 10.4)

End-to-end data flow from production scan to ML retraining.

```mermaid
graph TB
    subgraph SCAN["<b>Production Scan</b>"]
        FL["FastLane<br/>Pattern + Validator + Suppression"]
        ML_LANE["MidLane<br/>ML Classification"]
        DL["DeepLane<br/>(if escalated)"]
        FL --> ML_LANE --> DL
    end

    subgraph RECORD["<b>Retroactive Decision Record</b><br/><i>ClickHouse (append-only, partitioned)</i>"]
        FIELDS["retro_action_id · original_event_id<br/>analyst_verdict · analyst_notes<br/>time_to_review · training_eligible<br/>policy_gap_identified · new_rule_suggested"]
    end

    subgraph WF1["<b>Workflow 1</b><br/>Per-Incident"]
        SUGGEST["Suggestion Engine<br/>(near-miss, proximity, KB)"]
        APPROVE_1["Analyst approves"]
    end

    subgraph WF2["<b>Workflow 2</b><br/>Batch ML"]
        CLUSTER_2["Clustering Pipeline<br/>(K-Means, DBSCAN,<br/>Hierarchical)"]
        REPORT["Weekly report"]
        APPROVE_2["Team reviews"]
    end

    subgraph STORES["<b>Three-Store Update</b>"]
        S1_FAST["FastLane<br/>Runtime Overlay<br/><i>immediate</i>"]
        S2_LEARN["Learned Labels<br/>Mirror<br/><i>in-memory</i>"]
        S3_OPA["OPA Policy<br/>Store<br/><i>durable</i>"]
    end

    subgraph RETRAIN["<b>ML Retraining Pipeline</b>"]
        WEEKLY["Weekly batch retrain<br/>(SLM fine-tuning via LoRA)"]
        DAILY["Daily micro-updates<br/>(confidence thresholds)"]
        DRIFT["Drift detection<br/>(per-rule FP rate<br/>time series)"]
    end

    SCAN --> RECORD
    RECORD --> WF1
    RECORD --> WF2
    WF1 --> APPROVE_1 --> STORES
    WF2 --> REPORT --> APPROVE_2 --> STORES
    RECORD --> RETRAIN
    STORES --> |"enriched<br/>suppression<br/>corpus"| FL
    RETRAIN --> |"updated<br/>model"| ML_LANE
    DRIFT --> |"alert if FP rate<br/>exceeds 2x<br/>30-day average"| REPORT

    style SCAN fill:#ffebee,stroke:#c62828,stroke-width:2px
    style RECORD fill:#fff3e0,stroke:#e65100,stroke-width:2px
    style WF1 fill:#e8f5e9,stroke:#2e7d32,stroke-width:1px
    style WF2 fill:#e8f5e9,stroke:#2e7d32,stroke-width:1px
    style STORES fill:#f3e5f5,stroke:#6a1b9a,stroke-width:2px
    style RETRAIN fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
```

**Key message:** Two feedback loops — one fast (per-incident, minutes), one deep (batch clustering, weekly). Both feed the same three-store update. Drift detection monitors for rules getting worse over time. The system gets measurably better with every analyst interaction.

---

## Diagram 10: Label Integration — Connector Sync Architecture (Tab 11.2)

How external label sources connect to DLP Composer through five read methods.

```mermaid
graph TB
    subgraph SOURCES["<b>External Label Sources</b>"]
        MIP_DOC["<b>MIP / Titus / BJ</b><br/>Document-embedded<br/>OOXML properties<br/>PDF XMP metadata"]
        MIP_EMAIL["<b>MIP / PSPF / Titus</b><br/>Email headers<br/>msip_labels<br/>X-Protective-Marking"]
        GOOGLE["<b>Google Workspace</b><br/>Drive Labels API<br/>(label does NOT travel<br/>with downloaded file)"]
        CLOUD_SEC["<b>AWS Macie / GCP DLP<br/>Azure Purview</b><br/>Async scan findings"]
        CATALOGS["<b>Data Catalogs</b><br/>Snowflake tags<br/>Glue / Databricks<br/>Collibra / Alation"]
    end

    subgraph CONNECTORS["<b>ExternalLabelConnector + DataCatalogConnector</b>"]
        RM1["<b>file_metadata</b><br/>Parse OOXML custom props<br/>Parse PDF XMP<br/>Parse bjDocumentSecurityLabel<br/><br/><i>Zero latency, in-process</i><br/><i>No external dependency</i>"]
        RM2["<b>email_header</b><br/>Parse SMTP header value<br/>Format: mip_semicolon /<br/>pspf_key_value / titus_plain<br/><br/><i>Zero latency, in-process</i>"]
        RM3["<b>hash_correlation</b><br/>CASB crawls Drive →<br/>computes SHA-256 → caches<br/>{hash → label}<br/><br/>Agent hashes file →<br/>cache lookup (<0.1ms)<br/><br/><i>TTL: 1h–90d</i><br/><i>Miss action: allow/block/</i><br/><i>query_api/apply_default</i>"]
        RM4["<b>event_stream</b><br/>Subscribe: EventBridge /<br/>Pub/Sub / Event Grid<br/><br/>Parse finding → cache as<br/>{resource_id → label}<br/><br/><i>TTL: 1h–30d</i><br/><i>Async, minutes delay</i>"]
        RM5["<b>DataCatalogConnector</b><br/><br/><b>Bulk sync:</b><br/>Periodic full/incremental<br/>into DataAsset entities<br/><br/><b>Realtime API:</b><br/>Query at evaluation time<br/><br/><b>Hybrid:</b><br/>Bulk for classifications +<br/>real-time for permissions<br/><br/><i>13 catalog types</i>"]
    end

    MIP_DOC --> RM1
    MIP_EMAIL --> RM2
    GOOGLE --> RM3
    CLOUD_SEC --> RM4
    CATALOGS --> RM5

    subgraph NORMALIZE["<b>Normalization</b>"]
        MAPPING["<b>LabelMapping</b><br/>source_label_id →<br/>SensitivityTier +<br/>DataCategory<br/><br/>match_type: exact /<br/>contains / regex /<br/>starts_with<br/><br/>priority: integer"]
        CONFLICT["<b>Conflict Resolution</b><br/>highest_sensitivity_wins<br/>most_recent_wins<br/>connector_priority<br/><br/>unmapped → flag / ignore /<br/>apply_default"]
    end

    RM1 --> MAPPING
    RM2 --> MAPPING
    RM3 --> MAPPING
    RM4 --> MAPPING
    RM5 --> MAPPING
    MAPPING --> CONFLICT

    subgraph INTERNAL["<b>Internal Entities</b>"]
        TIER["<b>SensitivityTier</b><br/>Public (1) → Internal (2)<br/>→ Confidential (3)<br/>→ Restricted (4)<br/>→ Top Secret (5)<br/><br/>Cross-framework mapping"]
        CAT["<b>DataCategory</b><br/>Hierarchical tree<br/>PII → PII_Direct → SSN<br/>PCI → payment_card<br/>PHI → medical_record<br/><br/>Regulation refs + jurisdiction"]
    end

    CONFLICT --> TIER
    CONFLICT --> CAT

    style SOURCES fill:#f3e5f5,stroke:#6a1b9a,stroke-width:1px
    style CONNECTORS fill:#fff3e0,stroke:#e65100,stroke-width:2px
    style NORMALIZE fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
    style INTERNAL fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
```

**Key message:** Five read methods exist because label storage is fundamentally different across sources. Document-embedded labels have zero latency. Cloud labels need caching. Google labels need hash correlation because they don't travel with downloaded files. Each connector encapsulates the complexity — the rule engine only sees normalized SensitivityTier + DataCategory.

---

## Diagram 11: Label Runtime Enforcement Pipeline (Tab 11.5)

Six-stage pipeline from content interception to enforcement action, showing where labels are evaluated.

```mermaid
graph TB
    subgraph STAGE1["<b>Stage 1: Interception</b>"]
        CHANNELS["Content arrives at enforcement point:<br/>Email gateway · Endpoint agent · Cloud proxy<br/>USB intercept · Print spooler · IM paste"]
    end

    subgraph STAGE2["<b>Stage 2: Label Extraction</b><br/><i>Per active ExternalLabelConnector</i>"]
        EX_FILE["file_metadata<br/>→ Parse doc props<br/><i>&lt;1ms</i>"]
        EX_EMAIL["email_header<br/>→ Parse SMTP hdrs<br/><i>&lt;0.1ms</i>"]
        EX_HASH["hash_correlation<br/>→ SHA-256 + cache<br/><i>1-10ms</i>"]
        EX_API["cloud_api<br/>→ API call<br/><i>50-500ms</i>"]
        EX_EVENT["event_stream<br/>→ Cache lookup<br/><i>&lt;0.1ms</i>"]
        RAW["Raw labels<br/>per source"]

        EX_FILE --> RAW
        EX_EMAIL --> RAW
        EX_HASH --> RAW
        EX_API --> RAW
        EX_EVENT --> RAW
    end

    subgraph STAGE3["<b>Stage 3: Normalization</b>"]
        NORM["LabelMapping resolution<br/>Conflict resolution<br/><br/>Result: resolved<br/>sensitivity_tier +<br/>data_categories[]<br/><i>&lt;0.1ms</i>"]
    end

    subgraph STAGE4["<b>Stage 4: Label Scope Pre-Filter</b><br/><i>Eliminates rules early — saves processing</i>"]
        INCLUDE["include_labels:<br/>Rule only applies if<br/>label matches (e.g. ≥ Confidential)"]
        EXCLUDE["exclude_labels:<br/>Rule skips if label<br/>matches (e.g. = Public)"]
        FILTER_RESULT["Filtered rule set<br/>(only applicable rules<br/>proceed to detection)"]

        INCLUDE --> FILTER_RESULT
        EXCLUDE --> FILTER_RESULT
    end

    subgraph STAGE5["<b>Stage 5: Content Detection</b><br/><i>Only for surviving rules</i>"]
        PATTERN["Pattern matching<br/>(Vectorscan DFA)<br/><i>&lt;5ms</i>"]
        VALIDATE["Validators<br/>(Luhn, Mod97, SSN)"]
        SUPPRESS["Suppression +<br/>proximity + scoring"]
        LABEL_COND["<b>Label conditions</b><br/>evaluated alongside<br/>content conditions<br/><br/>tier_operator: ≥, ≤, =<br/>category_match_children<br/>source filtering"]
        VERDICT["Detection verdict<br/>per rule"]

        PATTERN --> VALIDATE --> SUPPRESS --> LABEL_COND --> VERDICT
    end

    subgraph STAGE6["<b>Stage 6: Enforcement</b>"]
        ACTION["Highest-severity matching<br/>rule determines action:<br/><br/>block &gt; quarantine &gt; encrypt<br/>&gt; redact &gt; alert &gt; log"]
    end

    STAGE1 --> STAGE2
    RAW --> NORM
    NORM --> INCLUDE
    NORM --> EXCLUDE
    FILTER_RESULT --> PATTERN
    NORM -->|"resolved labels<br/>available to"| LABEL_COND
    VERDICT --> ACTION

    style STAGE1 fill:#ffebee,stroke:#c62828,stroke-width:2px
    style STAGE2 fill:#fff3e0,stroke:#e65100,stroke-width:2px
    style STAGE3 fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
    style STAGE4 fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
    style STAGE5 fill:#f3e5f5,stroke:#6a1b9a,stroke-width:2px
    style STAGE6 fill:#c8e6c9,stroke:#2e7d32,stroke-width:3px
```

**Key message:** Labels are evaluated twice — once at Stage 4 (scope pre-filter, eliminates rules early) and once at Stage 5 (as detection conditions alongside content matching). This two-pass design means expensive content detection only runs on documents that pass the label filter. A "Confidential+ PCI" rule skips all Public documents at Stage 4 — no regex, no ML, no processing.

---

## Diagram 12: Label Channel Availability Matrix (Tab 11.5)

Which label read methods are available at each enforcement channel.

```mermaid
graph LR
    subgraph METHODS["<b>Label Read Methods</b>"]
        M_FILE["file_metadata<br/><i>&lt;1ms</i>"]
        M_EMAIL["email_header<br/><i>&lt;0.1ms</i>"]
        M_HASH["hash_correlation<br/><i>1-10ms</i>"]
        M_API["cloud_api<br/><i>50-500ms</i>"]
        M_EVENT["event_stream<br/><i>&lt;0.1ms</i>"]
    end

    subgraph FAST_CH["<b>Latency-Sensitive Channels</b><br/><i>Budget: &lt;5ms inline</i>"]
        USB["USB / Removable"]
        PRINT["Print"]
        CLIP["Clipboard / IM"]
    end

    subgraph TOLERANT_CH["<b>Latency-Tolerant Channels</b><br/><i>Budget: &lt;500ms</i>"]
        EMAIL_GW["Email Gateway"]
        EMAIL_EP["Email Endpoint"]
        CLOUD["Cloud Upload (CASB)"]
        WEB["Web Upload (Proxy)"]
        API_CH["API / DLP-as-a-Service"]
    end

    M_FILE -->|"✓"| USB
    M_FILE -->|"✓"| PRINT
    M_FILE -->|"✓"| EMAIL_GW
    M_FILE -->|"✓"| EMAIL_EP
    M_FILE -->|"✓"| CLOUD
    M_FILE -->|"✓"| WEB

    M_EMAIL -->|"✓"| EMAIL_GW
    M_EMAIL -->|"✓"| EMAIL_EP

    M_HASH -->|"✓"| USB
    M_HASH -->|"✓"| PRINT
    M_HASH -->|"✓"| EMAIL_EP
    M_HASH -->|"✓"| CLOUD
    M_HASH -->|"✓"| WEB
    M_HASH -->|"✓"| API_CH

    M_API -->|"✓"| EMAIL_GW
    M_API -->|"✓"| EMAIL_EP
    M_API -->|"✓"| CLOUD
    M_API -->|"✓"| WEB
    M_API -->|"✓"| API_CH

    M_EVENT -->|"✓"| USB
    M_EVENT -->|"✓"| PRINT
    M_EVENT -->|"✓"| EMAIL_GW
    M_EVENT -->|"✓"| EMAIL_EP
    M_EVENT -->|"✓"| CLOUD
    M_EVENT -->|"✓"| WEB
    M_EVENT -->|"✓"| API_CH

    style METHODS fill:#fff3e0,stroke:#e65100,stroke-width:2px
    style FAST_CH fill:#ffebee,stroke:#c62828,stroke-width:2px
    style TOLERANT_CH fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
```

**Key message:** Latency-sensitive channels (USB, print) can only use zero-latency methods (file_metadata, hash_correlation, event_stream cache). Cloud API calls are reserved for channels where 50-500ms latency is acceptable (email, cloud upload). When a label source is unavailable at a channel, the rule degrades gracefully to content-only enforcement rather than failing.

---

## Diagram 13: Label Operational Scenario — Google Drive to USB (Tab 11.7)

End-to-end walkthrough: Google Workspace label → hash correlation → USB enforcement.

```mermaid
sequenceDiagram
    participant GDrive as Google Drive
    participant CASB as CASB Connector
    participant Cache as Hash Correlation Cache
    participant User as End User
    participant Agent as Endpoint DLP Agent
    participant Engine as Rule Engine

    Note over GDrive,CASB: Pre-caching phase (background, periodic)
    GDrive->>CASB: Drive API: list files + labels
    CASB->>CASB: Hash each file (SHA-256)
    CASB->>Cache: Store {hash → label, tier, category, TTL}
    Note over Cache: "a1b2c3..." → Confidential, FINANCIAL

    Note over User,Engine: Enforcement phase (real-time)
    GDrive->>User: Download "Q3-report.xlsx"
    Note over User: Google label STRIPPED from local file

    User->>Agent: Copy to USB drive
    Agent->>Agent: Compute SHA-256 of file
    Agent->>Cache: Lookup hash "a1b2c3..."
    Cache-->>Agent: HIT: Confidential, FINANCIAL

    Agent->>Engine: Evaluate rules with resolved label
    Note over Engine: Stage 4: include_labels ≥ Confidential → IN SCOPE
    Note over Engine: Stage 5: Pattern match → CC numbers found → Luhn valid
    Engine-->>Agent: BLOCK (Confidential + PCI content)

    Agent-->>User: ⛔ USB copy blocked<br/>Reason: Confidential document<br/>containing payment card data
```

**Key message:** The Google Workspace label doesn't travel with the downloaded file — but hash correlation preserves it. The user sees a seamless enforcement experience: the DLP agent knows the file is "Confidential - Financial" even though the label is no longer embedded in the local copy.

---

## Diagram 14: Label Normalization — Multi-Source Conflict Resolution (Tab 11.3)

What happens when the same document has labels from multiple sources that disagree.

```mermaid
graph TB
    subgraph SOURCES_IN["<b>Same Document — Three Label Sources</b>"]
        SRC_MIP["<b>MIP (file_metadata)</b><br/>Label: 'Internal'<br/>Tier level: 2<br/><br/><i>User applied 2 weeks ago</i>"]
        SRC_MACIE["<b>AWS Macie (event_stream)</b><br/>Finding: severity HIGH<br/>Category: FINANCIAL + PII<br/><br/><i>Automated scan yesterday</i>"]
        SRC_USER["<b>User-Applied (manual)</b><br/>Label: 'Public'<br/>Tier level: 1<br/><br/><i>User clicked 'Public'<br/>at classify-on-save</i>"]
    end

    subgraph RESOLVE_S["<b>Conflict Resolution</b>"]
        STRAT["Strategy: <b>highest_sensitivity_wins</b><br/>(default — fail-safe)"]
        COMPARE["Compare tier levels:<br/>MIP: Internal (2)<br/>Macie: HIGH → Restricted (4)<br/>User: Public (1)<br/><br/><b>Winner: Macie → Restricted (4)</b>"]
    end

    subgraph RESULT_S["<b>Resolved Labels</b>"]
        FINAL_TIER["<b>SensitivityTier:</b> Restricted (4)<br/><i>From Macie — highest</i>"]
        FINAL_CAT["<b>DataCategories:</b><br/>FINANCIAL (from Macie)<br/>PII (from Macie)<br/><i>Merged from all sources</i>"]
        FLAG["<b>Discrepancy flag:</b><br/>User labeled 'Public' but<br/>automated scan found 'Restricted'<br/>→ admin review queue"]
    end

    SRC_MIP --> STRAT
    SRC_MACIE --> STRAT
    SRC_USER --> STRAT
    STRAT --> COMPARE
    COMPARE --> FINAL_TIER
    COMPARE --> FINAL_CAT
    COMPARE --> FLAG

    style SOURCES_IN fill:#fff3e0,stroke:#e65100,stroke-width:2px
    style RESOLVE_S fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
    style RESULT_S fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
```

**Key message:** highest_sensitivity_wins is the fail-safe default — over-protect, never under-protect. When a user labels something "Public" but Macie finds PII and financial data, the system treats it as Restricted AND flags the discrepancy for admin review. The user's label isn't silently trusted when automated classification disagrees.

---

## Additional Diagrams (to add in second pass)

| # | Diagram | Tab | Format |
|---|---------|-----|--------|
| 15 | Entity Composition Graph (SSN example) | 6.2 | Entity-relationship diagram showing Pattern, Validator, Dictionary, Regulation entities with reference arrows |
| 16 | Authoring Experience Flow | 6.6 | 5-step loop: edit → preview → AI recommend → accept → validate |
| 17 | Testing Pipeline (dual engine) | 6.7 | Two swim lanes: browser (WASM) vs CI (Vectorscan) |
| 18 | Production Feedback Loop | 6.7 | Circular: deploy → match → classify → corpus grows → improve → redeploy |
| 19 | A/M/E/D Mode Progression | 6.9 | State machine: A → M → D → E with time-in-mode |
| 20 | Challenge Causal Chain | 2 | Monolithic → fragmentation → no reuse → no testing → FPs → program failure |
| 21 | Benefits Traceability | 7 | Sankey: challenges → capabilities → metrics |
| 22 | Self-Learning Staircase | 4.3 | L0 → L4 ascending with human involvement decreasing |
| 23 | Vendor Complexity Quadrant | 8.6 | API maturity vs integration effort, vendors plotted |

---

*These diagrams are in Mermaid format for iteration. Final versions for Google Docs will be exported as images.*
