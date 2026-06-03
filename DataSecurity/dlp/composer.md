# DLP Composer — Influence Summary

## What it is and what we are solving (1000 characters)

DLP Composer is a universal rule composition engine solving the architecture problem behind DLP policy failures. Researched six major DLP vendors and interviewed DLP engineers, compliance analysts, and security architects. Identified that industry pain points — 15-40% false positive rates, untested rules, vendor lock-in, authoring bottlenecks — trace to one root cause: vendors conflate detection, scoping, actions, and channel config into monolithic, untestable objects. Designed the architecture from first principles: four-layer canonical hierarchy separating detection from rule from policy, composable entity system (95+ types, never inline values, always reference entities), seven-layer FP elimination stack, GenAI-powered authoring with testing at every keystroke, label integration bridging DSPM and DLP, and a transpiler for vendor portability. Produced a 9-section proposal with 14 architecture diagrams, 43 metrics, risk assessment, and vendor integration analysis — currently in leadership review for implementation.

---

## Impact (255 characters)

Reframed DLP from a vendor tooling problem to an architecture problem. Designed a vendor-neutral rule platform that eliminates channel duplication, embeds testing in authoring, and reduces false positives architecturally — capabilities no vendor offers.

---

## Results (255 characters)

Design proposal under review. Expected outcomes: rule authoring from days to hours, FP rates from 15-40% to below 10%, zero untested rules via gated pipeline, vendor migration from 6-12 months to 4-8 weeks, audit prep from weeks to hours.
