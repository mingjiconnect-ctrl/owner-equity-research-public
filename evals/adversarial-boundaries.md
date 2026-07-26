# Phase 1-2 adversarial boundary cases

The automated suite must reject:

1. A numeric fact without unit, currency, or period.
2. A claim without supporting evidence.
3. A claim that has neither counterevidence nor a counterevidence search note.
4. An assumption inserted into the fact collection.
5. A calculation attributed to a language model or manual narrative.
6. A score without facts, claims, calculation results, missing-evidence field, or red-flag field.
7. Any evidence contract referencing a score.
8. A dangling reference or an identifier reused across contract domains.
9. Historical-report access before the current conclusion has been frozen.
10. A valuation-kernel schema or Plugin version that differs from the pinned component lock.
11. Implicit invocation of quarterly, audit, or publish shells.
12. Any Phase 1 production module for analysis, scoring, valuation handoff, rendering, or publishing.
13. A 52/53-week period whose stated week count disagrees with its dates.
14. A Q2-Q4 discrete-quarter derivation without an adjacent prior cumulative period.
15. A TTM derivation without an adjacent prior fiscal year and prior comparable YTD.
16. A reconciliation that resolves without regulatory authority, or whose status contradicts
    its blocked state and authoritative references.
17. A growth bridge missing any of FX, acquisition, price or volume.
18. A free-cash-flow derivation that mixes currencies, periods or capex sign conventions.
19. A quarterly update with dangling references, multiple issuers or embedded valuation output.
20. Any Phase 3-7 production module or implicit quarterly invocation.
