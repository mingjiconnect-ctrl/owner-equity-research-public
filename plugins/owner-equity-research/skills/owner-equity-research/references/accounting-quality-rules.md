# Accounting-quality rules

Use deterministic rules for cash conversion, accruals, SBC dilution, recurring restructuring,
goodwill/intangible concentration, impairment, tax anomalies, lease commitments, acquisition
reconciliation, segment eliminations, and off-balance-sheet risk.

Treat each rule output as a suggested `informational`, `watch`, or `red_flag` severity. Confirm or
override it only through a Claim that cites Facts/calculations, documents counterevidence search,
states confidence, and gives a falsification condition. Classify confirmed findings as
`temporary`, `structural`, or `uncertain`.

When required evidence is unavailable, emit a blocked finding with the missing evidence. Do not
turn missing data into a red flag, a clearance, or a score. Do not create score, valuation,
management, report, PDF, or Publisher dependencies.
