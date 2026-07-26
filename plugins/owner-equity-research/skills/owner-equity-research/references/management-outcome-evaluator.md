# Management Outcome evaluator

Evaluate only after loading the compiled Commitment, official result evidence, explanatory Claims,
and any deterministic calculations. Before the due date, status is `pending` unless evidence is
blocked. After the due date, undisclosed official results are `unverifiable`; unresolved metric,
scope, unit, currency, basis, period, component, or source conflicts are `blocked`.

Use the registered policy for the arithmetic status. A single-component target is only `met` or
`missed`; `partially_met` requires multiple components with mixed results. Claims document
conditions, counterevidence, and falsification but cannot override the computed status.

Reported growth and cumulative evidence must produce assumption-free `CalculationResult` objects.
Constant-currency, organic, inorganic, and KPI-definition bridges require named deterministic
calculators and official inputs. Withdrawn and superseded Commitments produce lifecycle Outcomes
without ordinary result evidence and never become `missed`.
