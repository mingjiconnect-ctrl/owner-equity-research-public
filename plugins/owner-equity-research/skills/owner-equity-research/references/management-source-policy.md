# Management source policy

Use only SEC filings and issuer-hosted official IR material for confirmed management Statements.
Eligible SEC forms are 10-K, 10-Q, 8-K and exhibits, DEF 14A, and their amendments. Eligible IR
material includes company earnings releases, prepared remarks, investor-day material, and
company-hosted transcripts.

Require an explicit issuer host allowlist for every non-SEC request. Accept only credential-free
HTTPS, validate the final redirect host, keep raw bytes in the external content-addressed cache,
and bind each SourceDocument to its exact SHA-256. Third-party transcripts, analyst consensus, and
media summaries may support counterevidence Claims but never a confirmed Statement.

CI remains offline. Live retrieval is explicit and must record the data cutoff date.
