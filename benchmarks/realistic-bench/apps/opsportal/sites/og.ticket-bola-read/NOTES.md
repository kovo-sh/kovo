# og.ticket-bola-read

- Title: Ticket fetch trusts the path id without a team check
- Class: bola (CWE-639), severity high
- Entry routes: ticketGet
- Trigger routes: ticketGet
- Oracle: cross_tenant_read @ ticketGet
- Root cause file: tickets/fetch.ts (symbol register)
- Lure: query filters by status but the row is loaded by id before the filter applies

Spec-only site: approach is to differentiate the twin at tickets/fetch.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
