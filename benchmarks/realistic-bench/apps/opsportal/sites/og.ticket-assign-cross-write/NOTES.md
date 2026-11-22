# og.ticket-assign-cross-write

- Title: Ticket assignment writes to a ticket in another team
- Class: idor (CWE-639), severity high
- Entry routes: ticketAssign
- Trigger routes: ticketAssign
- Oracle: cross_tenant_write @ ticketAssign
- Root cause file: tickets/assign.ts (symbol register)
- Lure: assignee team is validated but the target ticket team is not

Spec-only site: approach is to differentiate the twin at tickets/assign.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
