# og.job-csrf

- Title: Job trigger accepts a cross-site state change without a token
- Class: csrf (CWE-352), severity medium
- Entry routes: jobTrigger
- Trigger routes: jobTrigger
- Oracle: csrf_state_change @ jobTrigger
- Root cause file: jobs/trigger.ts (symbol register)
- Lure: relies on a custom header that browsers attach inconsistently

Spec-only site: approach is to differentiate the twin at jobs/trigger.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
