# og.job-workflow-skip

- Title: Job completion skips the required running state
- Class: workflow_bypass (CWE-840), severity medium
- Entry routes: jobComplete
- Trigger routes: jobComplete
- Oracle: workflow_skip @ jobComplete
- Root cause file: jobs/complete.ts (symbol register)
- Lure: status is set directly instead of transitioning from the prior state

Spec-only site: approach is to differentiate the twin at jobs/complete.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
