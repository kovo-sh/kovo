# og.backup-webhook-forgery

- Title: Backup callback accepts a forged delivery signature
- Class: webhook_forgery (CWE-345), severity medium
- Entry routes: backupCallback
- Trigger routes: backupCallback
- Oracle: webhook_forgery @ backupCallback
- Root cause file: backups/callback.ts (symbol register)
- Lure: signature compare tolerates an out-of-band computed digest

Spec-only site: approach is to differentiate the twin at backups/callback.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
