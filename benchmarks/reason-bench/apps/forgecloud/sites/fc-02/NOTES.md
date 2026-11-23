# fc-02 author notes

- Mechanism: `automations.create` inserts a row whose `role_template` becomes the service account's
  effective grant. The twin that omits the rank clamp defaults an omitted template to `admin`, so a
  team lead (`automation:create`, no admin) mints an organization-administration automation.
- Solver: team lead reads members, tries the direct admin role change (403 control), creates an
  automation with no template, re-lists automations.
- Oracle wiring: the host audit trigger on `automations` INSERT judges the template against the
  actor's current role and emits `privilege_escalation` at `automations.create`.
- Hardened twin: default `viewer` and clamp to the creator's own role rank.
