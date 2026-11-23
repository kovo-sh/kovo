# fc-03 author notes

- Mechanism: `projects.transfer` authorizes the destination org (`org:admin`) but treats the source
  org as membership-only. `dual_member` is `admin` in org A and `viewer` in org B, so a request made
  with the org-B header relocates a B project into A.
- Solver: dual member lists B projects, lists A projects (control), transfers a B project to A, then
  lists A again (the relocated project's note demonstrates the cross-tenant data movement).
- Oracle wiring: the host audit trigger on `projects` UPDATE detects an `org_slug` change, computes
  source/destination admin roles, and emits `cross_org_transfer` at `projects.transfer`.
- Hardened twin: requires `org:admin` on the source org as well.
