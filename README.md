# Linux security patching (Debian / Ubuntu)

Ansible playbook that applies **security updates only** across the fleet, then
reports what still needs human attention.

Policy baked into this repo, per the agreed rollout:

| Decision | Setting |
|---|---|
| Distributions | Debian and Ubuntu (`apt`). A non-Debian host fails fast with a clear message. |
| Update scope | Security suites only (`*-security`, including Ubuntu ESM `-infra-security` / `-apps-security`) |
| Reboots | **Never.** Hosts needing one are listed in the run summary for a human to schedule. |
| Service restarts | **Never** by default. Stale services are reported, not restarted. |
| Rollout | One canary host, then batches of 25%. Any host failing aborts the run. |

## Quick start

```bash
ansible-galaxy collection install -r requirements.yml   # profile_tasks/timer callbacks

# 1. See what would happen, change nothing:
ansible-playbook playbooks/security-patch.yml --check

# 2. Same, but as a real run that only plans and reports:
ansible-playbook playbooks/security-patch.yml -e patch_apply=false

# 3. Patch for real:
ansible-playbook playbooks/security-patch.yml

# Narrow the blast radius while you build confidence:
ansible-playbook playbooks/security-patch.yml -l web-canary-01.example.com
ansible-playbook playbooks/security-patch.yml -l ubuntu
```

Every run writes `reports/<run-id>/` — `summary.md` first, then one `.md` and
one `.json` per host. **Start with `summary.md`: it lists the hosts that need a
reboot.** Reports are written in `--check` mode too, which is the point of a
check run.

## How "security only" is decided

`apt` has no `--security` switch, so the role works it out:

1. `apt-security-sources.py` reads the host's own apt configuration — both the
   one-line format and the deb822 format used by Ubuntu 24.04+ — and emits a
   copy containing only suites ending in `-security` (plus the historical Debian
   `<codename>/updates` form). deb822 stanzas are filtered in place so inline
   `Signed-By` PGP blocks survive.
2. `apt-get update` runs against *only* those sources, in an isolated state
   directory under `/var/lib/ansible-security-patch/`. The host's own
   `/var/lib/apt/lists` is never touched, and `APT::Get::List-Cleanup=0` keeps
   apt from pruning it.
3. `apt-plan-json.py` simulates `upgrade --with-new-pkgs` against that isolated
   view. Whatever apt now offers is, by construction, a security upgrade.
4. The upgrade is applied with the `apt` module, **pinned to the exact
   `name=version` from the plan**, so a newer non-security version landing in
   `-updates` between planning and applying cannot be pulled in instead.

Two safety gates exist because of how quietly this can go wrong:

- **Unreachable security mirror.** `apt-get update` exits 0 after failing to
  fetch an index; it only prints a `W:` warning. A host that cannot reach the
  mirror would report zero pending updates and look perfectly patched. The role
  passes `APT::Update::Error-Mode=any` to turn that into a hard error, and then
  separately asserts that at least one `Packages` index was actually fetched.
- **No security source configured.** Also indistinguishable from a fully patched
  host, so it is a hard failure rather than an empty plan.

## Safety gates

Before patching:

- host is Debian family, or fail
- `dpkg --audit` is clean (a half-finished dpkg run aborts the host unless
  `patch_fix_broken_dpkg=true`)
- the dpkg lock is free — probed with an `fcntl` lock, the same kind dpkg uses,
  because `flock(1)` cannot see dpkg's lock at all and would always report free
- free space on `/`, `/var` and `/boot` meets `patch_min_free_mb`

During:

- apt wanting to **remove** any package aborts the host (`patch_allow_removals`)
- `patch_exclude_packages` are `apt-mark hold`ed for the run so dependency
  resolution cannot drag them in, and released afterwards. Holds that already
  existed are recorded and left alone.
- `any_errors_fatal` stops the run at the first failing host, so a bad package
  reaches the canary and nothing else

After:

- pending-reboot marker and the packages that requested it
- `needrestart` findings: services running pre-patch code, and kernel status
- optional `patch_verify_services` assertion that named units are still running
- before/after `dpkg-query` diff, so the report shows what *actually* changed
  rather than what was planned
- leftover holds are flagged, since a stale hold silently blocks future patching

A failing host still writes its report before the run aborts.

## Configuration

Fleet-wide settings live in `group_vars/all.yml`; everything available is
documented in [roles/security_patch/defaults/main.yml](roles/security_patch/defaults/main.yml).
The ones that matter most:

| Variable | Default | Purpose |
|---|---|---|
| `patch_apply` | `true` | `false` = plan and report only |
| `patch_security_only` | `true` | `false` = all available updates |
| `patch_exclude_packages` | `[]` | Never upgrade these; held for the run |
| `patch_allow_removals` | `false` | Abort if apt wants to remove packages |
| `patch_min_free_mb` | `/ 512`, `/var 1024`, `/boot 200` | Preflight space check |
| `patch_verify_services` | `[]` | Units asserted running afterwards |
| `patch_restart_services` | `false` | Opt in to restarting stale services |
| `patch_allow_reboot` | `false` | Also needs `patch_reboot_confirmed=true` |

Per host, in the inventory:

```yaml
db-01.example.com:
  patch_exclude_packages:
    - postgresql-16
  patch_verify_services:
    - postgresql.service
```

## Choosing the canary

The play sets `order: inventory` with `serial: [1, "25%"]`, so **the canary is
the first host listed in the target group.** Put a low-risk host there.

## Reports

```
reports/20260928T101500Z/
├── summary.md                        # start here
├── web-canary-01.example.com.md      # human readable
└── web-canary-01.example.com.json    # same data, for dashboards/tickets
```

If a run aborts before the summary is written, rebuild it from the per-host JSON
without touching any hosts:

```bash
ansible-playbook playbooks/security-patch-summary.yml -e patch_run_id=20260928T101500Z
```

## Checking changes to this repo

There is no Ansible control node on Windows; run these from WSL or a Linux host:

```bash
ansible-playbook playbooks/security-patch.yml --syntax-check
ansible-lint
ansible-playbook playbooks/security-patch.yml --check --diff -l <one-host>
```

## Notes and limitations

- The two helper scripts stay in `/var/lib/ansible-security-patch/` on each host
  between runs; nothing else on the host is modified to work out the plan.
- `needrestart` is **not** installed by the role — installing a package in order
  to report would be a change nobody asked for. Add it to your base image and
  the stale-service section of the report fills in automatically.
- `patch_exclude_packages` is enforced with apt holds, not apt pinning. If you
  need a permanent policy that survives outside this playbook, add an
  `/etc/apt/preferences.d/` pin as well.
- Excluding a package means it stays on a known-vulnerable version. Every report
  says so explicitly, per host, in "Deliberately left unpatched".
