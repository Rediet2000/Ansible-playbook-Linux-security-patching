#!/usr/bin/env python3
"""Simulate a security-only upgrade and print the resulting plan as JSON.

Runs ``apt-get --simulate --with-new-pkgs upgrade`` with the apt option
overrides given on the command line (the caller points them at the isolated,
security-only source/list directories built by apt-security-sources.py), then
parses apt's machine-ish output into three buckets:

  upgrades      packages moving from an installed version to a security version
  new_packages  packages apt must install to complete the upgrade, typically a
                new kernel ABI package -- `upgrade --with-new-pkgs` allows these
  removals      packages apt wants to REMOVE; the playbook refuses to proceed on
                these unless patch_allow_removals is set, because an unattended
                security patch should never delete software

Nothing is installed here. This script only simulates, which is why the calling
task can safely run with check_mode disabled.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

INST_RE = re.compile(
    r"^Inst\s+(?P<name>\S+)\s+"
    r"(?:\[(?P<current>[^\]]+)\]\s+)?"
    r"\((?P<candidate>\S+)\s+(?P<origin>.*?)"
    r"(?:\s+\[(?P<arch>[^\]]+)\])?\)\s*$"
)

REMV_RE = re.compile(
    r"^Remv\s+(?P<name>\S+)(?:\s+\[(?P<current>[^\]]+)\])?"
)


def main(argv: list) -> int:
    apt_options = argv[1:]

    cmd = [
        "apt-get",
        "--simulate",
        "--quiet",
        "--with-new-pkgs",
        "upgrade",
    ] + apt_options

    env = dict(os.environ)
    env["DEBIAN_FRONTEND"] = "noninteractive"
    # apt's output is parsed below, so pin the locale.
    env["LC_ALL"] = "C"
    env["LANG"] = "C"

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        universal_newlines=True,
    )

    upgrades: list = []
    new_packages: list = []
    removals: list = []

    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("Inst "):
            match = INST_RE.match(line)
            if not match:
                continue
            entry = {
                "name": match.group("name"),
                "current": match.group("current"),
                "candidate": match.group("candidate"),
                "origin": (match.group("origin") or "").strip(),
                "arch": match.group("arch"),
                "pkgspec": "%s=%s" % (match.group("name"), match.group("candidate")),
            }
            if entry["current"]:
                upgrades.append(entry)
            else:
                new_packages.append(entry)
        elif line.startswith("Remv "):
            match = REMV_RE.match(line)
            if not match:
                continue
            removals.append(
                {"name": match.group("name"), "current": match.group("current")}
            )

    result = {
        "upgrades": sorted(upgrades, key=lambda e: e["name"]),
        "new_packages": sorted(new_packages, key=lambda e: e["name"]),
        "removals": sorted(removals, key=lambda e: e["name"]),
        "counts": {
            "upgrades": len(upgrades),
            "new_packages": len(new_packages),
            "removals": len(removals),
        },
        "apt_command": " ".join(cmd),
        "apt_rc": proc.returncode,
        "apt_stderr": proc.stderr.strip(),
    }

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if proc.returncode == 0 else 4


if __name__ == "__main__":
    sys.exit(main(sys.argv))
