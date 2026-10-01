#!/usr/bin/env python3
"""Emit an apt source configuration restricted to this host's security suites.

Why this exists: apt has no ``--security`` switch (unlike dnf). The reliable way
to find out which pending upgrades are *security* upgrades is to ask apt to
resolve upgrades while it can only see the security pockets. This script reads
the host's real apt configuration and reproduces just the security parts of it.

A suite counts as security when it ends in ``-security`` -- that covers
jammy-security, noble-security, bookworm-security and Ubuntu ESM's
<codename>-infra-security / <codename>-apps-security -- or when it uses the
historical Debian form ``<codename>/updates``.

Both apt source formats are handled:
  * one-line format  (/etc/apt/sources.list, sources.list.d/*.list)
  * deb822 format    (sources.list.d/*.sources, the Ubuntu 24.04+ default)

deb822 stanzas are copied through with only the Suites field filtered, so inline
``Signed-By`` PGP blocks survive intact instead of being mangled into a
one-line ``signed-by=`` option.

Output: a JSON object on stdout with keys ``one_line``, ``deb822``, ``suites``
and ``scanned``. A human-readable summary goes to stderr. Exit 3 means no
security source was found at all -- the caller must treat that as a failure
rather than as "no updates available", because a silent empty plan on a host
with no security source would look exactly like a fully patched host.
"""

from __future__ import annotations

import glob
import json
import os
import re
import sys

SECURITY_SUITE_RE = re.compile(r"(?:-security|/updates)$")

ONE_LINE_RE = re.compile(
    r"^(?P<type>deb|deb-src)\s+"
    r"(?:\[(?P<options>[^\]]*)\]\s+)?"
    r"(?P<uri>\S+)\s+"
    r"(?P<suite>\S+)"
    r"(?P<components>(?:\s+\S+)*)\s*$"
)

DEFAULT_LIST = "/etc/apt/sources.list"
DEFAULT_PARTS = "/etc/apt/sources.list.d"


def read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def is_security(suite: str) -> bool:
    return bool(SECURITY_SUITE_RE.search(suite))


def strip_comment(line: str) -> str:
    """Drop apt comments. '#' starts a comment at the start of a line or after
    whitespace; a bare '#' inside a URI or option value is left alone."""
    if line.lstrip().startswith("#"):
        return ""
    return re.split(r"\s+#", line, maxsplit=1)[0].rstrip()


def parse_one_line(path: str, text: str, suites: set, kept: list) -> None:
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = strip_comment(raw)
        if not line.strip():
            continue
        match = ONE_LINE_RE.match(line.strip())
        if not match:
            print(
                "  skip %s:%d (not a recognised one-line entry)" % (path, lineno),
                file=sys.stderr,
            )
            continue
        # Source packages are never needed to install a binary security update.
        if match.group("type") != "deb":
            continue
        suite = match.group("suite")
        if not is_security(suite):
            continue
        suites.add(suite)
        # Copied verbatim so options such as arch= and signed-by= are preserved.
        kept.append(line.strip())


def split_stanzas(text: str) -> list:
    stanzas: list = []
    current: list = []
    for raw in text.splitlines():
        if not raw.strip():
            if current:
                stanzas.append(current)
                current = []
            continue
        if raw.lstrip().startswith("#"):
            continue
        current.append(raw)
    if current:
        stanzas.append(current)
    return stanzas


def stanza_fields(lines: list) -> list:
    """-> [[key, first_value, [raw continuation lines]], ...]"""
    fields: list = []
    for line in lines:
        if line[:1] in (" ", "\t") and fields:
            fields[-1][2].append(line)
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        fields.append([key.strip(), value.strip(), []])
    return fields


def parse_deb822(path: str, text: str, suites: set, kept: list) -> None:
    for lines in split_stanzas(text):
        fields = stanza_fields(lines)
        by_key = {key.lower(): (value, cont) for key, value, cont in fields}

        enabled = by_key.get("enabled", ("yes", []))[0].strip().lower()
        if enabled in ("no", "false", "0"):
            continue

        types = (by_key.get("types", ("deb", []))[0]).split()
        if "deb" not in types:
            continue

        suite_value = by_key.get("suites", ("", []))[0]
        matching = [s for s in suite_value.split() if is_security(s)]
        if not matching:
            continue
        suites.update(matching)

        out: list = []
        for key, value, cont in fields:
            low = key.lower()
            if low == "suites":
                out.append("Suites: %s" % " ".join(matching))
            elif low == "types":
                out.append("Types: deb")
            else:
                out.append("%s: %s" % (key, value))
                out.extend(cont)
        kept.append("\n".join(out))
        print("  kept stanza from %s (suites: %s)" % (path, " ".join(matching)),
              file=sys.stderr)


def main() -> int:
    source_list = os.environ.get("APT_SOURCE_LIST", DEFAULT_LIST)
    source_parts = os.environ.get("APT_SOURCE_PARTS", DEFAULT_PARTS)

    suites: set = set()
    one_line: list = []
    deb822: list = []
    scanned: list = []

    files = [source_list]
    files += sorted(glob.glob(os.path.join(source_parts, "*.list")))
    files += sorted(glob.glob(os.path.join(source_parts, "*.sources")))

    for path in files:
        text = read(path)
        if not text:
            continue
        scanned.append(path)
        if path.endswith(".sources"):
            parse_deb822(path, text, suites, deb822)
        else:
            parse_one_line(path, text, suites, one_line)

    header = [
        "# Generated by Ansible role security_patch -- do not edit.",
        "# Security-only view of this host's apt sources.",
        "",
    ]

    result = {
        "one_line": "\n".join(header + one_line) + "\n",
        "deb822": ("\n\n".join(deb822) + "\n") if deb822 else "",
        "suites": sorted(suites),
        "scanned": scanned,
    }

    print(json.dumps(result, indent=2, sort_keys=True))

    if not suites:
        print(
            "ERROR: no security suite found in %s" % ", ".join(scanned or ["<nothing>"]),
            file=sys.stderr,
        )
        return 3

    print("security suites: %s" % " ".join(sorted(suites)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
