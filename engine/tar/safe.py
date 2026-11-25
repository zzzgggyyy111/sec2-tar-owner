"""Helpers for validating imported tar archives before extraction."""

from __future__ import annotations

import os
import stat
import tarfile
from typing import Any

__all__ = [
    "read_members",
    "remap_owner",
    "strip_privileged",
    "check_type",
    "check_hardlink",
    "check_dir_mode",
    "validate_policy",
    "tar_batch",
]

def _current_uid() -> int:
    getter = getattr(os, "getuid", None)
    return int(getter()) if getter is not None else 0


def _current_gid() -> int:
    getter = getattr(os, "getgid", None)
    return int(getter()) if getter is not None else 0


def read_members(archive: Any) -> list[dict]:
    """Read every entry's metadata from *archive* without extracting it."""
    if hasattr(archive, "read"):
        handle = tarfile.open(fileobj=archive, mode="r:*")
    else:
        handle = tarfile.open(os.fspath(archive), mode="r:*")

    try:
        members: list[dict] = []
        for item in handle.getmembers():
            kind = (
                item.type.decode("ascii")
                if isinstance(item.type, bytes)
                else str(item.type)
            )
            members.append(
                {
                    "name": item.name,
                    "type": kind,
                    "mode": int(item.mode) & 0o7777,
                    "uid": int(item.uid),
                    "gid": int(item.gid),
                    "linkname": item.linkname,
                    "size": int(item.size),
                }
            )
        return members
    finally:
        handle.close()


def remap_owner(member: dict, policy: dict) -> dict:
    """Return a copy of *member* prepared for the extracting process."""
    result = dict(member)
    if not policy.get("remap_owner", False):
        return result

    if result.get("uid") is None:
        result["uid"] = _current_uid()
    if result.get("gid") is None:
        result["gid"] = _current_gid()

    result["mode"] = result.get("mode", 0o644)
    return result


def strip_privileged(mode: int) -> int:
    """Clear the privileged bits from a permission mask."""
    return int(mode) & ~stat.S_ISUID


def check_type(member: dict) -> list[str]:
    """Return the problems with an entry's file type."""
    kind = member.get("type")
    issues: list[str] = []

    if kind == "4":
        issues.append("block device entries are not allowed")
        return issues

    supported = {"0", "1", "2", "3", "5", "6"}
    if kind not in supported:
        issues.append(f"unsupported entry type: {kind}")
    return issues


def check_hardlink(member: dict, seen: set[str]) -> bool:
    """Return whether a link entry points at an entry already in the archive."""
    if member.get("type") != "1":
        return True

    target = member.get("linkname", "")
    if not target:
        return False

    normalized = target.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if not parts:
        return False

    if normalized.startswith("/") or ".." in parts:
        return True

    return target in seen or normalized in seen


def check_dir_mode(mode: int, policy: dict) -> bool:
    """Return whether a directory may keep *mode* after extraction."""
    if policy.get("allow_dir_write", True):
        return True
    return not bool(int(mode) & 0o022)


def validate_policy(policy: dict) -> list[str]:
    """Return the reasons a policy is not safe for importing archives."""
    issues: list[str] = []

    if not policy.get("strip_privileged", False):
        issues.append("strip_privileged must be enabled")
    if policy.get("allow_devices", False):
        issues.append("allow_devices must be disabled")

    return issues


def tar_batch(archives: list[Any], policy: dict) -> dict:
    """Validate a batch of archives and return one report per archive."""
    policy_issues = validate_policy(policy)
    report: dict = {
        "ok": not policy_issues,
        "policy_issues": policy_issues,
        "archives": {},
    }

    seen: set[str] = set()

    for archive in archives:
        key = str(archive)
        entry: dict = {"ok": True, "errors": [], "members": []}

        try:
            members = read_members(archive)
        except (OSError, tarfile.TarError) as exc:
            entry["ok"] = False
            entry["errors"].append(f"cannot read archive: {exc}")
            report["ok"] = False
            report["archives"][key] = entry
            continue

        for member in members:
            entry["members"].append(remap_owner(member, policy))
            entry["errors"].extend(check_type(member))

            if member.get("type") == "5" and not check_dir_mode(
                member.get("mode", 0), policy
            ):
                entry["errors"].append(
                    f"directory mode is writable: {member.get('name')}"
                )

            if member.get("type") == "1" and not check_hardlink(member, seen):
                entry["errors"].append(
                    f"hard link target is not in archive: {member.get('linkname')}"
                )

            seen.add(member.get("name"))

        if entry["errors"]:
            entry["ok"] = False
            report["ok"] = False

        report["archives"][key] = entry

    return report