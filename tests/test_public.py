import io
import os
import tarfile

from engine.tar.safe import (
    check_type,
    remap_owner,
    strip_privileged,
    tar_batch,
)


def _uid() -> int:
    getter = getattr(os, "getuid", None)
    return int(getter()) if getter is not None else 0


def _gid() -> int:
    getter = getattr(os, "getgid", None)
    return int(getter()) if getter is not None else 0


def _policy() -> dict:
    return {
        "remap_owner": True,
        "strip_privileged": True,
        "allow_devices": False,
    }


def _write_tar(path, entries):
    with tarfile.open(path, "w") as handle:
        for spec in entries:
            info = tarfile.TarInfo(spec["name"])
            info.type = spec.get("type", tarfile.REGTYPE)
            info.mode = spec.get("mode", 0o644)
            info.uid = spec.get("uid", 424242)
            info.gid = spec.get("gid", 434343)
            info.linkname = spec.get("linkname", "")

            data = spec.get("data")
            if data is None:
                info.size = 0
                handle.addfile(info)
            else:
                payload = data.encode("utf-8")
                info.size = len(payload)
                handle.addfile(info, io.BytesIO(payload))

    return path


def test_normal_archive_passes(tmp_path):
    archive = _write_tar(
        tmp_path / "plain.tar",
        [{"name": "notes/readme.txt", "data": "hello", "mode": 0o644}],
    )

    report = tar_batch([archive], _policy())

    assert report["ok"] is True
    entry = report["archives"][str(archive)]
    assert entry["ok"] is True
    assert entry["errors"] == []
    assert entry["members"][0]["uid"] == _uid()
    assert entry["members"][0]["gid"] == _gid()


def test_owner_and_group_are_remapped():
    member = {
        "name": "owned.txt",
        "type": "0",
        "mode": 0o644,
        "uid": 424242,
        "gid": 434343,
        "linkname": "",
        "size": 0,
    }

    result = remap_owner(member, _policy())

    assert result["uid"] == _uid()
    assert result["gid"] == _gid()


def test_privileged_bits_are_stripped():
    assert strip_privileged(0o6755) == 0o755


def test_device_file_is_rejected():
    member = {
        "name": "dev/null",
        "type": "3",
        "mode": 0o600,
        "uid": 0,
        "gid": 0,
        "linkname": "",
        "size": 0,
    }

    assert check_type(member)


def test_batch_archives_are_independent(tmp_path):
    first = _write_tar(
        tmp_path / "first.tar",
        [{"name": "only-first.txt", "data": "first"}],
    )
    second = _write_tar(
        tmp_path / "second.tar",
        [{"name": "alias.txt", "type": tarfile.LNKTYPE, "linkname": "only-first.txt"}],
    )

    report = tar_batch([first, second], _policy())

    assert report["archives"][str(first)]["ok"] is True
    assert report["archives"][str(second)]["ok"] is False
    assert report["archives"][str(second)]["errors"]