import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from wechatma.profiles import (
    DetectedWechat,
    UnsupportedVersionError,
    resolve_profile,
)


def _write(dir_path: Path, version: str, magicdy: str) -> None:
    data = {
        "schema_version": 1,
        "wechat": {"bundle_version": version, "magicdy_version": magicdy},
        "hooks": {},
    }
    (dir_path / f"wechat-{version}-magicdy{magicdy}.json").write_text(
        json.dumps(data)
    )


def det(version: str, magicdy: str) -> DetectedWechat:
    return DetectedWechat(version=version, build="x", magicdy=magicdy, app_path="x")


def test_exact_match(tmp_path):
    _write(tmp_path, "4.1.15", "965")
    _write(tmp_path, "4.1.15", "900")
    r = resolve_profile(tmp_path, det("4.1.15", "965"))
    assert r.match == "exact"
    assert r.profile_key == "4.1.15+magicdy965"


def test_same_bundle_fallback(tmp_path):
    _write(tmp_path, "4.1.15", "900")
    r = resolve_profile(tmp_path, det("4.1.15", "965"))
    assert r.match == "same-bundle"


def test_same_major_fallback(tmp_path):
    _write(tmp_path, "4.1.10", "900")
    r = resolve_profile(tmp_path, det("4.1.15", "965"))
    assert r.match == "same-major"


def test_unsupported(tmp_path):
    _write(tmp_path, "3.9.0", "10")
    with pytest.raises(UnsupportedVersionError):
        resolve_profile(tmp_path, det("4.1.15", "965"))
