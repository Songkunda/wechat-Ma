"""版本化 profile 解析：检测当前微信版本 -> 选择匹配的配置文件。

微信升级后只需运行一次 tools/gen_profile.py 生成新 profile，
这里按 (bundle_version, magicdy_version) 自动挑选：
  1. 精确匹配 bundle+magicdy
  2. 同 bundle 版本、不同 magicdy（插件热更新，hook 面大概率兼容）-> degraded
  3. 都无 -> UnsupportedVersion
"""

from __future__ import annotations

import json
import plistlib
from dataclasses import dataclass
from pathlib import Path

MAGICDY_PLUGINS = (
    Path.home()
    / "Library/Containers/com.tencent.xinWeChat/Data/Documents"
    / "app_data/xplugin/plugins/Magicdy"
)


class UnsupportedVersionError(RuntimeError):
    def __init__(self, detected: "DetectedWechat", available: list[str]):
        self.detected = detected
        self.available = available
        super().__init__(
            f"UNSUPPORTED_VERSION: {detected.version}+magicdy{detected.magicdy}"
            f" (profiles: {', '.join(available) or 'none'})"
        )


@dataclass(frozen=True)
class DetectedWechat:
    version: str
    build: str
    magicdy: str
    app_path: str


@dataclass(frozen=True)
class ResolvedProfile:
    path: Path
    data: dict
    match: str  # "exact" | "same-bundle" | "same-major"
    profile_key: str


def detect_wechat(app_path: str = "/Applications/WeChat.app") -> DetectedWechat:
    info = Path(app_path) / "Contents/Info.plist"
    with info.open("rb") as f:
        plist = plistlib.load(f)
    magicdy = ""
    if MAGICDY_PLUGINS.is_dir():
        nums = [d.name for d in MAGICDY_PLUGINS.iterdir() if d.name.isdigit()]
        magicdy = max(nums, key=int) if nums else ""
    return DetectedWechat(
        version=str(plist.get("CFBundleShortVersionString", "")),
        build=str(plist.get("CFBundleVersion", "")),
        magicdy=magicdy,
        app_path=app_path,
    )


def _major(version: str) -> str:
    parts = version.split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else version


def resolve_profile(
    profiles_dir: Path | str,
    detected: DetectedWechat | None = None,
) -> ResolvedProfile:
    detected = detected or detect_wechat()
    profiles_dir = Path(profiles_dir)
    candidates: list[tuple[Path, dict]] = []
    for p in sorted(profiles_dir.glob("*.json")):
        try:
            data = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("schema_version") == 1 and "wechat" in data:
            candidates.append((p, data))

    def key(d: dict) -> str:
        w = d["wechat"]
        return f"{w.get('bundle_version')}+magicdy{w.get('magicdy_version')}"

    scored: list[tuple[int, Path, dict]] = []
    for p, d in candidates:
        w = d["wechat"]
        if w.get("bundle_version") == detected.version and w.get(
            "magicdy_version"
        ) == detected.magicdy:
            scored.append((0, p, d))
        elif w.get("bundle_version") == detected.version:
            scored.append((1, p, d))
        elif _major(str(w.get("bundle_version", ""))) == _major(detected.version):
            scored.append((2, p, d))
    if not scored:
        raise UnsupportedVersionError(detected, [key(d) for _, d in candidates])
    rank, path, data = min(scored, key=lambda s: s[0])
    match = {0: "exact", 1: "same-bundle", 2: "same-major"}[rank]
    return ResolvedProfile(path=path, data=data, match=match, profile_key=key(data))


def load_runtime_config(repo_root: Path | str) -> dict:
    cfg_path = Path(repo_root) / "config.json"
    if cfg_path.exists():
        return json.loads(cfg_path.read_text())
    return {}
