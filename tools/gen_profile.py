#!/usr/bin/env python3
"""gen_profile.py — 一键为当前安装的微信生成版本 profile。

新版本微信发布后，只需运行一次：

    python3 tools/gen_profile.py            # 快速静态提取（约 1 分钟）
    python3 tools/gen_profile.py --deep     # 追加 REA/Ghidra 深度分析（后台，耗时长）

产出：profiles/wechat-<bundle版本>-magicdy<插件版本>.json
      运行时由 src/wechatma/profiles.py 按检测到的版本自动选择。
中间产物（二进制切片等）写入 docs/analysis/raw/（已 gitignore）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RAW_DIR = REPO / "docs" / "analysis" / "raw"
SYMBOLS_FILE = REPO / "tools" / "hook-symbols.txt"
MAGICDY_PLUGINS = (
    Path.home()
    / "Library/Containers/com.tencent.xinWeChat/Data/Documents"
    / "app_data/xplugin/plugins/Magicdy"
)
CGI_RE = re.compile(r'<cgi reqid="(\d+)"[^>]*>([a-z0-9_-]+)</cgi>')
SERVICE_HINTS = ("micromsg.AddMsg", "AddMsgCmdHandler", "SendMsg", "NewSync", "wcdb_lv_")
SIG_BYTES = 24


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=True, **kw)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def plist_key(plist: Path, key: str) -> str:
    with plist.open("rb") as f:
        return str(plistlib.load(f).get(key, ""))


def detect_wechat(app: Path) -> dict:
    info = app / "Contents/Info.plist"
    version = plist_key(info, "CFBundleShortVersionString")
    build = plist_key(info, "CFBundleVersion")
    magicdy = ""
    if MAGICDY_PLUGINS.is_dir():
        nums = [d.name for d in MAGICDY_PLUGINS.iterdir() if d.name.isdigit()]
        magicdy = max(nums, key=int) if nums else ""
    return {
        "bundle_version": version,
        "build": build,
        "magicdy_version": magicdy,
        "app_path": str(app),
    }


def thin(src: Path, dst: Path) -> Path:
    """fat Mach-O -> arm64 单架构切片（REA/Ghidra 不能对 universal 选架构）。"""
    dst.parent.mkdir(parents=True, exist_ok=True)
    lipo = run(["lipo", "-info", str(src)]).stdout
    if "arm64" in lipo and ("x86_64" in lipo or "are:" in lipo):
        run(["lipo", "-thin", "arm64", str(src), "-output", str(dst)])
    else:
        dst.write_bytes(src.read_bytes())
    return dst


def load_patterns() -> list[tuple[str, re.Pattern]]:
    out = []
    for line in SYMBOLS_FILE.read_text().splitlines():
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        key, pat = line.split("\t", 1)
        out.append((key, re.compile(pat)))
    return out


def resolve_hooks(symbols_tsv: str, patterns, image: Path) -> tuple[dict, list[str]]:
    """匹配 nm|c++filt 输出 -> {key: {offset,mangled,demangled,sig_hex}}；缺失的进 missing。"""
    hooks, missing = {}, []
    for key, pat in patterns:
        hit = None
        for line in symbols_tsv.splitlines():
            parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            addr, _typ, demangled = parts
            if pat.search(demangled):
                hit = (int(addr, 16), demangled)
                break
        if not hit:
            missing.append(key)
            continue
        addr, demangled = hit
        # thin slice image_base=0 -> nm 地址即文件偏移
        with image.open("rb") as f:
            f.seek(addr)
            sig = f.read(SIG_BYTES).hex()
        hooks[key] = {
            "offset": hex(addr),
            "demangled": demangled,
            "sig_hex": sig,
        }
    return hooks, missing


def nm_dump(image: Path) -> str:
    nm = run(["nm", "-gU", str(image)]).stdout
    return run(["c++filt"], input=nm).stdout


def extract_cgi_table(core: Path) -> dict[str, int]:
    """核心库内嵌 <cgi reqid=..>name</cgi> 表 -> {name: cmdid}。"""
    strings = subprocess.run(
        ["strings", "-a", str(core)],
        capture_output=True,
        text=True,
        errors="replace",
    ).stdout
    table: dict[str, int] = {}
    for m in CGI_RE.finditer(strings):
        table.setdefault(m.group(2), int(m.group(1)))
    return table


def service_hints(core: Path) -> dict[str, bool]:
    strings = subprocess.run(
        ["strings", "-a", str(core)],
        capture_output=True,
        text=True,
        errors="replace",
    ).stdout
    return {s: (s in strings) for s in SERVICE_HINTS}


def find_core(app: Path, magicdy: str) -> tuple[Path, str]:
    if magicdy:
        p = MAGICDY_PLUGINS / magicdy / "extracted" / "wechat.dylib"
        if p.exists():
            return p, "magicdy-extracted"
    return app / "Contents/Resources/wechat.dylib", "bundle"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--app", default="/Applications/WeChat.app")
    ap.add_argument("--out", default=str(REPO / "profiles"))
    ap.add_argument("--deep", action="store_true", help="追加 REA/Ghidra 深度分析（慢）")
    args = ap.parse_args()

    app = Path(args.app)
    if not (app / "Contents/Info.plist").exists():
        sys.exit(f"wechat app not found: {app}")

    meta = detect_wechat(app)
    if not meta["magicdy_version"]:
        print("warn: 未找到 Magicdy 插件目录，核心库回退到 bundle 版", file=sys.stderr)
    core_path, core_source = find_core(app, meta["magicdy_version"])
    ilink_path = next(
        (app / "Contents/Resources/ilink2.framework/Versions").glob("*/ilink2")
    )

    tag = f"wechat-{meta['bundle_version']}-magicdy{meta['magicdy_version'] or 'none'}"
    core_thin = thin(core_path, RAW_DIR / f"core-{tag}-arm64.dylib")
    ilink_thin = thin(ilink_path, RAW_DIR / f"ilink2-{tag}-arm64")

    print(f"[1/4] {tag}")
    print(f"      core : {core_path} ({core_source})")
    print(f"      ilink: {ilink_path}")

    print("[2/4] 解析 ilink2 hook 符号…")
    hooks, missing = resolve_hooks(
        nm_dump(ilink_thin), load_patterns(), ilink_thin
    )
    for key in missing:
        print(f"      !! 未解析: {key}")

    print("[3/4] 提取核心库 CGI/cmdid 表 + 服务名…")
    cmdids = extract_cgi_table(core_thin)
    hints = service_hints(core_thin)

    profile = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "generator": "tools/gen_profile.py",
        "wechat": meta,
        "modules": {
            "core": {
                "path": str(core_path),
                "source": core_source,
                "size": core_path.stat().st_size,
                "sha256": sha256(core_path),
                "thin_sha256": sha256(core_thin),
            },
            "ilink2": {
                "path": str(ilink_path),
                "size": ilink_path.stat().st_size,
                "sha256": sha256(ilink_path),
                "thin_sha256": sha256(ilink_thin),
            },
        },
        "hooks": hooks,
        "hooks_missing": missing,
        "cgi_cmdids": cmdids,
        "service_hints": hints,
        "deep_analysis": {"status": "skipped"},
    }

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{tag}.json"
    out.write_text(json.dumps(profile, ensure_ascii=False, indent=2) + "\n")
    print(f"[4/4] 写出 {out}")
    print(f"      hooks: {len(hooks)} 解析 / {len(missing)} 缺失, cmdids: {len(cmdids)}")

    if args.deep:
        deep_dir = RAW_DIR / f"deep-{tag}"
        deep_dir.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env.setdefault("GHIDRA_INSTALL_DIR", str(Path.home() / "opt/ghidra_12.1.4_PUBLIC"))
        env.setdefault(
            "JAVA_HOME",
            str(Path.home() / "Library/Java/JavaVirtualMachines/openjdk-24.0.2/Contents/Home"),
        )
        env.setdefault("REA_GHIDRA_STARTUP_TIMEOUT_MS", "3600000")
        log = deep_dir / "deep.log"
        print(f"[deep] REA 分析核心库（日志 {log}，完成后重跑本脚本会回填状态）")
        proc = subprocess.Popen(
            ["npx", "rea-agents@latest", "analyze", str(core_thin), "--format", "json"],
            stdout=(deep_dir / "analyze-core.json").open("w"),
            stderr=log.open("w"),
            env=env,
            cwd=REPO,
        )
        profile["deep_analysis"] = {"status": "running", "pid": proc.pid}
        out.write_text(json.dumps(profile, ensure_ascii=False, indent=2) + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
