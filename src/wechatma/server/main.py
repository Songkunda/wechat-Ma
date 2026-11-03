"""Central server entrypoint.

Routes external API calls to per-process WeChat agents over local sockets.
Agents are injected dylibs; none exist yet at M0, so instance lists are empty
and message endpoints return structured errors.
"""

from pathlib import Path

from fastapi import FastAPI

from wechatma import __version__
from wechatma.profiles import (
    UnsupportedVersionError,
    detect_wechat,
    load_runtime_config,
    resolve_profile,
)

REPO = Path(__file__).resolve().parents[3]
CONFIG = load_runtime_config(REPO)

app = FastAPI(title="wechatma", version=__version__)


@app.get("/api/health")
def health() -> dict:
    out: dict = {"status": "ok", "version": __version__, "instances": []}
    try:
        detected = detect_wechat(CONFIG.get("wechat_app", "/Applications/WeChat.app"))
        out["wechat"] = {
            "version": detected.version,
            "build": detected.build,
            "magicdy": detected.magicdy,
        }
        try:
            resolved = resolve_profile(
                REPO / CONFIG.get("profiles_dir", "profiles"), detected
            )
            out["profile"] = {"key": resolved.profile_key, "match": resolved.match}
        except UnsupportedVersionError as e:
            out["status"] = "degraded"
            out["error"] = {"code": "UNSUPPORTED_VERSION", "message": str(e)}
    except FileNotFoundError:
        out["status"] = "degraded"
        out["error"] = {"code": "WECHAT_NOT_RUNNING", "message": "WeChat.app not found"}
    return out


@app.get("/api/profile")
def profile() -> dict:
    resolved = resolve_profile(REPO / CONFIG.get("profiles_dir", "profiles"))
    return {"key": resolved.profile_key, "match": resolved.match, "profile": resolved.data}
