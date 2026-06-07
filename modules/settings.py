import logging
import os
import re

from flask import Blueprint, jsonify, render_template, request

logger = logging.getLogger(__name__)
settings_bp = Blueprint("settings", __name__)

ENV_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")

SETTINGS_KEYS = [
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "OLLAMA_ENDPOINT",
    "OLLAMA_MODEL",
    "OPENAI_MODEL",
    "CLAUDE_MODEL",
    "DEFAULT_PROVIDER",
]


def _mask(value: str) -> str:
    """Mask API keys for safe display."""
    if not value:
        return ""
    if len(value) <= 8:
        return "●" * len(value)
    return value[:4] + "●" * (len(value) - 8) + value[-4:]


def _read_env_file() -> dict:
    """Read current .env file into a dict."""
    env = {}
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, val = line.partition("=")
                    env[key.strip()] = val.strip().strip('"').strip("'")
    return env


def _write_env_file(env: dict):
    """Write updated settings back to .env file."""
    lines = []
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()

    updated_keys = set()
    new_lines = []

    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in env:
                new_lines.append(f'{key}={env[key]}\n')
                updated_keys.add(key)
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)

    # Add new keys not previously in file
    for key, val in env.items():
        if key not in updated_keys:
            new_lines.append(f'{key}={val}\n')

    with open(ENV_FILE, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

    # Reload into os.environ immediately
    for key, val in env.items():
        os.environ[key] = val

    logger.info("Settings saved and environment updated.")


@settings_bp.route("/", methods=["GET"])
def settings_page():
    return render_template("settings.html")


@settings_bp.route("/get", methods=["GET"])
def get_settings():
    """Return current settings with masked API keys."""
    env = _read_env_file()
    # Also include live env vars (may differ if set externally)
    for key in SETTINGS_KEYS:
        if key not in env:
            env[key] = os.environ.get(key, "")

    masked = {}
    for key in SETTINGS_KEYS:
        val = env.get(key, "")
        if "KEY" in key or "SECRET" in key or "TOKEN" in key:
            masked[key] = {"masked": _mask(val), "set": bool(val)}
        else:
            masked[key] = {"value": val, "set": bool(val)}

    return jsonify(masked)


@settings_bp.route("/save", methods=["POST"])
def save_settings():
    """Save new settings to .env file."""
    data = request.get_json()
    updates = {}

    for key in SETTINGS_KEYS:
        if key in data:
            val = str(data[key]).strip()
            # Skip empty values for API keys (don't overwrite with blank)
            if "KEY" in key and not val:
                continue
            updates[key] = val

    if not updates:
        return jsonify({"error": "No settings to save."}), 400

    try:
        _write_env_file(updates)
        return jsonify({"status": "saved", "updated": list(updates.keys())})
    except Exception as exc:
        logger.exception("Failed to save settings")
        return jsonify({"error": str(exc)}), 500


@settings_bp.route("/test", methods=["POST"])
def test_connection():
    """Test connectivity to Ollama endpoint."""
    import requests as req
    endpoint = os.environ.get("OLLAMA_ENDPOINT", "http://localhost:11434")
    try:
        resp = req.get(f"{endpoint}/api/tags", timeout=3)
        models = [m["name"] for m in resp.json().get("models", [])]
        return jsonify({"status": "connected", "models": models})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)})