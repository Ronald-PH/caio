import logging
import os
import time

import requests

logger = logging.getLogger(__name__)

# ── Cost rates ($/1K tokens) — override via .env ─────────────────────────────
OPENAI_INPUT_RATE  = float(os.environ.get("OPENAI_INPUT_RATE",  "0.005"))
OPENAI_OUTPUT_RATE = float(os.environ.get("OPENAI_OUTPUT_RATE", "0.015"))
CLAUDE_INPUT_RATE  = float(os.environ.get("CLAUDE_INPUT_RATE",  "0.003"))
CLAUDE_OUTPUT_RATE = float(os.environ.get("CLAUDE_OUTPUT_RATE", "0.015"))


# ── Helper ────────────────────────────────────────────────────────────────────

def _get(key: str, default: str = "") -> str:
    value = os.environ.get(key)
    if value is None or value.strip() == "":
        return default
    return value


def _retry(fn, retries: int = 2, backoff: float = 1.5):
    """Call fn() with exponential-backoff retry on exception."""
    last_exc = None
    for attempt in range(retries + 1):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if attempt < retries:
                sleep = backoff ** attempt
                logger.warning("Retry %d/%d in %.1fs: %s", attempt + 1, retries, sleep, exc)
                time.sleep(sleep)
    raise last_exc


# ── Token helpers ─────────────────────────────────────────────────────────────

def _count_tokens_openai(prompt: str, response: str, model: str) -> tuple[int, int]:
    """Use tiktoken for precise token counts."""
    try:
        import tiktoken
        try:
            enc = tiktoken.encoding_for_model(model)
        except KeyError:
            enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(prompt)), len(enc.encode(response))
    except ImportError:
        # Fallback: ~4 chars/token
        return len(prompt) // 4, len(response) // 4


def _count_tokens_claude(prompt: str, response: str) -> tuple[int, int]:
    """Approximate: ~4 chars/token (Anthropic's rule of thumb)."""
    return len(prompt) // 4, len(response) // 4


def _count_tokens_ollama(response: str) -> tuple[int, int]:
    """Word-count estimate for local models (no cost)."""
    return 0, len(response.split())


def calc_cost(provider: str, input_tokens: int, output_tokens: int) -> float:
    """Return estimated USD cost for a given API call."""
    if provider == "openai":
        return (input_tokens / 1000 * OPENAI_INPUT_RATE) + (output_tokens / 1000 * OPENAI_OUTPUT_RATE)
    elif provider in ("claude", "anthropic"):
        return (input_tokens / 1000 * CLAUDE_INPUT_RATE) + (output_tokens / 1000 * CLAUDE_OUTPUT_RATE)
    return 0.0  # Ollama is free


# ── Ollama ────────────────────────────────────────────────────────────────────

def call_ollama(prompt: str, model: str = None, system: str = None) -> tuple[str, int, float]:
    """Returns (response_text, tokens_used, cost_estimate)."""
    endpoint = _get("OLLAMA_ENDPOINT", "http://localhost:11434")
    if not endpoint.strip():
        endpoint = "http://localhost:11434"
    if not endpoint.startswith(("http://", "https://")):
        endpoint = "http://" + endpoint

    model = model or _get("OLLAMA_MODEL", "llama3.2")
    url = f"{endpoint.rstrip('/')}/api/generate"
    full_prompt = f"{system}\n\n{prompt}" if system else prompt
    payload = {"model": model, "prompt": full_prompt, "stream": False}

    def _call():
        logger.info("[Ollama] POST %s | model=%s", url, model)
        resp = requests.post(url, json=payload, timeout=120)
        resp.raise_for_status()
        return resp.json().get("response", "[Ollama returned empty response]")

    try:
        text = _retry(_call)
    except requests.exceptions.ConnectionError:
        msg = (
            f"⚠️ Cannot connect to Ollama at {endpoint}. "
            "Make sure 'ollama serve' is running."
        )
        logger.error(msg)
        return msg, 0, 0.0
    except Exception as exc:
        logger.exception("Ollama call failed")
        return f"⚠️ Ollama error: {exc}", 0, 0.0

    _, out_tokens = _count_tokens_ollama(text)
    return text, out_tokens, 0.0


# ── OpenAI ────────────────────────────────────────────────────────────────────

def call_openai(prompt: str, model: str = None, system: str = None) -> tuple[str, int, float]:
    try:
        import openai
    except ImportError:
        return "⚠️ 'openai' package not installed. Run: pip install openai", 0, 0.0

    api_key = _get("OPENAI_API_KEY")
    if not api_key:
        return "⚠️ OPENAI_API_KEY is not set. Configure it in Settings.", 0, 0.0

    model = model or _get("OPENAI_MODEL", "gpt-4o")
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    def _call():
        client = openai.OpenAI(api_key=api_key)
        logger.info("[OpenAI] model=%s", model)
        return client.chat.completions.create(model=model, messages=messages, max_tokens=2048)

    try:
        response = _retry(_call)
    except Exception as exc:
        logger.exception("OpenAI call failed")
        if "authentication" in str(exc).lower():
            return "⚠️ OpenAI authentication failed. Check your API key.", 0, 0.0
        return f"⚠️ OpenAI error: {exc}", 0, 0.0

    text = response.choices[0].message.content
    # Use response usage if available
    if hasattr(response, "usage") and response.usage:
        in_tok  = response.usage.prompt_tokens
        out_tok = response.usage.completion_tokens
    else:
        in_tok, out_tok = _count_tokens_openai(prompt, text, model)

    total_tokens = in_tok + out_tok
    cost = calc_cost("openai", in_tok, out_tok)
    return text, total_tokens, cost


# ── Anthropic Claude ──────────────────────────────────────────────────────────

def call_claude(prompt: str, model: str = None, system: str = None) -> tuple[str, int, float]:
    try:
        import anthropic
    except ImportError:
        return "⚠️ 'anthropic' package not installed. Run: pip install anthropic", 0, 0.0

    api_key = _get("ANTHROPIC_API_KEY")
    if not api_key:
        return "⚠️ ANTHROPIC_API_KEY is not set. Configure it in Settings.", 0, 0.0

    model = model or _get("CLAUDE_MODEL", "claude-sonnet-4-20250514")
    kwargs = {
        "model": model,
        "max_tokens": 2048,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        kwargs["system"] = system

    def _call():
        client = anthropic.Anthropic(api_key=api_key)
        logger.info("[Claude] model=%s", model)
        return client.messages.create(**kwargs)

    try:
        response = _retry(_call)
    except Exception as exc:
        logger.exception("Claude call failed")
        if "authentication" in str(exc).lower():
            return "⚠️ Anthropic authentication failed. Check your API key.", 0, 0.0
        return f"⚠️ Claude error: {exc}", 0, 0.0

    text = response.content[0].text
    # Use Anthropic usage object if present
    if hasattr(response, "usage") and response.usage:
        in_tok  = response.usage.input_tokens
        out_tok = response.usage.output_tokens
    else:
        in_tok, out_tok = _count_tokens_claude(prompt, text)

    total_tokens = in_tok + out_tok
    cost = calc_cost("claude", in_tok, out_tok)
    return text, total_tokens, cost


# ── Dispatcher ────────────────────────────────────────────────────────────────

def query_ai(
    prompt: str,
    provider: str = None,
    model: str = None,
    system: str = None,
) -> str:
    """
    Route to the correct AI provider. Returns response text only.
    Use query_ai_full() when you need token/cost data.
    """
    text, _, _ = query_ai_full(prompt, provider=provider, model=model, system=system)
    return text


def query_ai_full(
    prompt: str,
    provider: str = None,
    model: str = None,
    system: str = None,
) -> tuple[str, int, float]:
    """
    Returns (response_text, tokens_used, cost_estimate).
    provider: "ollama" | "openai" | "claude"
    """
    provider = (provider or _get("DEFAULT_PROVIDER", "ollama")).lower()

    if provider == "openai":
        return call_openai(prompt, model=model, system=system)
    elif provider in ("claude", "anthropic"):
        return call_claude(prompt, model=model, system=system)
    else:
        return call_ollama(prompt, model=model, system=system)
