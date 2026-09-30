import os
import re
import base64
import binascii
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

app = FastAPI(
    title="Lua Deobfuscator API",
    version="2.0.0",
    description="Static Lua deobfuscation pipeline. Submitted Lua is never executed."
)

MAX_INPUT = 1_000_000
MAX_PASSES = 3

class DeobfuscateRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=MAX_INPUT)
    ai: bool = True
    passes: int = Field(default=2, ge=1, le=MAX_PASSES)

def static_pass(code: str):
    findings = []

    patterns = [
        (r'\bloadstring\b', "loadstring detected"),
        (r'\bload\s*\(', "load() detected"),
        (r'\bloadfile\b', "loadfile detected"),
        (r'\bdofile\b', "dofile detected"),
        (r'\bos\.execute\b', "os.execute detected"),
        (r'\bio\.popen\b', "io.popen detected"),
        (r'\bdebug\.', "debug library usage detected"),
        (r'\bHttpGet\b', "HttpGet detected"),
        (r'\brequest\s*\(', "request() detected"),
        (r'\bgetgenv\s*\(', "getgenv() detected"),
        (r'\bgetfenv\s*\(', "getfenv() detected"),
    ]

    for pattern, message in patterns:
        if re.search(pattern, code, re.IGNORECASE):
            findings.append(message)

    if re.search(r"MoonSec", code, re.IGNORECASE):
        findings.append("MoonSec marker detected")

    decoded_strings = []

    # Static Base64 decoding only. No decoded Lua is executed.
    string_pattern = re.compile(r'(["\'])([A-Za-z0-9+/]{16,}={0,2})\1')
    for match in string_pattern.finditer(code):
        raw = match.group(2)
        try:
            decoded = base64.b64decode(raw, validate=True)
            text = decoded.decode("utf-8")
            printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / max(1, len(text))
            if printable >= 0.90 and text.strip():
                decoded_strings.append({"encoded": raw[:120], "decoded": text[:2000]})
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass

    cleaned = code.replace("\r\n", "\n").replace("\r", "\n")
    cleaned = re.sub(r'--[^\n]*', '', cleaned)
    cleaned = re.sub(r'\n{3,}', '\n\n', cleaned).strip()

    return cleaned, findings, decoded_strings[:100]

def ai_pass(code: str):
    if OpenAI is None:
        raise RuntimeError("openai package is not installed")

    key = os.getenv("OPENAI_API_KEY")
    if not key:
        raise RuntimeError("OPENAI_API_KEY is not configured")

    model = os.getenv("OPENAI_MODEL", "gpt-5")
    client = OpenAI(api_key=key)

    instructions = """You are a Lua static deobfuscation assistant.
Analyze the supplied Lua source and return ONLY Lua source code.

Rules:
- NEVER execute the supplied program.
- Do not invent missing code.
- Preserve behavior as closely as possible.
- Decode obvious literal encodings and simplify constant expressions when safe.
- Rename meaningless temporary identifiers only when it clearly improves readability.
- Remove obvious obfuscation scaffolding when its meaning is certain.
- Do not remove security checks or runtime behavior merely because it looks unusual.
- If a transformation cannot be established statically, leave that portion unchanged.
- Do not wrap the answer in Markdown fences.
- The input may itself be the output of another obfuscation layer."""

    response = client.responses.create(
        model=model,
        instructions=instructions,
        input=code,
        store=False,
    )
    result = response.output_text.strip()
    if result.startswith("```"):
        result = re.sub(r"^```(?:lua)?\s*", "", result, flags=re.I)
        result = re.sub(r"\s*```$", "", result)
    return result.strip()

@app.get("/api/health")
def health():
    return {
        "ok": True,
        "service": "lua-deobfuscator",
        "ai_configured": bool(os.getenv("OPENAI_API_KEY"))
    }

@app.post("/api/deobfuscate")
def deobfuscate(payload: DeobfuscateRequest):
    current = payload.code
    all_findings = []
    decoded = []
    pass_log = []

    try:
        # Local static pass first.
        current, findings, strings = static_pass(current)
        all_findings.extend(findings)
        decoded.extend(strings)
        pass_log.append({"pass": 0, "type": "static", "changed": True})

        # Optional recursive AI passes. Each pass receives the previous pass output,
        # so double/triple obfuscation gets multiple opportunities to simplify.
        if payload.ai and os.getenv("OPENAI_API_KEY"):
            for i in range(1, payload.passes + 1):
                before = current
                candidate = ai_pass(current)

                if not candidate:
                    break

                changed = candidate != before
                current = candidate
                pass_log.append({
                    "pass": i,
                    "type": "ai",
                    "changed": changed,
                    "chars": len(current)
                })

                if not changed:
                    break

                # Re-run cheap static analysis after every AI pass.
                current, findings, strings = static_pass(current)
                all_findings.extend(findings)
                decoded.extend(strings)

        else:
            pass_log.append({
                "pass": 1,
                "type": "ai",
                "changed": False,
                "skipped": True,
                "reason": "OPENAI_API_KEY not configured or ai=false"
            })

        # Final analysis after all passes.
        _, final_findings, final_strings = static_pass(current)
        all_findings.extend(final_findings)
        decoded.extend(final_strings)

        unique_findings = list(dict.fromkeys(all_findings))
        unique_strings = []
        seen = set()
        for item in decoded:
            key = (item["encoded"], item["decoded"])
            if key not in seen:
                seen.add(key)
                unique_strings.append(item)

        return {
            "success": True,
            "code": current,
            "findings": unique_findings,
            "warnings": [
                "Lua was never executed by this server.",
                "AI output is a static transformation and should be reviewed before use."
            ],
            "decoded_strings": unique_strings[:100],
            "passes": pass_log,
            "stats": {
                "input_chars": len(payload.code),
                "output_chars": len(current)
            }
        }

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.get("/")
def index():
    return FileResponse("static/index.html")

app.mount("/static", StaticFiles(directory="static"), name="static")
