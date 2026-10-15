import os
import re
import secrets
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Lua Restore Engine", version="1.0.0")
ENGINE_ROOT = Path(os.getenv("ENGINE_ROOT", "/opt/luraph-repo/Deobfuscator/deobf"))
INTERNAL_TOKEN = os.getenv("ENGINE_TOKEN", "")
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_OUTPUT_BYTES = 5 * 1024 * 1024
TIMEOUT = int(os.getenv("ENGINE_TIMEOUT_SECONDS", "180"))


class RequestBody(BaseModel):
    source: str = Field(min_length=1)
    version: Literal["auto", "14.7", "14.8", "14.9", "15.0"] = "auto"


def limit_child_resources():
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (TIMEOUT, TIMEOUT))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES))
        resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
        resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    except Exception:
        pass


def select_engine(source_path: Path, version: str):
    v14_cli = ENGINE_ROOT / "cli.py"
    v15_cli = ENGINE_ROOT / "deob.py"
    source_head = source_path.read_text(encoding="utf-8", errors="replace")[:16000]

    if version == "auto":
        match = re.search(r"Luraph\s+Obfuscator\s+v?(\d+\.\d+)", source_head, re.I)
        detected = match.group(1) if match else ""
        version = detected if detected in {"14.7", "14.8", "14.9", "15.0"} else "14.7"

    if version in {"14.7", "14.8", "14.9"}:
        if not v14_cli.is_file():
            raise HTTPException(status_code=503, detail="V14 CLI가 없습니다. 엔진 설치를 확인하세요.")
        return [
            "python3", str(v14_cli), str(source_path), "-o", str(output_path_placeholder()),
            "--engine", version
        ], version
    if version == "15.0":
        if not v15_cli.is_file():
            raise HTTPException(status_code=503, detail="V15 CLI가 없습니다. 엔진 설치를 확인하세요.")
        return [
            "python3", str(v15_cli), str(source_path), "-o", str(output_path_placeholder()),
            "--obfuscator", "luraph_v15"
        ], version
    raise HTTPException(status_code=400, detail="Unsupported version")


def output_path_placeholder():
    # Replaced by caller after creating request-specific temp paths.
    return Path("/tmp/lua-restore-output-placeholder.lua")


@app.get("/health")
def health():
    return {
        "ok": bool(INTERNAL_TOKEN) and ENGINE_ROOT.exists(),
        "service": "lua-restore-engine",
        "v14_cli_exists": (ENGINE_ROOT / "cli.py").is_file(),
        "v15_cli_exists": (ENGINE_ROOT / "deob.py").is_file(),
    }


@app.post("/v1/deobfuscate")
def deobfuscate(body: RequestBody, x_internal_token: str = Header(default="")):
    if not INTERNAL_TOKEN or not secrets.compare_digest(x_internal_token, INTERNAL_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized")
    source_bytes = body.source.encode("utf-8")
    if len(source_bytes) > MAX_SOURCE_BYTES:
        raise HTTPException(status_code=413, detail="소스는 2 MiB 이하만 지원합니다.")
    if "\x00" in body.source:
        raise HTTPException(status_code=400, detail="NUL 문자가 포함되어 있습니다.")

    request_id = secrets.token_hex(8)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="lua-restore-") as tmp:
        work = Path(tmp)
        source_path = work / "input.lua"
        output_path = work / "recovered.lua"
        source_path.write_text(body.source, encoding="utf-8")

        chosen = body.version
        if chosen == "auto":
            head = body.source[:16000]
            m = re.search(r"Luraph\s+Obfuscator\s+v?(\d+\.\d+)", head, re.I)
            chosen = m.group(1) if m and m.group(1) in {"14.7", "14.8", "14.9", "15.0"} else "14.7"

        if chosen in {"14.7", "14.8", "14.9"}:
            cli = ENGINE_ROOT / "cli.py"
            command = ["python3", str(cli), str(source_path), "-o", str(output_path), "--engine", chosen]
        else:
            cli = ENGINE_ROOT / "deob.py"
            command = ["python3", str(cli), str(source_path), "-o", str(output_path), "--obfuscator", "luraph_v15"]

        if not cli.is_file():
            raise HTTPException(status_code=503, detail=f"엔진 CLI를 찾을 수 없습니다: {cli.name}")

        env = {
            "PATH": os.getenv("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": str(work),
            "TMPDIR": str(work),
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "DEOB_NO_FETCH": "1",
        }
        try:
            proc = subprocess.run(
                command, cwd=str(ENGINE_ROOT), env=env,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                timeout=TIMEOUT, check=False,
                preexec_fn=limit_child_resources if os.name == "posix" else None,
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=504, detail=f"시간 제한({TIMEOUT}s)을 초과했습니다.")
        except OSError:
            raise HTTPException(status_code=503, detail="복원 엔진 실행에 실패했습니다.")

        log_tail = (proc.stdout or "")[-8000:]
        recovered = ""
        if output_path.is_file():
            if output_path.stat().st_size > MAX_OUTPUT_BYTES:
                raise HTTPException(status_code=502, detail="출력 크기가 제한을 초과했습니다.")
            recovered = output_path.read_text(encoding="utf-8", errors="replace")

        if proc.returncode != 0 or not recovered.strip():
            return {
                "ok": False, "request_id": request_id, "engine": chosen,
                "status": "failed", "message": "엔진이 결과를 만들지 못했습니다.",
                "engine_log": log_tail, "elapsed_seconds": round(time.monotonic() - started, 2)
            }

        return {
            "ok": True, "request_id": request_id, "engine": chosen,
            "status": "completed_unverified",
            "message": "결과 파일을 생성했습니다. 완전 복원 여부는 별도 검증이 필요합니다.",
            "recovered_source": recovered,
            "output_bytes": len(recovered.encode("utf-8")),
            "engine_log": log_tail,
            "elapsed_seconds": round(time.monotonic() - started, 2),
        }
