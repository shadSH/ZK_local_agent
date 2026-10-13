import asyncio
import base64
from typing import List

from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pyzkfp import ZKFP2

app = FastAPI()

# --- Enable CORS for your production domain and local development ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://ettc-rms.com",
        "http://localhost",
        "http://127.0.0.1",
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Initialize the SDK engine ONCE globally ---
zkfp2 = ZKFP2()
zkfp2.Init()

# Serialize all SDK access (capture + match) — run uvicorn with workers=1 only
sdk_lock = asyncio.Lock()

# Minimum score to treat as a real match (tune if needed)
MATCH_SCORE_THRESHOLD = 1


# --- Pydantic Models ---
class TemplateRecord(BaseModel):
    id: int  # This will represent the Case ID or Case Number
    template: str


class ProbeRecord(BaseModel):
    key: str
    template: str


class MatchRequest(BaseModel):
    new_template: str
    database_templates: List[TemplateRecord]


class MatchBatchRequest(BaseModel):
    probes: List[ProbeRecord]
    database_templates: List[TemplateRecord]


class VerifyRequest(BaseModel):
    database_templates: List[TemplateRecord]


def build_gallery(database_templates: List[TemplateRecord]) -> None:
    zkfp2.DBInit()
    for record in database_templates:
        try:
            tmp_bytes = bytearray(base64.b64decode(record.template))
            zkfp2.DBAdd(record.id, tmp_bytes)
        except Exception:
            continue


def identify_template(template_b64: str) -> tuple[int, int]:
    tmp_bytes = bytearray(base64.b64decode(template_b64))
    return zkfp2.DBIdentify(tmp_bytes)


def free_gallery() -> None:
    try:
        zkfp2.DBFree()
    except Exception:
        pass


# ---------------------------------------------------------
# 0. HEALTH CHECK & WALK-IN VERIFY ENDPOINTS
# ---------------------------------------------------------
@app.get("/health")
async def health_check():
    device_count = 0
    try:
        device_count = zkfp2.GetDeviceCount()
    except Exception:
        pass
    return {
        "status": "online",
        "device_connected": device_count > 0,
        "device_count": device_count,
    }


@app.post("/verify")
async def verify_walk_in(request: VerifyRequest):
    """Captures a fingerprint from the physical scanner and matches it 1:N against the provided database templates."""
    if not request.database_templates:
        return {"success": False, "message": "No active cases with templates provided."}

    async with sdk_lock:
        device_count = 0
        try:
            device_count = zkfp2.GetDeviceCount()
        except Exception:
            pass

        if device_count == 0:
            raise HTTPException(status_code=400, detail="No fingerprint scanner detected.")

        try:
            zkfp2.OpenDevice(0)
            build_gallery(request.database_templates)

            # Wait up to 10 seconds for user to place finger
            timeout_counter = 0
            captured_template_b64 = None

            while timeout_counter < 100:  # 100 * 0.1s = 10 seconds
                capture = zkfp2.AcquireFingerprint()
                if capture:
                    tmp, img = capture
                    captured_template_b64 = base64.b64encode(bytes(tmp)).decode("utf-8")
                    break
                await asyncio.sleep(0.1)
                timeout_counter += 1

            if not captured_template_b64:
                return {"success": False, "message": "Fingerprint scan timed out. Try again."}

            # Perform 1:N Identification against the gallery
            matched_id, score = identify_template(captured_template_b64)

            if matched_id and score >= MATCH_SCORE_THRESHOLD:
                return {
                    "success": True,
                    "matched_case_id": matched_id,
                    "score": score,
                }

            return {"success": False, "message": "Fingerprint not recognized in pending payment records."}

        except Exception as e:
            return {"success": False, "message": str(e)}

        finally:
            free_gallery()
            try:
                zkfp2.CloseDevice()
            except Exception:
                pass


# ---------------------------------------------------------
# 1. WEBSOCKET: Capture Fingerprint (Frontend Live Preview)
# ---------------------------------------------------------
@app.websocket("/ws/fingerprint")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    async with sdk_lock:
        if zkfp2.GetDeviceCount() == 0:
            await websocket.send_json({"status": "error", "message": "No scanner found."})
            await websocket.close()
            return

        zkfp2.OpenDevice(0)
        await websocket.send_json({"status": "ready", "message": "Place finger on scanner..."})

        try:
            while True:
                capture = zkfp2.AcquireFingerprint()
                if capture:
                    tmp, img = capture
                    template_b64 = base64.b64encode(bytes(tmp)).decode("utf-8")
                    await websocket.send_json({"status": "success", "template": template_b64})
                    break
                await asyncio.sleep(0.1)
        except Exception as e:
            await websocket.send_json({"status": "error", "message": str(e)})
        finally:
            try:
                zkfp2.CloseDevice()
            except Exception:
                pass
            await websocket.close()


# ---------------------------------------------------------
# 2. API ENDPOINT: 1:N Duplication Check (Backend, single probe)
# ---------------------------------------------------------
@app.post("/api/match")
async def match_fingerprint(request: MatchRequest):
    if not request.database_templates:
        return {"is_duplicate": False}

    async with sdk_lock:
        try:
            build_gallery(request.database_templates)
            matched_id, score = identify_template(request.new_template)

            if matched_id and score >= MATCH_SCORE_THRESHOLD:
                return {
                    "is_duplicate": True,
                    "matched_case_id": matched_id,
                    "score": score,
                }

            return {"is_duplicate": False}

        except Exception:
            return {"is_duplicate": False}

        finally:
            free_gallery()


# ---------------------------------------------------------
# 3. API ENDPOINT: 1:N Duplication Check (Backend, batch probes)
# ---------------------------------------------------------
@app.post("/api/match-batch")
async def match_fingerprint_batch(request: MatchBatchRequest):
    if not request.probes or not request.database_templates:
        return {"is_duplicate": False}

    async with sdk_lock:
        try:
            build_gallery(request.database_templates)

            for probe in request.probes:
                matched_id, score = identify_template(probe.template)

                if matched_id and score >= MATCH_SCORE_THRESHOLD:
                    return {
                        "is_duplicate": True,
                        "probe_key": probe.key,
                        "matched_case_id": matched_id,
                        "score": score,
                    }

            return {"is_duplicate": False}

        except Exception:
            return {"is_duplicate": False}

        finally:
            free_gallery()


if __name__ == "__main__":
    import uvicorn

    # IMPORTANT: keep workers=1 because the ZK SDK is not thread-safe
    uvicorn.run(app, host="127.0.0.1", port=8000, workers=1)