"""
ETTC ZK9500 fingerprint bridge.

One codebase, three roles (env BRIDGE_ROLE):

  capture  Runs on every registration / cashier workstation that has a ZK9500.
           Exposes only the WebSocket capture endpoint to the ETTC page in the
           browser. Every connection must present a short-lived, single-use
           ticket signed by Laravel (HMAC, BRIDGE_TICKET_SECRET).

  matcher  Runs once, on a host the Laravel server can reach. Holds the
           persistent 1:N gallery in the SDK's in-memory cache and answers
           duplicate checks. Every call needs the server token
           (Authorization: Bearer BRIDGE_API_TOKEN).

  all      Both roles in one process, for a single-machine / development setup.

Design rules
  * All ZK SDK calls run on ONE dedicated thread. The SDK is not thread-safe
    and its calls block; they must never run on the asyncio event loop.
  * The gallery is never written to disk. Laravel's database is the source of
    truth; after a restart the matcher reports "empty" and Laravel resyncs it.
  * Errors never reach the client as raw exception text. They are logged with
    an error id; the client gets a generic message and that id.
  * Duplicate checks fail closed: if matching cannot run, the bridge answers
    503, never "no duplicate".
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.websockets import WebSocketDisconnect, WebSocketState

log = logging.getLogger("zk_bridge")

MAX_FID = 2_147_483_647  # the SDK stores template ids as 32-bit ints
SDK_NO_MATCH = -17  # DBIdentify: "operation failed" = nothing matched


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------
def _env_csv(name: str, default: str) -> Tuple[str, ...]:
    raw = os.getenv(name, default)
    return tuple(item.strip().rstrip("/") for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    role: str = "all"
    host: str = "127.0.0.1"
    port: int = 8000
    allowed_origins: Tuple[str, ...] = (
        "https://ettc-rms.com",
        "https://www.ettc-rms.com",
        "http://localhost",
        "http://127.0.0.1",
        "http://localhost:8000",
    )
    api_token: str = ""
    ticket_secret: str = ""
    capture_timeout_seconds: float = 15.0
    auth_timeout_seconds: float = 5.0
    match_score_threshold: int = 1
    max_ticket_ttl_seconds: int = 120
    max_adhoc_gallery: int = 500
    max_body_bytes: int = 25 * 1024 * 1024
    max_template_chars: int = 8192

    @property
    def capture_enabled(self) -> bool:
        return self.role in ("capture", "all")

    @property
    def matcher_enabled(self) -> bool:
        return self.role in ("matcher", "all")

    @classmethod
    def from_env(cls) -> "Settings":
        defaults = cls()
        return cls(
            role=os.getenv("BRIDGE_ROLE", defaults.role).strip().lower(),
            host=os.getenv("BRIDGE_HOST", defaults.host),
            port=int(os.getenv("BRIDGE_PORT", str(defaults.port))),
            allowed_origins=_env_csv("BRIDGE_ALLOWED_ORIGINS", ",".join(defaults.allowed_origins)),
            api_token=os.getenv("BRIDGE_API_TOKEN", ""),
            ticket_secret=os.getenv("BRIDGE_TICKET_SECRET", ""),
            capture_timeout_seconds=float(os.getenv("CAPTURE_TIMEOUT_SECONDS", "15")),
            match_score_threshold=int(os.getenv("FINGERPRINT_MATCH_MIN_SCORE", "1")),
            max_adhoc_gallery=int(os.getenv("MAX_ADHOC_GALLERY", "500")),
        )

    def validate(self) -> None:
        if self.role not in ("capture", "matcher", "all"):
            raise RuntimeError("BRIDGE_ROLE must be capture, matcher or all.")
        # Fail secure: refuse to start rather than run without authentication.
        if self.matcher_enabled and len(self.api_token) < 32:
            raise RuntimeError("BRIDGE_API_TOKEN must be set (at least 32 characters).")
        if self.capture_enabled and len(self.ticket_secret) < 32:
            raise RuntimeError("BRIDGE_TICKET_SECRET must be set (at least 32 characters).")
        if "*" in self.allowed_origins:
            raise RuntimeError("BRIDGE_ALLOWED_ORIGINS must list explicit origins, not '*'.")


# --------------------------------------------------------------------------
# Errors that map to client responses (never carry internal details)
# --------------------------------------------------------------------------
class BridgeError(Exception):
    status_code = 500
    code = "internal_error"
    public_message = "Internal bridge error."


class ScannerUnavailable(BridgeError):
    status_code = 503
    code = "scanner_unavailable"
    public_message = "No fingerprint scanner detected."


class SdkFailure(BridgeError):
    status_code = 503
    code = "matching_unavailable"
    public_message = "Fingerprint matching is temporarily unavailable."


class GalleryNotReady(BridgeError):
    status_code = 503
    code = "gallery_not_ready"
    public_message = "The fingerprint gallery is still loading."


class InvalidTemplate(BridgeError):
    status_code = 422
    code = "invalid_template"
    public_message = "A fingerprint template is not valid."


class InvalidTicket(Exception):
    pass


def decode_template(template_b64: str, max_chars: int) -> bytearray:
    if not template_b64 or len(template_b64) > max_chars:
        raise InvalidTemplate()
    try:
        raw = base64.b64decode(template_b64, validate=True)
    except (binascii.Error, ValueError):
        raise InvalidTemplate() from None
    if len(raw) < 16:
        raise InvalidTemplate()
    return bytearray(raw)


# --------------------------------------------------------------------------
# ZK SDK adapter
# --------------------------------------------------------------------------
class ZkSdk:
    """
    Owns the ZK library. Methods without `async` run ONLY on the SDK thread
    (call them through `await sdk.run(...)`).

    Uses its own algorithm-cache handles through the raw .NET API. pyzkfp keeps
    a single `dbHandle` that OpenDevice() silently replaces with a fresh
    DBInit() on every call, which (a) leaked one native cache per scan in the
    old code and (b) would wipe any gallery stored in that handle.
    """

    def __init__(self, factory: Optional[Callable[[], Any]] = None) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="zkfp")
        self._factory = factory
        self._zk: Any = None
        self._raw: Any = None
        self._device_open = False

    async def run(self, fn: Callable[..., Any], *args: Any) -> Any:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, fn, *args)

    # --- lifecycle (SDK thread) -------------------------------------------
    def init(self) -> None:
        if self._factory is None:
            from pyzkfp import ZKFP2  # Windows only (pythonnet + libzkfpcsharp)

            self._factory = ZKFP2
        self._zk = self._factory()
        self._zk.Init()
        self._raw = self._zk.zkfp2

    def shutdown(self) -> None:
        self.close_device()
        try:
            self._zk.Terminate()
        except Exception:
            log.warning("ZK SDK terminate failed", exc_info=True)

    # --- device (SDK thread) ----------------------------------------------
    def device_count(self) -> int:
        try:
            return int(self._zk.GetDeviceCount())
        except Exception:
            log.warning("GetDeviceCount failed", exc_info=True)
            return 0

    def _ensure_device_open(self) -> None:
        if self._device_open:
            return
        if self.device_count() == 0:
            raise ScannerUnavailable()
        self._zk.OpenDevice(0)
        stray = getattr(self._zk, "dbHandle", None)
        if stray:
            try:
                self._raw.DBFree(stray)
            except Exception:
                log.warning("Could not free the cache created by OpenDevice", exc_info=True)
            self._zk.dbHandle = None
        self._device_open = True

    def close_device(self) -> None:
        if not self._device_open:
            return
        self._device_open = False
        try:
            self._zk.CloseDevice()
        except Exception:
            log.warning("CloseDevice failed", exc_info=True)

    def acquire_once(self) -> Optional[str]:
        """One capture attempt: a base64 template, or None when no finger is on the sensor."""
        try:
            self._ensure_device_open()
            capture = self._zk.AcquireFingerprint()
        except ScannerUnavailable:
            raise
        except Exception as exc:
            self.close_device()  # reopen on the next attempt (unplugged, driver reset, ...)
            raise ScannerUnavailable() from exc
        if not capture:
            return None
        template, _image = capture
        return base64.b64encode(bytes(template)).decode("ascii")

    # --- algorithm cache primitives (SDK thread) --------------------------
    def cache_new(self) -> Any:
        handle = self._raw.DBInit()
        if not handle:
            raise SdkFailure()
        return handle

    def cache_free(self, handle: Any) -> None:
        try:
            self._raw.DBFree(handle)
        except Exception:
            log.warning("DBFree failed", exc_info=True)

    def cache_add(self, handle: Any, fid: int, template: bytearray) -> bool:
        try:
            return self._raw.DBAdd(handle, fid, template) == 0
        except Exception:
            log.warning("DBAdd raised for template %s", fid, exc_info=True)
            return False

    def cache_del(self, handle: Any, fid: int) -> None:
        try:
            self._raw.DBDel(handle, fid)
        except Exception:
            log.warning("DBDel raised for template %s", fid, exc_info=True)

    def cache_identify(self, handle: Any, template: bytearray) -> Tuple[int, int]:
        try:
            ret, fid, score = self._raw.DBIdentify(handle, template, 0, 0)
        except Exception as exc:
            raise SdkFailure() from exc
        if ret == 0:
            return int(fid), int(score)
        if ret == SDK_NO_MATCH:
            return 0, 0
        log.error("DBIdentify returned %s", ret)
        raise SdkFailure()


# --------------------------------------------------------------------------
# Persistent gallery (all methods run on the SDK thread)
# --------------------------------------------------------------------------
@dataclass
class CaseEntry:
    version: int
    templates: Dict[int, bytearray] = field(default_factory=dict)  # accepted by the SDK
    declared: Tuple[int, ...] = ()  # every template id Laravel sent (for the checksum)


class Gallery:
    """
    Mirror of Laravel's "submitted, scanned" fingerprints, kept in one SDK
    cache handle for the life of the process.

    Membership is decided by Laravel; the bridge only applies per-case
    replacements. Every update carries a version (Laravel's last change time in
    ms) so late or replayed updates cannot overwrite newer data, including
    updates that race with a full resync.
    """

    EMPTY, LOADING, READY = "empty", "loading", "ready"

    def __init__(self, sdk: ZkSdk) -> None:
        self._sdk = sdk
        self._handle: Any = None
        self._cases: Dict[int, CaseEntry] = {}
        self._template_case: Dict[int, int] = {}
        self._tombstones: Dict[int, int] = {}
        self.state = self.EMPTY
        self.generation: Optional[str] = None
        self.needs_resync = False

    # --- full sync --------------------------------------------------------
    def begin_sync(self, generation: str) -> None:
        if self._handle is not None:
            self._sdk.cache_free(self._handle)
        self._handle = self._sdk.cache_new()
        self._cases.clear()
        self._template_case.clear()
        self._tombstones.clear()
        self.state = self.LOADING
        self.generation = generation
        self.needs_resync = False

    def commit_sync(self, generation: str, expected_cases: int, expected_templates: int, checksum: str) -> bool:
        if generation != self.generation or self.state == self.EMPTY:
            return False
        status = self.status()
        if (
            status["cases"] == expected_cases
            and status["templates"] == expected_templates
            and hmac.compare_digest(status["checksum"], checksum.lower())
        ):
            self.state = self.READY
            return True
        return False

    # --- incremental updates ---------------------------------------------
    def upsert_case(self, case_id: int, version: int, templates: List[Tuple[int, bytearray]]) -> Dict[str, Any]:
        if not templates:
            return self.remove_case(case_id, version)
        if self._is_stale(case_id, version):
            return {"applied": False, "reason": "stale"}
        handle = self._ensure_handle()
        self._drop_case_templates(case_id)

        entry = CaseEntry(version=version, declared=tuple(sorted(fid for fid, _ in templates)))
        rejected: List[int] = []
        for fid, template in templates:
            owner = self._template_case.get(fid)
            if owner is not None and owner != case_id:
                self._drop_template(owner, fid)
            if self._sdk.cache_add(handle, fid, template):
                entry.templates[fid] = template
                self._template_case[fid] = case_id
            else:
                rejected.append(fid)

        # Keep the entry even when every template was rejected: Laravel counts
        # the case, and the status checksum must agree with it.
        self._cases[case_id] = entry
        self._tombstones.pop(case_id, None)
        return {"applied": True, "accepted": len(entry.templates), "rejected": rejected}

    def remove_case(self, case_id: int, version: int) -> Dict[str, Any]:
        if self._is_stale(case_id, version):
            return {"applied": False, "reason": "stale"}
        self._drop_case_templates(case_id)
        self._cases.pop(case_id, None)
        self._tombstones[case_id] = version
        return {"applied": True, "accepted": 0, "rejected": []}

    # --- matching ---------------------------------------------------------
    def identify(
        self,
        probes: List[Tuple[str, bytearray]],
        exclude_case_ids: List[int],
        threshold: int,
    ) -> Optional[Dict[str, Any]]:
        if self.state != self.READY:
            raise GalleryNotReady()
        handle = self._handle

        # DBIdentify returns only the best match. If that belongs to a case we
        # must ignore (the case being edited), take that case's templates out,
        # search again, and put them back. Done lazily: most checks exclude
        # nothing or never hit the excluded case.
        excluded: Dict[int, bytearray] = {}
        for case_id in exclude_case_ids:
            entry = self._cases.get(case_id)
            if entry:
                excluded.update(entry.templates)
        removed: List[int] = []

        try:
            for key, template in probes:
                fid, score = self._sdk.cache_identify(handle, template)
                if fid and fid in excluded and not removed:
                    for excluded_fid in excluded:
                        self._sdk.cache_del(handle, excluded_fid)
                        removed.append(excluded_fid)
                    fid, score = self._sdk.cache_identify(handle, template)

                if not fid or score < threshold:
                    continue
                case_id = self._template_case.get(fid)
                if case_id is None:
                    log.error("SDK matched template %s that the gallery does not track", fid)
                    self.needs_resync = True
                    raise SdkFailure()
                return {"probe_key": key, "template_id": fid, "case_id": case_id, "score": score}
            return None
        finally:
            for excluded_fid in removed:
                if not self._sdk.cache_add(handle, excluded_fid, excluded[excluded_fid]):
                    log.error("Could not restore template %s after an excluded search", excluded_fid)
                    self.needs_resync = True

    # --- status -----------------------------------------------------------
    def status(self) -> Dict[str, Any]:
        """
        checksum = XOR over cases of the first 8 bytes of
        sha256("<case_id>:<version>:<sorted template ids, comma separated>"),
        as 16 hex digits. Laravel computes the same value from its database to
        detect drift without sending templates.
        """
        acc = 0
        for case_id, entry in self._cases.items():
            ids = ",".join(str(fid) for fid in entry.declared)
            digest = hashlib.sha256(f"{case_id}:{entry.version}:{ids}".encode()).digest()
            acc ^= int.from_bytes(digest[:8], "big")
        return {
            "state": self.state,
            "generation": self.generation,
            "cases": len(self._cases),
            "templates": len(self._template_case),
            "checksum": f"{acc:016x}",
            "needs_resync": self.needs_resync,
        }

    # --- internals --------------------------------------------------------
    def _ensure_handle(self) -> Any:
        if self._handle is None:
            self._handle = self._sdk.cache_new()
        return self._handle

    def _is_stale(self, case_id: int, version: int) -> bool:
        current = self._cases.get(case_id)
        if current is not None and version < current.version:
            return True
        tombstone = self._tombstones.get(case_id)
        return tombstone is not None and version < tombstone

    def _drop_case_templates(self, case_id: int) -> None:
        entry = self._cases.get(case_id)
        if not entry:
            return
        for fid in list(entry.templates):
            self._drop_template(case_id, fid)

    def _drop_template(self, case_id: int, fid: int) -> None:
        if self._handle is not None:
            self._sdk.cache_del(self._handle, fid)
        self._template_case.pop(fid, None)
        entry = self._cases.get(case_id)
        if entry:
            entry.templates.pop(fid, None)


def adhoc_identify(
    sdk: ZkSdk,
    gallery: List[Tuple[int, bytearray]],
    probes: List[Tuple[str, bytearray]],
    threshold: int,
) -> Tuple[Optional[Dict[str, Any]], int]:
    """Small caller-supplied gallery (household members, transition period). SDK thread."""
    handle = sdk.cache_new()
    try:
        rejected = sum(0 if sdk.cache_add(handle, fid, tpl) else 1 for fid, tpl in gallery)
        for key, template in probes:
            fid, score = sdk.cache_identify(handle, template)
            if fid and score >= threshold:
                return {"probe_key": key, "template_id": fid, "score": score}, rejected
        return None, rejected
    finally:
        sdk.cache_free(handle)


# --------------------------------------------------------------------------
# Capture tickets (browser -> capture agent)
# --------------------------------------------------------------------------
def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class TicketVerifier:
    """
    Ticket = base64url(JSON payload) "." base64url(HMAC-SHA256(payload part)).
    Payload: {"v":1,"aud":"zk-bridge","sub":<admin id>,"purpose":"enroll"|"walk_in",
              "origin":"https://ettc-rms.com","nonce":"<32+ chars>","exp":<unix>}

    Laravel mints it for a logged-in user. A random website cannot read that
    response (same-origin policy), so it cannot obtain a ticket.
    """

    PURPOSES = ("enroll", "walk_in")

    def __init__(self, secret: str, max_ttl: int, clock: Callable[[], float] = time.time) -> None:
        self._secret = secret.encode()
        self._max_ttl = max_ttl
        self._clock = clock
        self._seen: Dict[str, float] = {}

    def verify(self, ticket: Any, origin: Optional[str]) -> Dict[str, Any]:
        if not isinstance(ticket, str) or ticket.count(".") != 1 or len(ticket) > 2048:
            raise InvalidTicket()
        payload_part, signature_part = ticket.split(".")
        expected = hmac.new(self._secret, payload_part.encode("ascii", "ignore"), hashlib.sha256).digest()
        try:
            signature = _b64url_decode(signature_part)
            payload = json.loads(_b64url_decode(payload_part))
        except (binascii.Error, ValueError):
            raise InvalidTicket() from None
        if not hmac.compare_digest(expected, signature):
            raise InvalidTicket()
        if not isinstance(payload, dict) or payload.get("v") != 1 or payload.get("aud") != "zk-bridge":
            raise InvalidTicket()
        if payload.get("purpose") not in self.PURPOSES:
            raise InvalidTicket()
        if origin is None or payload.get("origin") != origin:
            raise InvalidTicket()

        now = self._clock()
        try:
            expires = float(payload["exp"])
            nonce = str(payload["nonce"])
        except (KeyError, TypeError, ValueError):
            raise InvalidTicket() from None
        if expires < now or expires - now > self._max_ttl or len(nonce) < 16:
            raise InvalidTicket()

        self._seen = {n: exp for n, exp in self._seen.items() if exp >= now}
        if nonce in self._seen:
            raise InvalidTicket()  # replay
        self._seen[nonce] = expires
        return payload


# --------------------------------------------------------------------------
# Request models
# --------------------------------------------------------------------------
TemplateStr = Field(min_length=16, max_length=8192)


class TemplateRecord(BaseModel):
    id: int = Field(ge=1, le=MAX_FID)
    template: str = TemplateStr


class ProbeRecord(BaseModel):
    key: str = Field(min_length=1, max_length=64)
    template: str = TemplateStr


class MatchRequest(BaseModel):  # legacy single probe, caller-supplied gallery
    new_template: str = TemplateStr
    database_templates: List[TemplateRecord] = Field(default_factory=list, max_length=5000)


class MatchBatchRequest(BaseModel):  # legacy batch, caller-supplied gallery
    probes: List[ProbeRecord] = Field(default_factory=list, max_length=20)
    database_templates: List[TemplateRecord] = Field(default_factory=list, max_length=5000)


class IdentifyRequest(BaseModel):
    probes: List[ProbeRecord] = Field(min_length=1, max_length=20)
    exclude_case_ids: List[int] = Field(default_factory=list, max_length=50)


class CaseTemplates(BaseModel):
    case_id: int = Field(ge=1)
    version: int = Field(ge=0)
    templates: List[TemplateRecord] = Field(default_factory=list, max_length=20)


class UpsertCaseRequest(BaseModel):
    version: int = Field(ge=0)
    templates: List[TemplateRecord] = Field(default_factory=list, max_length=20)


class SyncBeginRequest(BaseModel):
    generation: str = Field(min_length=1, max_length=64)


class SyncChunkRequest(BaseModel):
    generation: str = Field(min_length=1, max_length=64)
    cases: List[CaseTemplates] = Field(max_length=2000)


class SyncCommitRequest(BaseModel):
    generation: str = Field(min_length=1, max_length=64)
    expected_cases: int = Field(ge=0)
    expected_templates: int = Field(ge=0)
    checksum: str = Field(min_length=16, max_length=16)


# --------------------------------------------------------------------------
# Application
# --------------------------------------------------------------------------
def create_app(settings: Optional[Settings] = None, sdk: Optional[ZkSdk] = None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.validate()
    sdk = sdk or ZkSdk()
    gallery = Gallery(sdk)
    tickets = TicketVerifier(settings.ticket_secret, settings.max_ticket_ttl_seconds)
    capture_lock = asyncio.Lock()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        await sdk.run(sdk.init)
        log.info("ZK bridge started (role=%s)", settings.role)
        try:
            yield
        finally:
            await sdk.run(sdk.shutdown)

    app = FastAPI(
        title="ETTC fingerprint bridge",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    app.state.gallery = gallery

    # Browsers only use the WebSocket (CORS does not apply to it; Origin is
    # checked by hand below) and possibly GET /health. No cookies are used.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.allowed_origins),
        allow_credentials=False,
        allow_methods=["GET"],
        allow_headers=[],
    )

    # --- error handling: generic messages, details only in the log --------
    @app.middleware("http")
    async def limit_body_size(request: Request, call_next):
        length = request.headers.get("content-length")
        if length is not None and (not length.isdigit() or int(length) > settings.max_body_bytes):
            return JSONResponse({"code": "payload_too_large", "message": "Request is too large."}, status_code=413)
        return await call_next(request)

    @app.exception_handler(BridgeError)
    async def bridge_error_handler(_request: Request, exc: BridgeError):
        error_id = uuid.uuid4().hex[:12]
        log.warning("%s [%s]", exc.code, error_id, exc_info=exc.__cause__ is not None)
        return JSONResponse(
            {"code": exc.code, "message": exc.public_message, "error_id": error_id},
            status_code=exc.status_code,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_request: Request, exc: RequestValidationError):
        # Do not echo the request back: it would contain fingerprint templates.
        fields = sorted({".".join(str(p) for p in err.get("loc", ())[:2]) for err in exc.errors()})
        return JSONResponse({"code": "invalid_request", "message": "Invalid request.", "fields": fields}, status_code=422)

    @app.exception_handler(Exception)
    async def unhandled_handler(_request: Request, exc: Exception):
        error_id = uuid.uuid4().hex[:12]
        log.error("Unhandled error [%s]", error_id, exc_info=exc)
        return JSONResponse({"code": "internal_error", "message": "Internal bridge error.", "error_id": error_id}, status_code=500)

    # --- server-to-server authentication -----------------------------------
    def require_api_token(request: Request) -> None:
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not settings.api_token or not hmac.compare_digest(
            token.encode(), settings.api_token.encode()
        ):
            raise HTTPException(status_code=401, detail="Unauthorized.")

    authed = [Depends(require_api_token)]

    def decode(template_b64: str) -> bytearray:
        return decode_template(template_b64, settings.max_template_chars)

    # --- health -----------------------------------------------------------
    @app.get("/health")
    async def health() -> Dict[str, Any]:
        return {"status": "online", "role": settings.role}

    @app.get("/health/details", dependencies=authed)
    async def health_details() -> Dict[str, Any]:
        count = await sdk.run(sdk.device_count)
        details: Dict[str, Any] = {"status": "online", "role": settings.role, "device_count": count}
        if settings.matcher_enabled:
            details["gallery"] = await sdk.run(gallery.status)
        return details

    # --- capture (browser) -------------------------------------------------
    if settings.capture_enabled:

        @app.websocket("/ws/fingerprint")
        async def capture_socket(websocket: WebSocket) -> None:
            origin = (websocket.headers.get("origin") or "").rstrip("/") or None
            if origin not in settings.allowed_origins:
                await websocket.close(code=1008)  # rejected before the handshake completes
                return
            await websocket.accept()

            async def fail(code: str, message: str, close_code: int = 1008) -> None:
                if websocket.application_state == WebSocketState.CONNECTED:
                    await websocket.send_json({"status": "error", "code": code, "message": message})
                    await websocket.close(code=close_code)

            try:
                first = await asyncio.wait_for(websocket.receive_json(), timeout=settings.auth_timeout_seconds)
                if not isinstance(first, dict) or first.get("type") != "auth":
                    raise InvalidTicket()
                tickets.verify(first.get("ticket"), origin)
            except (InvalidTicket, asyncio.TimeoutError, ValueError, KeyError):
                await fail("unauthorized", "Scanner access was not authorised. Reload the page and try again.")
                return
            except WebSocketDisconnect:
                return

            if capture_lock.locked():
                await fail("busy", "The scanner is in use. Try again in a moment.", close_code=1013)
                return

            async with capture_lock:
                receiver = asyncio.create_task(websocket.receive())
                try:
                    await websocket.send_json({"status": "ready", "message": "Place finger on scanner..."})
                    template = await _capture(sdk, receiver, settings.capture_timeout_seconds)
                    if template is None:
                        return  # client disconnected or cancelled
                    await websocket.send_json({"status": "success", "template": template})
                    await websocket.close()
                except asyncio.TimeoutError:
                    await fail("timeout", "Fingerprint scan timed out. Try again.", close_code=1000)
                except ScannerUnavailable:
                    await fail("scanner_unavailable", "No fingerprint scanner detected.", close_code=1011)
                except WebSocketDisconnect:
                    return
                except Exception:
                    error_id = uuid.uuid4().hex[:12]
                    log.exception("Capture failed [%s]", error_id)
                    await fail("internal_error", f"Scanner error (ref {error_id}).", close_code=1011)
                finally:
                    receiver.cancel()

    # --- matching (Laravel) ------------------------------------------------
    if settings.matcher_enabled:

        @app.post("/api/identify", dependencies=authed)
        async def identify(body: IdentifyRequest) -> Dict[str, Any]:
            probes = [(p.key, decode(p.template)) for p in body.probes]
            hit = await sdk.run(gallery.identify, probes, body.exclude_case_ids, settings.match_score_threshold)
            return {"is_duplicate": True, **hit} if hit else {"is_duplicate": False}

        @app.get("/gallery/status", dependencies=authed)
        async def gallery_status() -> Dict[str, Any]:
            return await sdk.run(gallery.status)

        @app.put("/gallery/cases/{case_id}", dependencies=authed)
        async def upsert_case(case_id: int, body: UpsertCaseRequest) -> Dict[str, Any]:
            templates = [(t.id, decode(t.template)) for t in body.templates]
            return await sdk.run(gallery.upsert_case, case_id, body.version, templates)

        @app.delete("/gallery/cases/{case_id}", dependencies=authed)
        async def remove_case(case_id: int, version: int) -> Dict[str, Any]:
            return await sdk.run(gallery.remove_case, case_id, version)

        @app.post("/gallery/sync/begin", dependencies=authed)
        async def sync_begin(body: SyncBeginRequest) -> Dict[str, Any]:
            await sdk.run(gallery.begin_sync, body.generation)
            return await sdk.run(gallery.status)

        @app.post("/gallery/sync/chunk", dependencies=authed)
        async def sync_chunk(body: SyncChunkRequest) -> Dict[str, Any]:
            decoded = [(c.case_id, c.version, [(t.id, decode(t.template)) for t in c.templates]) for c in body.cases]

            def apply() -> Dict[str, Any]:
                if gallery.generation != body.generation or gallery.state == Gallery.EMPTY:
                    return {"applied": False, "reason": "generation_mismatch"}
                rejected: List[int] = []
                for case_id, version, templates in decoded:
                    rejected.extend(gallery.upsert_case(case_id, version, templates).get("rejected", []))
                return {"applied": True, "rejected": rejected}

            result = await sdk.run(apply)
            if not result["applied"]:
                raise HTTPException(status_code=409, detail="Sync generation does not match.")
            return result

        @app.post("/gallery/sync/commit", dependencies=authed)
        async def sync_commit(body: SyncCommitRequest) -> Dict[str, Any]:
            committed = await sdk.run(
                gallery.commit_sync, body.generation, body.expected_cases, body.expected_templates, body.checksum
            )
            status = await sdk.run(gallery.status)
            if not committed:
                return JSONResponse({"committed": False, **status}, status_code=409)
            return {"committed": True, **status}

        # Caller-supplied gallery: household members and the migration period.
        # Capped; answers 503 instead of "not a duplicate" when it cannot run.
        async def _adhoc(gallery_records: List[TemplateRecord], probes: List[Tuple[str, bytearray]]):
            if len(gallery_records) > settings.max_adhoc_gallery:
                raise HTTPException(status_code=413, detail="Use /api/identify for large galleries.")
            records = [(r.id, decode(r.template)) for r in gallery_records]
            hit, rejected = await sdk.run(adhoc_identify, sdk, records, probes, settings.match_score_threshold)
            if rejected:
                log.warning("Ad-hoc match rejected %s gallery templates", rejected)
            return hit, rejected

        @app.post("/api/match", dependencies=authed)
        async def match_single(body: MatchRequest) -> Dict[str, Any]:
            if not body.database_templates:
                return {"is_duplicate": False}
            hit, rejected = await _adhoc(body.database_templates, [("0", decode(body.new_template))])
            if not hit:
                return {"is_duplicate": False, "rejected_templates": rejected}
            # matched_case_id keeps the old (misleading) name for compatibility:
            # it is the template / biometric id, not a case id.
            return {"is_duplicate": True, "matched_case_id": hit["template_id"], "score": hit["score"], "rejected_templates": rejected}

        @app.post("/api/match-batch", dependencies=authed)
        async def match_batch(body: MatchBatchRequest) -> Dict[str, Any]:
            if not body.probes or not body.database_templates:
                return {"is_duplicate": False}
            probes = [(p.key, decode(p.template)) for p in body.probes]
            hit, rejected = await _adhoc(body.database_templates, probes)
            if not hit:
                return {"is_duplicate": False, "rejected_templates": rejected}
            return {
                "is_duplicate": True,
                "probe_key": hit["probe_key"],
                "matched_case_id": hit["template_id"],
                "score": hit["score"],
                "rejected_templates": rejected,
            }

    return app


async def _capture(sdk: ZkSdk, receiver: "asyncio.Task[Any]", timeout: float) -> Optional[str]:
    """
    Poll the scanner until a finger is read, the timeout passes or the client
    goes away. Each attempt is a separate job on the SDK thread, so duplicate
    checks queued by Laravel run between attempts instead of waiting for the
    whole scan (the old code held the SDK lock with no timeout at all).
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if receiver.done():
            return None  # disconnect or any client message (= cancel)
        template = await sdk.run(sdk.acquire_once)
        if template:
            return template
        await asyncio.sleep(0.1)
    raise asyncio.TimeoutError()


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    _settings = Settings.from_env()
    # One process only: the SDK and the gallery live in this process' memory.
    uvicorn.run(
        create_app(_settings),
        host=_settings.host,
        port=_settings.port,
        workers=1,
        ssl_certfile=os.getenv("BRIDGE_TLS_CERT") or None,
        ssl_keyfile=os.getenv("BRIDGE_TLS_KEY") or None,
        server_header=False,
    )
