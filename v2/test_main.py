"""
Tests for the bridge, run against a fake ZK SDK (pyzkfp only works on Windows
with the scanner driver). The fake mirrors the parts of the real API the bridge
uses, including pyzkfp's habit of creating a cache inside OpenDevice().

    pip install fastapi httpx pytest
    pytest -q test_main.py
"""

import base64
import hashlib
import hmac
import json
import time
import uuid

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import main
from main import Settings, TicketVerifier, ZkSdk, create_app

API_TOKEN = "t" * 40
TICKET_SECRET = "s" * 40
ORIGIN = "https://ettc-rms.com"


# --------------------------------------------------------------------------
# Fake SDK: two templates "match" when their bytes are identical.
# --------------------------------------------------------------------------
class FakeRaw:
    def __init__(self):
        self.caches = {}
        self.next_handle = 1
        self.fail_identify = False

    def DBInit(self):
        handle = self.next_handle
        self.next_handle += 1
        self.caches[handle] = {}
        return handle

    def DBFree(self, handle):
        self.caches.pop(handle, None)
        return 0

    def DBAdd(self, handle, fid, template):
        if bytes(template).startswith(b"BAD"):
            return -13
        self.caches[handle][fid] = bytes(template)
        return 0

    def DBDel(self, handle, fid):
        self.caches[handle].pop(fid, None)
        return 0

    def DBIdentify(self, handle, template, fid, score):
        if self.fail_identify:
            return -7, 0, 0
        for stored_fid, stored in self.caches[handle].items():
            if stored == bytes(template):
                return 0, stored_fid, 80
        return main.SDK_NO_MATCH, 0, 0


class FakeZk:
    def __init__(self):
        self.zkfp2 = FakeRaw()
        self.dbHandle = None
        self.devices = 1
        self.pending_capture = None
        self.open_calls = 0

    def Init(self):
        pass

    def Terminate(self):
        pass

    def GetDeviceCount(self):
        return self.devices

    def OpenDevice(self, index=0):
        self.open_calls += 1
        self.dbHandle = self.zkfp2.DBInit()  # like pyzkfp
        return 1

    def CloseDevice(self):
        pass

    def AcquireFingerprint(self):
        if self.pending_capture is None:
            return None
        template, self.pending_capture = self.pending_capture, None
        return bytearray(template), b""


def tpl(label: str) -> str:
    return base64.b64encode(label.encode().ljust(64, b"\0")).decode()


def make_client(role="all", **overrides):
    fake = FakeZk()
    settings = Settings(
        role=role,
        api_token=API_TOKEN,
        ticket_secret=TICKET_SECRET,
        capture_timeout_seconds=overrides.pop("capture_timeout_seconds", 0.5),
        auth_timeout_seconds=0.5,
        max_adhoc_gallery=overrides.pop("max_adhoc_gallery", 500),
    )
    app = create_app(settings, ZkSdk(factory=lambda: fake))
    return TestClient(app), fake


AUTH = {"Authorization": f"Bearer {API_TOKEN}"}


def ticket(purpose="enroll", origin=ORIGIN, exp_in=60, secret=TICKET_SECRET, nonce=None):
    payload = {
        "v": 1,
        "aud": "zk-bridge",
        "sub": 7,
        "purpose": purpose,
        "origin": origin,
        "nonce": nonce or uuid.uuid4().hex,
        "exp": int(time.time()) + exp_in,
    }
    part = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = hmac.new(secret.encode(), part.encode(), hashlib.sha256).digest()
    return part + "." + base64.urlsafe_b64encode(sig).decode().rstrip("=")


def checksum(cases):
    """cases: [(case_id, version, [template ids])] -- same formula as Laravel."""
    acc = 0
    for case_id, version, ids in cases:
        line = f"{case_id}:{version}:{','.join(str(i) for i in sorted(ids))}"
        acc ^= int.from_bytes(hashlib.sha256(line.encode()).digest()[:8], "big")
    return f"{acc:016x}"


def load_gallery(client, cases):
    """cases: {case_id: (version, [(template_id, label), ...])}"""
    assert client.post("/gallery/sync/begin", json={"generation": "g1"}, headers=AUTH).status_code == 200
    body = {
        "generation": "g1",
        "cases": [
            {"case_id": cid, "version": ver, "templates": [{"id": fid, "template": tpl(lbl)} for fid, lbl in rows]}
            for cid, (ver, rows) in cases.items()
        ],
    }
    assert client.post("/gallery/sync/chunk", json=body, headers=AUTH).status_code == 200
    commit = {
        "generation": "g1",
        "expected_cases": len(cases),
        "expected_templates": sum(len(rows) for _, rows in cases.values()),
        "checksum": checksum([(cid, ver, [fid for fid, _ in rows]) for cid, (ver, rows) in cases.items()]),
    }
    response = client.post("/gallery/sync/commit", json=commit, headers=AUTH)
    assert response.status_code == 200, response.json()


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
def test_refuses_to_start_without_secrets():
    with pytest.raises(RuntimeError):
        Settings(role="matcher", api_token="short").validate()
    with pytest.raises(RuntimeError):
        Settings(role="capture", ticket_secret="").validate()
    with pytest.raises(RuntimeError):
        Settings(role="all", api_token=API_TOKEN, ticket_secret=TICKET_SECRET, allowed_origins=("*",)).validate()


def test_capture_role_exposes_no_matching_endpoints():
    client, _ = make_client(role="capture")
    with client:
        assert client.post("/api/identify", json={}, headers=AUTH).status_code == 404


# --------------------------------------------------------------------------
# Server authentication and error handling
# --------------------------------------------------------------------------
def test_matcher_endpoints_require_bearer_token():
    client, _ = make_client()
    with client:
        probe = {"probes": [{"key": "0", "template": tpl("a")}]}
        assert client.post("/api/identify", json=probe).status_code == 401
        assert client.post("/api/identify", json=probe, headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert client.get("/gallery/status").status_code == 401


def test_validation_errors_do_not_echo_templates():
    client, _ = make_client()
    with client:
        response = client.post("/api/identify", json={"probes": [{"key": "0", "template": "!!"}]}, headers=AUTH)
        assert response.status_code == 422
        assert "!!" not in response.text


def test_sdk_failure_is_503_not_no_duplicate():
    client, fake = make_client()
    with client:
        load_gallery(client, {10: (1, [(100, "alice")])})
        fake.zkfp2.fail_identify = True
        response = client.post("/api/identify", json={"probes": [{"key": "0", "template": tpl("x")}]}, headers=AUTH)
        assert response.status_code == 503
        body = response.json()
        assert body["code"] == "matching_unavailable" and "error_id" in body
        # Legacy endpoint used to swallow errors and answer "not a duplicate".
        legacy = {"new_template": tpl("x"), "database_templates": [{"id": 1, "template": tpl("y")}]}
        assert client.post("/api/match", json=legacy, headers=AUTH).status_code == 503


def test_invalid_base64_template_is_422():
    client, _ = make_client()
    with client:
        load_gallery(client, {10: (1, [(100, "alice")])})
        bad = "@" * 20
        response = client.post("/api/identify", json={"probes": [{"key": "0", "template": bad}]}, headers=AUTH)
        assert response.status_code == 422 and response.json()["code"] == "invalid_template"


# --------------------------------------------------------------------------
# Persistent gallery
# --------------------------------------------------------------------------
def test_identify_requires_a_loaded_gallery():
    client, _ = make_client()
    with client:
        response = client.post("/api/identify", json={"probes": [{"key": "0", "template": tpl("a")}]}, headers=AUTH)
        assert response.status_code == 503 and response.json()["code"] == "gallery_not_ready"


def test_identify_finds_duplicate_and_reports_case_and_template():
    client, _ = make_client()
    with client:
        load_gallery(client, {10: (1, [(100, "alice"), (101, "alice2")]), 11: (1, [(110, "bob")])})
        response = client.post(
            "/api/identify",
            json={"probes": [{"key": "right_thumb", "template": tpl("zzz")}, {"key": "left_index", "template": tpl("bob")}]},
            headers=AUTH,
        )
        assert response.json() == {"is_duplicate": True, "probe_key": "left_index", "template_id": 110, "case_id": 11, "score": 80}


def test_excluded_case_is_ignored_and_restored():
    client, fake = make_client()
    with client:
        load_gallery(client, {10: (1, [(100, "alice")]), 11: (1, [(110, "bob")])})
        probe = {"probes": [{"key": "0", "template": tpl("alice")}]}
        excluded = client.post("/api/identify", json={**probe, "exclude_case_ids": [10]}, headers=AUTH).json()
        assert excluded == {"is_duplicate": False}
        # The excluded case's templates are back in the cache afterwards.
        assert client.post("/api/identify", json=probe, headers=AUTH).json()["case_id"] == 10


def test_case_upsert_replace_remove_and_stale_versions():
    client, _ = make_client()
    with client:
        load_gallery(client, {10: (5, [(100, "alice")])})
        probe = lambda label: client.post(
            "/api/identify", json={"probes": [{"key": "0", "template": tpl(label)}]}, headers=AUTH
        ).json()

        # New submitted case appears immediately.
        put = client.put("/gallery/cases/12", json={"version": 1, "templates": [{"id": 120, "template": tpl("carol")}]}, headers=AUTH)
        assert put.json()["applied"] is True
        assert probe("carol")["case_id"] == 12

        # Re-scan replaces the old template.
        client.put("/gallery/cases/10", json={"version": 6, "templates": [{"id": 100, "template": tpl("alice-new")}]}, headers=AUTH)
        assert probe("alice") == {"is_duplicate": False}
        assert probe("alice-new")["case_id"] == 10

        # A late, older update is ignored.
        stale = client.put("/gallery/cases/10", json={"version": 5, "templates": [{"id": 100, "template": tpl("alice")}]}, headers=AUTH)
        assert stale.json() == {"applied": False, "reason": "stale"}

        # Removal, and a stale re-add after removal, are handled.
        assert client.delete("/gallery/cases/12?version=2", headers=AUTH).json()["applied"] is True
        assert probe("carol") == {"is_duplicate": False}
        late = client.put("/gallery/cases/12", json={"version": 1, "templates": [{"id": 120, "template": tpl("carol")}]}, headers=AUTH)
        assert late.json()["applied"] is False


def test_rejected_templates_are_reported_not_silent():
    client, _ = make_client()
    with client:
        load_gallery(client, {10: (1, [(100, "alice")])})
        put = client.put(
            "/gallery/cases/13",
            json={"version": 1, "templates": [{"id": 130, "template": tpl("BAD-template")}, {"id": 131, "template": tpl("dave")}]},
            headers=AUTH,
        )
        assert put.json()["rejected"] == [130]


def test_commit_fails_on_checksum_mismatch():
    client, _ = make_client()
    with client:
        client.post("/gallery/sync/begin", json={"generation": "g2"}, headers=AUTH)
        client.post(
            "/gallery/sync/chunk",
            json={"generation": "g2", "cases": [{"case_id": 1, "version": 1, "templates": [{"id": 1, "template": tpl("a")}]}]},
            headers=AUTH,
        )
        response = client.post(
            "/gallery/sync/commit",
            json={"generation": "g2", "expected_cases": 1, "expected_templates": 1, "checksum": "0" * 16},
            headers=AUTH,
        )
        assert response.status_code == 409
        assert client.get("/gallery/status", headers=AUTH).json()["state"] == "loading"


def test_chunk_for_old_generation_is_rejected():
    client, _ = make_client()
    with client:
        client.post("/gallery/sync/begin", json={"generation": "new"}, headers=AUTH)
        response = client.post("/gallery/sync/chunk", json={"generation": "old", "cases": []}, headers=AUTH)
        assert response.status_code == 409


def test_adhoc_gallery_is_capped():
    client, _ = make_client(max_adhoc_gallery=2)
    with client:
        body = {"new_template": tpl("a"), "database_templates": [{"id": i, "template": tpl(str(i))} for i in range(1, 4)]}
        assert client.post("/api/match", json=body, headers=AUTH).status_code == 413


def test_legacy_batch_contract_still_works():
    client, _ = make_client()
    with client:
        body = {
            "probes": [{"key": "right_thumb", "template": tpl("x")}, {"key": "left_thumb", "template": tpl("m2")}],
            "database_templates": [{"id": 1, "template": tpl("m1")}, {"id": 2, "template": tpl("m2")}],
        }
        result = client.post("/api/match-batch", json=body, headers=AUTH).json()
        assert result["is_duplicate"] and result["probe_key"] == "left_thumb" and result["matched_case_id"] == 2


# --------------------------------------------------------------------------
# WebSocket capture
# --------------------------------------------------------------------------
def test_websocket_rejects_unknown_origin():
    client, _ = make_client()
    with client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws/fingerprint", headers={"origin": "https://evil.example"}):
                pass


def test_websocket_requires_valid_ticket():
    client, _ = make_client()
    with client:
        with client.websocket_connect("/ws/fingerprint", headers={"origin": ORIGIN}) as ws:
            ws.send_json({"type": "auth", "ticket": ticket(secret="x" * 40)})
            message = ws.receive_json()
            assert message["status"] == "error" and message["code"] == "unauthorized"
            assert "Traceback" not in json.dumps(message)


def test_websocket_rejects_ticket_minted_for_another_origin():
    client, _ = make_client()
    with client:
        with client.websocket_connect("/ws/fingerprint", headers={"origin": ORIGIN}) as ws:
            ws.send_json({"type": "auth", "ticket": ticket(origin="http://localhost")})
            assert ws.receive_json()["code"] == "unauthorized"


def test_websocket_capture_success_and_ticket_is_single_use():
    client, fake = make_client()
    with client:
        good = ticket()
        fake.pending_capture = b"finger-template".ljust(64, b"\0")
        with client.websocket_connect("/ws/fingerprint", headers={"origin": ORIGIN}) as ws:
            ws.send_json({"type": "auth", "ticket": good})
            assert ws.receive_json()["status"] == "ready"
            success = ws.receive_json()
            assert success["status"] == "success"
            assert base64.b64decode(success["template"]).startswith(b"finger-template")
        with client.websocket_connect("/ws/fingerprint", headers={"origin": ORIGIN}) as ws:
            ws.send_json({"type": "auth", "ticket": good})
            assert ws.receive_json()["code"] == "unauthorized"  # replay


def test_websocket_capture_times_out_with_generic_message():
    client, _ = make_client(capture_timeout_seconds=0.3)
    with client:
        with client.websocket_connect("/ws/fingerprint", headers={"origin": ORIGIN}) as ws:
            ws.send_json({"type": "auth", "ticket": ticket()})
            assert ws.receive_json()["status"] == "ready"
            message = ws.receive_json()
            assert message["code"] == "timeout"


def test_open_device_cache_is_not_leaked():
    client, fake = make_client()
    with client:
        fake.pending_capture = b"x".ljust(64, b"\0")
        with client.websocket_connect("/ws/fingerprint", headers={"origin": ORIGIN}) as ws:
            ws.send_json({"type": "auth", "ticket": ticket()})
            ws.receive_json()
            ws.receive_json()
        # The cache pyzkfp creates inside OpenDevice() was freed; none left over.
        assert fake.dbHandle is None
        assert fake.zkfp2.caches == {}


def test_ticket_verifier_rejects_expired_and_long_lived():
    verifier = TicketVerifier(TICKET_SECRET, max_ttl=120)
    with pytest.raises(main.InvalidTicket):
        verifier.verify(ticket(exp_in=-5), ORIGIN)
    with pytest.raises(main.InvalidTicket):
        verifier.verify(ticket(exp_in=3600), ORIGIN)
    assert verifier.verify(ticket(), ORIGIN)["sub"] == 7
