# Fingerprint bridge v2 — ETTC integration guide

Files in this folder:

| Path | What it is | Status |
|---|---|---|
| `main.py` | Refactored bridge (capture / matcher / all roles) | 22 tests pass against a fake SDK |
| `test_main.py` | Tests (fake ZK SDK; run on any OS) | `pytest -q test_main.py` |
| `laravel/…` | New Laravel pieces (client, gallery rule, jobs, command, ticket endpoint, migration) | Not run: no PHP in my environment — review and test before merging |

---

## 1. Environment

### Bridge (`.env` / service environment)

| Variable | capture PCs | matcher | Notes |
|---|---|---|---|
| `BRIDGE_ROLE` | `capture` | `matcher` | `all` only for a single dev machine |
| `BRIDGE_TICKET_SECRET` | required (≥32 chars) | – | same value as Laravel `FINGERPRINT_BRIDGE_TICKET_SECRET` |
| `BRIDGE_API_TOKEN` | – | required (≥32 chars) | same value as Laravel `FINGERPRINT_BRIDGE_API_TOKEN` |
| `BRIDGE_ALLOWED_ORIGINS` | e.g. `https://ettc-rms.com,http://ettc.test` | – | exact origins, no `*` |
| `BRIDGE_HOST` / `BRIDGE_PORT` | `127.0.0.1` / `8000` | private address / `8000` | |
| `BRIDGE_TLS_CERT` / `BRIDGE_TLS_KEY` | – | recommended | when the matcher is reached over a network |
| `CAPTURE_TIMEOUT_SECONDS` | `15` | – | keep below the frontend timeout (30 s) |

The bridge refuses to start if a required secret is missing or an origin is `*`.

### Laravel (`config/fingerprint.php` additions)

```php
'bridge_url' => env('FINGERPRINT_BRIDGE_URL', 'http://127.0.0.1:8000'),
'bridge_api_token' => env('FINGERPRINT_BRIDGE_API_TOKEN'),
'bridge_ticket_secret' => env('FINGERPRINT_BRIDGE_TICKET_SECRET'),
'capture_origin' => env('FINGERPRINT_CAPTURE_ORIGIN', env('APP_URL')),
```

`FINGERPRINT_CAPTURE_ORIGIN` must equal the browser's origin exactly (`https://ettc-rms.com`, no path, no trailing slash).
Generate secrets with `php -r "echo bin2hex(random_bytes(32));"`.

---

## 2. Laravel changes

### 2.1 Duplicate check uses the persistent gallery

`FingerprintDuplicateChecker::findForTemplates()` stops loading every template:

```php
public function findForTemplates(array $probes, ?int $ignoreCaseId = null): ?array
{
    $probes = array_filter($probes, fn ($template) => filled($template));

    if ($probes === [] || ! $this->matcher->isEnabled()) {
        return null;
    }

    $hit = $this->bridge->identify($probes, $ignoreCaseId ? [$ignoreCaseId] : []);

    return $hit ? $this->resolveHit($hit['template_id'], $hit['probe_key']) : null;
}
```

(Inject `FingerprintBridgeClient $bridge` in the constructor; `loadGallery()` is removed.)
`matchAgainst()` — checking household members against each other — keeps using `FingerprintMatchService::identifyMany()` and the small ad-hoc gallery; add `->withToken(config('fingerprint.bridge_api_token'))` to both HTTP calls in `FingerprintMatchService` and point `match_url` / `match_batch_url` at the matcher.

`NoDuplicateBiometrics` is unchanged in behaviour but now costs one small request per member instead of a full-table read plus a full-gallery upload.

### 2.2 Keep the gallery current

1. Run the migration `2026_10_13_000001_add_gallery_version_to_returnee_cases`.
2. Wherever a case's fingerprints or registration status change, bump the version and queue a push (after commit):

```php
$case->forceFill(['gallery_version' => FingerprintGallery::nextVersion()])->saveQuietly();
SyncCaseFingerprints::dispatch($case->id);
```

Call sites:
- `CaseBiometricSync::sync()` — only when a row was created, updated or deleted (the mass `whereNotIn(...)->delete()` fires no model events, so model observers are not enough).
- `StoreHouseholdAction` — for every member whose `registration_status` becomes `submitted`.
- `DeleteReturneeCaseAction` — `SyncCaseFingerprints::dispatch($id, FingerprintGallery::nextVersion())` after the delete commits.

3. Schedule reconciliation (`routes/console.php`):

```php
Schedule::command('fingerprint:reconcile-gallery')->everyTenMinutes()->withoutOverlapping();
```

4. A queue worker must be running (the deploy script starts none today).

### 2.3 Capture tickets

Route (inside the `auth` + `verified` group of `routes/system.php`):

```php
Route::post('fingerprint/ticket', FingerprintTicketController::class)
    ->middleware('throttle:30,1')
    ->name('fingerprint.ticket');
```

Frontend — `FingerprintScanner.tsx` `startScan()`: fetch a ticket first, then send it as the first WebSocket message:

```ts
const response = await fetch(route("system.fingerprint.ticket"), {
    method: "POST",
    headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-CSRF-TOKEN": csrfToken(),
        "X-Requested-With": "XMLHttpRequest",
    },
    credentials: "same-origin",
    body: JSON.stringify({ purpose: "enroll" }), // "walk_in" on the gateway page
});
if (!response.ok) { settle("error", t("returnee_cases.fingerprint.error_unreachable")); return; }
const { ticket } = await response.json();

socket = new WebSocket(resolveWsUrl(wsUrl));
socket.onopen = () => socket.send(JSON.stringify({ type: "auth", ticket }));
```

Error messages from the bridge now have a `code` (`unauthorized`, `busy`, `timeout`, `scanner_unavailable`, `internal_error`) and a generic `message`; map `code` to translated text instead of showing `message` verbatim.

### 2.4 Gateway walk-in verification

Today: browser → Laravel `verify-walk-in` → bridge `/verify`, which captures on the machine **Laravel** runs on. In production that is the web server, which has no scanner.

New flow (no `/verify` endpoint needed):
1. Gateway page captures through the local capture agent (ticket purpose `walk_in`).
2. Page POSTs the template to `system.gateway.verify-walk-in`.
3. `verifyWalkIn` calls `WalkInLookupAction::handle($admin, $template)`, which already identifies against the gallery, enforces branch scope and checks for a pending payment.

Remove `ProxyWalkInVerifyAction`, the `walk-in-lookup` API route, `GATEWAY_BRIDGE_TOKEN` / `LARAVEL_WALKIN_LOOKUP_URL`, and `services/fingerprint-bridge/` (replace with this bridge so there is one copy).

---

## 3. Rollout order

1. Deploy the matcher (`BRIDGE_ROLE=matcher`) on its host; set Laravel `FINGERPRINT_BRIDGE_URL` and token. The legacy `/api/match` and `/api/match-batch` keep working (now authenticated and fail-closed) so nothing breaks yet.
2. Run the migration, deploy the sync jobs/command, run `php artisan fingerprint:reconcile-gallery --force`, wait for `state: ready` (`GET /gallery/status`).
3. Switch `findForTemplates()` to `identify()` (2.1).
4. Deploy the ticket endpoint and the frontend change, then the capture agents (`BRIDGE_ROLE=capture`) on each workstation.
5. Switch the gateway walk-in flow (2.4) and delete the old bridge copy.

---

## 4. Things to verify on real hardware

- **SDK cache capacity and speed**: measure `DBAdd` time for a full load and `DBIdentify` time at your gallery size; check the ZKFinger SDK documentation for the version you ship regarding the maximum number of templates in one cache.
- **Template storage size**: `AcquireFingerprint` returns a fixed 2048-byte buffer and the base64 of all of it is stored (~2.7 KB per finger). Whether the real template length can be stored instead depends on the SDK returning it (pyzkfp currently discards it).
- **Browser access to `ws://127.0.0.1`** from `https://ettc-rms.com`: Chrome's local-network-access permission prompt must be accepted once per workstation.
- **Matcher memory**: it keeps every template in the SDK cache and a copy in Python (needed to restore excluded cases). Roughly 2 × 2 KB × number of scanned fingers.
