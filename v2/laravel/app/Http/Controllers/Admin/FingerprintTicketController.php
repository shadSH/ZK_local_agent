<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;

/**
 * Issues a 60-second, single-use ticket that lets the ETTC page in THIS
 * browser open the local capture bridge. A third-party website cannot read
 * this response (same-origin policy), so it cannot use the scanner.
 *
 * Route (routes/system.php, inside the auth + verified group):
 *   Route::post('fingerprint/ticket', FingerprintTicketController::class)
 *       ->middleware('throttle:30,1')
 *       ->name('fingerprint.ticket');
 */
class FingerprintTicketController extends Controller
{
    public function __invoke(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'purpose' => ['required', Rule::in(['enroll', 'walk_in'])],
        ]);

        $admin = $request->user();

        $allowed = $validated['purpose'] === 'walk_in'
            ? $admin->can('view-payment-gateway')
            : $admin->can('create-returnee-case') || $admin->can('update-returnee-case');

        abort_unless($allowed, 403);

        $secret = (string) config('fingerprint.bridge_ticket_secret');
        abort_if($secret === '', 503, 'Fingerprint capture is not configured.');

        $payload = [
            'v' => 1,
            'aud' => 'zk-bridge',
            'sub' => $admin->id,
            'purpose' => $validated['purpose'],
            // Must equal the browser's Origin header exactly (scheme://host[:port]).
            'origin' => rtrim((string) config('fingerprint.capture_origin', config('app.url')), '/'),
            'nonce' => Str::random(40),
            'exp' => now()->addSeconds(60)->timestamp,
        ];

        $part = self::base64Url(json_encode($payload, JSON_THROW_ON_ERROR));
        $signature = self::base64Url(hash_hmac('sha256', $part, $secret, true));

        return response()->json(['ticket' => $part.'.'.$signature])
            ->header('Cache-Control', 'no-store');
    }

    private static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
