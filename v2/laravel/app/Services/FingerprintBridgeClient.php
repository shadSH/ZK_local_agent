<?php

namespace App\Services;

use App\Exceptions\FingerprintServiceUnavailableException;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * Server-to-server client for the matcher bridge (BRIDGE_ROLE=matcher).
 * Every call carries the bearer token; failures throw so callers fail closed.
 */
class FingerprintBridgeClient
{
    /**
     * 1:N search against the persistent gallery.
     *
     * @param  array<string, string>  $probes  probe key => base64 template
     * @param  list<int>  $excludeCaseIds
     * @return array{template_id: int, case_id: int, score: int, probe_key: string}|null
     *
     * @throws FingerprintServiceUnavailableException
     */
    public function identify(array $probes, array $excludeCaseIds = []): ?array
    {
        $response = $this->send(fn (PendingRequest $http) => $http->post($this->url('/api/identify'), [
            'probes' => collect($probes)
                ->map(fn (string $template, string|int $key) => ['key' => (string) $key, 'template' => $template])
                ->values()
                ->all(),
            'exclude_case_ids' => array_values(array_map('intval', $excludeCaseIds)),
        ]));

        if ($response->status() === 503 && $response->json('code') === 'gallery_not_ready') {
            // Fail closed, but start the resync so the next attempt works.
            \App\Jobs\SyncFingerprintGalleryJob::dispatch();

            throw new FingerprintServiceUnavailableException('Fingerprint gallery is loading.');
        }

        $this->ensureOk($response);

        if ($response->json('is_duplicate') !== true) {
            return null;
        }

        $score = (int) $response->json('score');

        if ($score < (int) config('fingerprint.min_score')) {
            return null;
        }

        return [
            'template_id' => (int) $response->json('template_id'),
            'case_id' => (int) $response->json('case_id'),
            'score' => $score,
            'probe_key' => (string) $response->json('probe_key'),
        ];
    }

    /**
     * @param  list<array{id: int, template: string}>  $templates  empty = remove the case
     *
     * @throws FingerprintServiceUnavailableException
     */
    public function putCase(int $caseId, int $version, array $templates): void
    {
        $this->ensureOk($this->send(fn (PendingRequest $http) => $http->put(
            $this->url("/gallery/cases/{$caseId}"),
            ['version' => $version, 'templates' => $templates],
        )));
    }

    /** @throws FingerprintServiceUnavailableException */
    public function removeCase(int $caseId, int $version): void
    {
        $this->ensureOk($this->send(fn (PendingRequest $http) => $http->delete(
            $this->url("/gallery/cases/{$caseId}").'?version='.$version,
        )));
    }

    /** @throws FingerprintServiceUnavailableException */
    public function status(): array
    {
        $response = $this->send(fn (PendingRequest $http) => $http->get($this->url('/gallery/status')));
        $this->ensureOk($response);

        return (array) $response->json();
    }

    /** @throws FingerprintServiceUnavailableException */
    public function beginSync(string $generation): void
    {
        $this->ensureOk($this->send(fn (PendingRequest $http) => $http->post(
            $this->url('/gallery/sync/begin'),
            ['generation' => $generation],
        )));
    }

    /**
     * @param  list<array{case_id: int, version: int, templates: list<array{id: int, template: string}>}>  $cases
     *
     * @throws FingerprintServiceUnavailableException
     */
    public function syncChunk(string $generation, array $cases): array
    {
        $response = $this->send(fn (PendingRequest $http) => $http->post(
            $this->url('/gallery/sync/chunk'),
            ['generation' => $generation, 'cases' => $cases],
        ));
        $this->ensureOk($response);

        return (array) $response->json();
    }

    /** @throws FingerprintServiceUnavailableException */
    public function commitSync(string $generation, int $cases, int $templates, string $checksum): bool
    {
        $response = $this->send(fn (PendingRequest $http) => $http->post($this->url('/gallery/sync/commit'), [
            'generation' => $generation,
            'expected_cases' => $cases,
            'expected_templates' => $templates,
            'checksum' => $checksum,
        ]));

        if ($response->status() === 409) {
            return false;
        }

        $this->ensureOk($response);

        return true;
    }

    /**
     * @param  callable(PendingRequest): Response  $call
     *
     * @throws FingerprintServiceUnavailableException
     */
    private function send(callable $call): Response
    {
        $token = (string) config('fingerprint.bridge_api_token');

        if ($token === '') {
            throw new FingerprintServiceUnavailableException('FINGERPRINT_BRIDGE_API_TOKEN is not configured.');
        }

        try {
            return $call(
                Http::withToken($token)
                    ->acceptJson()
                    ->timeout((int) config('fingerprint.timeout', 15))
                    ->connectTimeout(3),
            );
        } catch (ConnectionException $e) {
            throw new FingerprintServiceUnavailableException('Unable to reach the fingerprint bridge.', previous: $e);
        } catch (Throwable $e) {
            throw new FingerprintServiceUnavailableException('Fingerprint bridge request failed.', previous: $e);
        }
    }

    /** @throws FingerprintServiceUnavailableException */
    private function ensureOk(Response $response): void
    {
        if ($response->successful()) {
            return;
        }

        throw new FingerprintServiceUnavailableException(sprintf(
            'Fingerprint bridge returned HTTP %d (%s, ref %s).',
            $response->status(),
            (string) $response->json('code', 'error'),
            (string) $response->json('error_id', '-'),
        ));
    }

    private function url(string $path): string
    {
        return rtrim((string) config('fingerprint.bridge_url'), '/').$path;
    }
}
