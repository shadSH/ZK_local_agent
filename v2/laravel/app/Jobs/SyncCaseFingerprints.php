<?php

namespace App\Jobs;

use App\Services\FingerprintBridgeClient;
use App\Support\FingerprintGallery;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Modules\System\ReturneeCase\App\Models\ReturneeCase;

/**
 * Pushes one case's current gallery state to the matcher. Dispatched after
 * commit whenever a case's fingerprints or registration status change, or the
 * case is deleted. Reads the database at run time, so retries and duplicates
 * are harmless (the bridge also ignores older versions).
 */
class SyncCaseFingerprints implements ShouldQueue, ShouldBeUnique
{
    use Queueable;

    public int $tries = 5;

    public int $uniqueFor = 60;

    public function __construct(public int $caseId, public ?int $deletedVersion = null)
    {
        $this->afterCommit();
    }

    public function uniqueId(): string
    {
        return (string) $this->caseId;
    }

    /** @return list<int> */
    public function backoff(): array
    {
        return [5, 30, 120, 600];
    }

    public function handle(FingerprintBridgeClient $bridge): void
    {
        $case = ReturneeCase::query()->find($this->caseId);

        if ($case === null) {
            $bridge->removeCase($this->caseId, $this->deletedVersion ?? FingerprintGallery::nextVersion());

            return;
        }

        $payload = FingerprintGallery::payloadFor($case);
        $bridge->putCase($case->id, $payload['version'], $payload['templates']);
    }
}
