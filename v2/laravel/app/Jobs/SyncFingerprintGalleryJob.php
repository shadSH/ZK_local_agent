<?php

namespace App\Jobs;

use App\Services\FingerprintBridgeClient;
use App\Support\FingerprintGallery;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Modules\System\ReturneeCase\App\Models\ReturneeCase;

/**
 * Full (re)load of the matcher's gallery. Runs when the bridge reports it is
 * empty (restart), when reconciliation finds drift, or from
 * `php artisan fingerprint:sync-gallery`.
 *
 * Streams the database in chunks of cases; never builds the whole gallery in
 * PHP memory. Per-case updates that race with this job are safe: the bridge
 * keeps the newest version of each case.
 */
class SyncFingerprintGalleryJob implements ShouldQueue, ShouldBeUnique
{
    use Queueable;

    public int $tries = 3;

    public int $timeout = 1800;

    public int $uniqueFor = 1800;

    private const CASES_PER_CHUNK = 500;

    public function handle(FingerprintBridgeClient $bridge): void
    {
        $generation = (string) Str::uuid();
        $bridge->beginSync($generation);

        $checksumRows = [];
        $caseCount = 0;
        $templateCount = 0;

        FingerprintGallery::casesQuery()
            ->select(['id', 'gallery_version'])
            ->orderBy('id')
            ->chunkById(self::CASES_PER_CHUNK, function ($cases) use ($bridge, $generation, &$checksumRows, &$caseCount, &$templateCount) {
                $templates = FingerprintGallery::templatesQuery()
                    ->whereIn('returnee_case_id', $cases->pluck('id'))
                    ->orderBy('id')
                    ->get(['id', 'returnee_case_id', 'template'])
                    ->groupBy('returnee_case_id');

                $payload = $cases->map(function (ReturneeCase $case) use ($templates, &$checksumRows) {
                    $rows = ($templates[$case->id] ?? collect())
                        ->map(fn ($b) => ['id' => (int) $b->id, 'template' => $b->template])
                        ->values()
                        ->all();

                    $checksumRows[] = [
                        'case_id' => (int) $case->id,
                        'version' => (int) $case->gallery_version,
                        'ids' => array_column($rows, 'id'),
                    ];

                    return ['case_id' => (int) $case->id, 'version' => (int) $case->gallery_version, 'templates' => $rows];
                })->values()->all();

                $result = $bridge->syncChunk($generation, $payload);

                if (! empty($result['rejected'])) {
                    Log::warning('Fingerprint bridge rejected templates during sync', ['ids' => $result['rejected']]);
                }

                $caseCount += count($payload);
                $templateCount += array_sum(array_map(fn ($c) => count($c['templates']), $payload));
            });

        $committed = $bridge->commitSync(
            $generation,
            $caseCount,
            $templateCount,
            FingerprintGallery::checksum($checksumRows),
        );

        if (! $committed) {
            // Something changed mid-sync in a way versions could not settle;
            // retry (fail closed in the meantime: the gallery stays "loading").
            $this->release(30);
        }
    }
}
