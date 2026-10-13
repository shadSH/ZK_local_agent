<?php

namespace App\Console\Commands;

use App\Exceptions\FingerprintServiceUnavailableException;
use App\Jobs\SyncFingerprintGalleryJob;
use App\Services\FingerprintBridgeClient;
use App\Support\FingerprintGallery;
use Illuminate\Console\Command;

/**
 * Compares the matcher's gallery with the database (counts + checksum, no
 * templates transferred) and queues a full resync when they differ.
 *
 * Schedule it, e.g. in routes/console.php:
 *   Schedule::command('fingerprint:reconcile-gallery')->everyTenMinutes()->withoutOverlapping();
 */
class ReconcileFingerprintGallery extends Command
{
    protected $signature = 'fingerprint:reconcile-gallery {--force : Resync even when the gallery looks current}';

    protected $description = 'Check the fingerprint bridge gallery against the database and resync if it drifted';

    public function handle(FingerprintBridgeClient $bridge): int
    {
        try {
            $status = $bridge->status();
        } catch (FingerprintServiceUnavailableException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $rows = [];
        $templates = 0;

        FingerprintGallery::casesQuery()
            ->select(['id', 'gallery_version'])
            ->orderBy('id')
            ->chunkById(2000, function ($cases) use (&$rows, &$templates) {
                $ids = FingerprintGallery::templatesQuery()
                    ->whereIn('returnee_case_id', $cases->pluck('id'))
                    ->get(['id', 'returnee_case_id'])
                    ->groupBy('returnee_case_id');

                foreach ($cases as $case) {
                    $caseIds = ($ids[$case->id] ?? collect())->pluck('id')->map(fn ($id) => (int) $id)->all();
                    $templates += count($caseIds);
                    $rows[] = ['case_id' => (int) $case->id, 'version' => (int) $case->gallery_version, 'ids' => $caseIds];
                }
            });

        $inSync = ($status['state'] ?? null) === 'ready'
            && ! ($status['needs_resync'] ?? false)
            && (int) ($status['cases'] ?? -1) === count($rows)
            && (int) ($status['templates'] ?? -1) === $templates
            && hash_equals(FingerprintGallery::checksum($rows), (string) ($status['checksum'] ?? ''));

        if ($inSync && ! $this->option('force')) {
            $this->info('Fingerprint gallery is in sync ('.count($rows).' cases).');

            return self::SUCCESS;
        }

        SyncFingerprintGalleryJob::dispatch();
        $this->warn('Fingerprint gallery resync queued.');

        return self::SUCCESS;
    }
}
