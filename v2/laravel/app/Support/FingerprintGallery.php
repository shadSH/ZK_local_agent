<?php

namespace App\Support;

use App\Enum\RegistrationStatus;
use Illuminate\Database\Eloquent\Builder;
use Modules\System\ReturneeCase\App\Models\ReturneeBiometric;
use Modules\System\ReturneeCase\App\Models\ReturneeCase;

/**
 * The single definition of "which fingerprints are in the duplicate-check
 * gallery": scanned (not skipped) templates of SUBMITTED cases. This is the
 * rule FingerprintDuplicateChecker::loadGallery() applies today.
 */
class FingerprintGallery
{
    /**
     * What the bridge should hold for one case: an empty list means "remove".
     *
     * @return array{version: int, templates: list<array{id: int, template: string}>}
     */
    public static function payloadFor(ReturneeCase $case): array
    {
        $templates = [];

        if ($case->exists && $case->registration_status === RegistrationStatus::SUBMITTED) {
            $templates = self::templatesQuery()
                ->where('returnee_case_id', $case->id)
                ->orderBy('id')
                ->get(['id', 'template'])
                ->map(fn (ReturneeBiometric $b) => ['id' => (int) $b->id, 'template' => $b->template])
                ->all();
        }

        return ['version' => (int) $case->gallery_version, 'templates' => $templates];
    }

    /**
     * Cases that belong in the gallery, for full sync and reconciliation.
     *
     * @return Builder<ReturneeCase>
     */
    public static function casesQuery(): Builder
    {
        return ReturneeCase::query()
            ->where('registration_status', RegistrationStatus::SUBMITTED->value)
            ->whereHas('biometrics', fn (Builder $q) => $q->where('is_skipped', false)
                ->whereNotNull('template')
                ->where('template', '!=', ''));
    }

    /** @return Builder<ReturneeBiometric> */
    public static function templatesQuery(): Builder
    {
        return ReturneeBiometric::query()
            ->where('is_skipped', false)
            ->whereNotNull('template')
            ->where('template', '!=', '');
    }

    /**
     * Same formula as the bridge's Gallery.status():
     * XOR of the first 8 bytes of sha256("<case>:<version>:<sorted ids>").
     *
     * @param  iterable<array{case_id: int, version: int, ids: list<int>}>  $rows
     */
    public static function checksum(iterable $rows): string
    {
        $acc = str_repeat("\0", 8);

        foreach ($rows as $row) {
            $ids = $row['ids'];
            sort($ids);
            $line = $row['case_id'].':'.$row['version'].':'.implode(',', $ids);
            $acc ^= substr(hash('sha256', $line, true), 0, 8);
        }

        return bin2hex($acc);
    }

    /** A value that only grows; stored on the case whenever its fingerprints or status change. */
    public static function nextVersion(): int
    {
        return (int) floor(microtime(true) * 1000);
    }
}
