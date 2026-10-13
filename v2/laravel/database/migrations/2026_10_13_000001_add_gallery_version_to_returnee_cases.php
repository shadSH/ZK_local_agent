<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Version of a case's fingerprint-gallery state, in milliseconds. Bumped
 * whenever the case's templates or registration status change, so the bridge
 * can drop late or replayed updates and the reconcile job can detect drift.
 * (updated_at is not enough: deleting a biometric row does not touch the case.)
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('returnee_cases', function (Blueprint $table) {
            $table->unsignedBigInteger('gallery_version')->default(0);
        });

        // Seed from updated_at so the first full sync has meaningful versions.
        // (Tests run on SQLite, production on PostgreSQL.)
        $expression = DB::connection()->getDriverName() === 'pgsql'
            ? 'CAST(EXTRACT(EPOCH FROM updated_at) * 1000 AS BIGINT)'
            : "CAST(strftime('%s', updated_at) AS INTEGER) * 1000";

        DB::table('returnee_cases')->whereNotNull('updated_at')->update([
            'gallery_version' => DB::raw($expression),
        ]);
    }

    public function down(): void
    {
        Schema::table('returnee_cases', function (Blueprint $table) {
            $table->dropColumn('gallery_version');
        });
    }
};
