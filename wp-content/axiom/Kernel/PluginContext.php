<?php
/**
 * Plugin Context
 *
 * Encapsulates all runtime metadata about a single plugin under
 * Axiom supervision — its slug, file path, parsed manifest,
 * isolation mode, and accumulated resource usage.
 *
 * @package Axiom\Kernel
 */

declare(strict_types=1);

namespace Axiom\Kernel;

use Axiom\Security\PluginManifest;

final class PluginContext
{
    private string $slug;
    private string $file;
    private ?PluginManifest $manifest;
    private bool $is_modern;
    private int $cpu_consumed_ms = 0;
    private int $peak_memory_bytes = 0;
    private int $hook_invocations = 0;
    private int $sql_queries = 0;
    private bool $active = true;
    private ?string $isolate_id = null;

    public function __construct(
        string $slug,
        string $file,
        ?PluginManifest $manifest = null,
        bool $is_modern = false
    ) {
        $this->slug     = $slug;
        $this->file     = $file;
        $this->manifest = $manifest;
        $this->is_modern = $is_modern;
    }

    public function slug(): string                     { return $this->slug; }
    public function file(): string                     { return $this->file; }
    public function manifest(): ?PluginManifest        { return $this->manifest; }
    public function is_modern(): bool                  { return $this->is_modern; }
    public function is_legacy(): bool                  { return ! $this->is_modern; }
    public function is_active(): bool                  { return $this->active; }
    public function isolate_id(): ?string              { return $this->isolate_id; }

    public function set_isolate_id( string $id ): void { $this->isolate_id = $id; }
    public function deactivate(): void                 { $this->active = false; }

    public function record_cpu( int $milliseconds ): void
    {
        $this->cpu_consumed_ms += $milliseconds;
    }

    public function record_memory( int $bytes ): void
    {
        if ( $bytes > $this->peak_memory_bytes ) {
            $this->peak_memory_bytes = $bytes;
        }
    }

    public function record_hook(): void
    {
        $this->hook_invocations++;
    }

    public function record_sql(): void
    {
        $this->sql_queries++;
    }

    public function cpu_consumed_ms(): int     { return $this->cpu_consumed_ms; }
    public function peak_memory_bytes(): int   { return $this->peak_memory_bytes; }
    public function hook_invocations(): int    { return $this->hook_invocations; }
    public function sql_queries(): int         { return $this->sql_queries; }

    /**
     * Check if this plugin has exceeded its resource budget for the current hook.
     */
    public function has_exceeded_budget( int $cpu_limit_ms, int $memory_limit_mb ): bool
    {
        return $this->cpu_consumed_ms > $cpu_limit_ms
            || $this->peak_memory_bytes > $memory_limit_mb * 1024 * 1024;
    }

    public function reset_budget(): void
    {
        $this->cpu_consumed_ms  = 0;
        $this->peak_memory_bytes = 0;
    }

    /**
     * Has a manifest been explicitly granted?
     */
    public function has_manifest(): bool
    {
        return $this->manifest !== null;
    }
}
