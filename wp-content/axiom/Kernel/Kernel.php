<?php
/**
 * Axiom Kernel — Central Orchestrator
 *
 * Singleton responsible for initializing all Axiom subsystems.
 * Wires up the database proxy, hook marshaller, isolate manager,
 * resource governor, profiler, and security validator into the
 * WordPress bootstrap lifecycle.
 *
 * @package Axiom\Kernel
 */

declare(strict_types=1);

namespace Axiom\Kernel;

use Axiom\Bridge\DatabaseProxy;
use Axiom\Bridge\HookMarshaller;
use Axiom\Bridge\StateSnapshotEngine;
use Axiom\Security\ManifestValidator;
use Axiom\Security\ResourceGovernor;
use Axiom\Profiler\AutomatedProfiler;
use Axiom\Profiler\AuditLogger;

final class Kernel
{
    private static ?Kernel $instance = null;

    private bool $initialized = false;

    private KernelConfig $config;
    private ManifestValidator $manifest_validator;
    private ResourceGovernor $resource_governor;
    private DatabaseProxy $database_proxy;
    private StateSnapshotEngine $snapshot_engine;
    private HookMarshaller $hook_marshaller;
    private IsolateManager $isolate_manager;
    private AutomatedProfiler $profiler;
    private AuditLogger $audit_logger;

    /**
     * Registered plugin contexts, keyed by plugin slug.
     * @var array<string, PluginContext>
     */
    private array $plugin_contexts = [];

    private function __construct()
    {
        $this->config = KernelConfig::load();
    }

    public static function get_instance(): self
    {
        if ( self::$instance === null ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Initialize all kernel subsystems in dependency order.
     */
    public function init(): void
    {
        if ( $this->initialized ) {
            return;
        }

        $this->audit_logger       = new AuditLogger( $this->config );
        $this->manifest_validator = new ManifestValidator( $this->config );

        if ( $this->config->is_learning_mode() ) {
            $this->profiler = new AutomatedProfiler( $this->config, $this->audit_logger );
        }

        $this->resource_governor = new ResourceGovernor( $this->config, $this->audit_logger );
        $this->resource_governor->register();

        $this->snapshot_engine = new StateSnapshotEngine( $this->config, $this->audit_logger );

        $this->database_proxy = new DatabaseProxy(
            $this->config,
            $this->manifest_validator,
            $this->audit_logger,
            $this->profiler ?? null
        );

        $this->isolate_manager = new IsolateManager(
            $this->config,
            $this->manifest_validator,
            $this->snapshot_engine,
            $this->resource_governor,
            $this->audit_logger,
            $this->profiler ?? null
        );

        $this->hook_marshaller = new HookMarshaller(
            $this->config,
            $this->isolate_manager,
            $this->manifest_validator,
            $this->audit_logger
        );

        $this->install_database_proxy();
        $this->install_hook_proxy();

        $this->initialized = true;

        $this->audit_logger->log( AuditLogger::INFO, 'Axiom Kernel initialized', [
            'version'     => AXIOM_KERNEL_VERSION,
            'mode'        => $this->config->mode(),
            'learning'    => $this->config->is_learning_mode(),
            'plugins'     => count( $this->plugin_contexts ),
        ] );
    }

    /**
     * Register a plugin under Axiom supervision.
     */
    public function register_plugin( string $plugin_slug, string $plugin_file, bool $is_modern = false ): PluginContext
    {
        $manifest = $this->manifest_validator->load_manifest( $plugin_slug, $plugin_file );

        $context = new PluginContext(
            $plugin_slug,
            $plugin_file,
            $manifest,
            $is_modern
        );

        $this->plugin_contexts[ $plugin_slug ] = $context;

        if ( $this->profiler !== null && $manifest === null ) {
            $this->profiler->watch_plugin( $plugin_slug, $plugin_file );
        }

        return $context;
    }

    /**
     * Retrieve a registered plugin context.
     */
    public function get_plugin_context( string $plugin_slug ): ?PluginContext
    {
        return $this->plugin_contexts[ $plugin_slug ] ?? null;
    }

    /**
     * Replace the global $wpdb with our proxied version.
     */
    private function install_database_proxy(): void
    {
        global $wpdb;
        $wpdb = $this->database_proxy->proxy( $wpdb );
    }

    /**
     * Wrap the WP_Hook instance to route through the HookMarshaller.
     */
    private function install_hook_proxy(): void
    {
        $this->hook_marshaller->install();
    }

    public function config(): KernelConfig
    {
        return $this->config;
    }

    public function manifest_validator(): ManifestValidator
    {
        return $this->manifest_validator;
    }

    public function database_proxy(): DatabaseProxy
    {
        return $this->database_proxy;
    }

    public function isolate_manager(): IsolateManager
    {
        return $this->isolate_manager;
    }

    public function hook_marshaller(): HookMarshaller
    {
        return $this->hook_marshaller;
    }

    public function resource_governor(): ResourceGovernor
    {
        return $this->resource_governor;
    }

    public function audit_logger(): AuditLogger
    {
        return $this->audit_logger;
    }

    public function profiler(): ?AutomatedProfiler
    {
        return $this->profiler;
    }

    /**
     * Prevent cloning.
     */
    private function __clone()
    {
    }
}
