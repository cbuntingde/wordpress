<?php
/**
 * Axiom Admin — WordPress Admin Dashboard for Plugin Security
 *
 * Registers admin menus, enqueues assets, and handles AJAX
 * endpoints for the Axiom security dashboard.
 *
 * @package Axiom\Admin
 */

declare(strict_types=1);

namespace Axiom\Admin;

use Axiom\Kernel\Kernel;
use Axiom\Kernel\KernelConfig;
use Axiom\Profiler\AuditLogger;
use Axiom\Profiler\AutomatedProfiler;

defined( 'ABSPATH' ) || exit;

final class Admin {

    private static ?self $instance = null;
    private string $assets_url   = '';
    private string $assets_path  = '';
    private        $kernel       = null;

    private function __construct() {
        $this->assets_url   = WP_CONTENT_URL . '/axiom/Admin';
        $this->assets_path  = WP_CONTENT_DIR . '/axiom/Admin';
    }

    public static function get_instance(): self {
        if ( self::$instance === null ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function init(): void {
        if ( ! \is_admin() ) {
            return;
        }

        \add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_assets' ] );
    }

    /**
     * Register AJAX handlers on plugins_loaded so they're available
     * for admin-ajax.php requests (admin_init doesn't fire there).
     */
    public function register_ajax_handlers(): void {
        \add_action( 'wp_ajax_axiom_save_settings', [ $this, 'ajax_save_settings' ] );
        \add_action( 'wp_ajax_axiom_generate_manifest', [ $this, 'ajax_generate_manifest' ] );
        \add_action( 'wp_ajax_axiom_view_log', [ $this, 'ajax_view_log' ] );
        \add_action( 'wp_ajax_axiom_clear_log', [ $this, 'ajax_clear_log' ] );
        \add_action( 'wp_ajax_axiom_refresh_overview', [ $this, 'ajax_refresh_overview' ] );
        \add_action( 'wp_ajax_axiom_get_manifest', [ $this, 'ajax_get_manifest' ] );
        \add_action( 'wp_ajax_axiom_save_manifest', [ $this, 'ajax_save_manifest' ] );
    }

    public function register_menus(): void {
        \add_menu_page(
            'Plugin Security',
            'Plugin Security',
            'manage_options',
            'axiom-security',
            [ $this, 'render_dashboard' ],
            'dashicons-shield',
            66
        );

        \add_submenu_page(
            'axiom-security',
            'Dashboard',
            'Dashboard',
            'manage_options',
            'axiom-security',
            [ $this, 'render_dashboard' ]
        );

        \add_submenu_page(
            'axiom-security',
            'Settings',
            'Settings',
            'manage_options',
            'axiom-settings',
            [ $this, 'render_settings' ]
        );

        \add_submenu_page(
            'axiom-security',
            'Plugins',
            'Plugins',
            'manage_options',
            'axiom-plugins',
            [ $this, 'render_plugins' ]
        );

        \add_submenu_page(
            'axiom-security',
            'Audit Log',
            'Audit Log',
            'manage_options',
            'axiom-audit-log',
            [ $this, 'render_audit_log' ]
        );
    }

    public function enqueue_assets( string $hook ): void {
        // Skip assets unless we're on a Plugin Security admin page or the plugins list.
        if ( ! str_starts_with( $hook, 'toplevel_page_axiom-security' )
            && ! str_contains( $hook, '_page_axiom-' )
            && $hook !== 'plugins.php'
        ) {
            return;
        }

        \wp_enqueue_style(
            'axiom-admin',
            $this->assets_url . '/css/admin.css',
            [],
            \Axiom\AXIOM_KERNEL_VERSION
        );

        \wp_enqueue_script(
            'axiom-admin',
            $this->assets_url . '/js/admin.js',
            [ 'jquery' ],
            \Axiom\AXIOM_KERNEL_VERSION,
            true
        );

        \wp_localize_script( 'axiom-admin', 'axiomAdmin', [
            'ajaxUrl' => \admin_url( 'admin-ajax.php' ),
            'nonce'   => \wp_create_nonce( 'axiom_admin_nonce' ),
            'i18n'    => [
                'saved'          => 'Settings saved successfully.',
                'error'          => 'An error occurred.',
                'generatePrompt' => 'Generate a manifest for this plugin based on observed activity?',
                'generated'      => 'Manifest generated.',
                'logCleared'     => 'Audit log cleared.',
                'confirmClear'   => 'Clear all audit log entries? This cannot be undone.',
            ],
        ] );
    }

    public function load_kernel(): void {
        if ( $this->kernel === null && defined( 'AXIOM_LOADED' ) && AXIOM_LOADED ) {
            $this->kernel = Kernel::get_instance();
        }
    }

    public function kernel(): ?Kernel {
        $this->load_kernel();
        return $this->kernel;
    }

    /* ---- Renderers ---- */

    public function render_dashboard(): void {
        $this->load_kernel();
        $config = $this->kernel?->config();
        include $this->assets_path . '/views/dashboard.php';
    }

    public function render_settings(): void {
        $this->load_kernel();
        $config = $this->kernel?->config();
        include $this->assets_path . '/views/settings.php';
    }

    public function render_plugins(): void {
        $this->load_kernel();
        $config = $this->kernel?->config();
        include $this->assets_path . '/views/plugins.php';
    }

    public function render_audit_log(): void {
        $this->load_kernel();
        $config = $this->kernel?->config();
        include $this->assets_path . '/views/audit-log.php';
    }

    /* ---- Plugin list column ---- */

    public function register_plugin_list_column(): void {
        \add_filter( 'manage_plugins_columns', [ $this, 'add_isolation_column' ] );
        \add_action( 'manage_plugins_custom_column', [ $this, 'render_isolation_column' ], 10, 3 );
    }

    public function add_isolation_column( array $columns ): array {
        $before = 'auto-updates';
        $out    = [];
        foreach ( $columns as $key => $label ) {
            if ( $key === $before ) {
                $out['axiom_isolation'] = '<span class="dashicons dashicons-shield" style="font-size:16px;width:16px;height:16px;" title="Axiom Isolation"></span> <span style="display:none;">Isolation</span>';
            }
            $out[ $key ] = $label;
        }
        return $out;
    }

    public function render_isolation_column( string $column_name, string $plugin_file, array $plugin_data ): void {
        if ( $column_name !== 'axiom_isolation' ) {
            return;
        }

        $this->load_kernel();
        if ( $this->kernel === null ) {
            echo '<span class="dashicons dashicons-shield" style="color:#bbb;" title="Axiom not initialized"></span>';
            return;
        }

        $slug = \dirname( $plugin_file );
        if ( $slug === '.' || $slug === '/' || $slug === '\\' ) {
            $slug = \basename( $plugin_file, '.php' );
        }
        $context = $this->kernel->get_plugin_context( $slug );

        if ( $context === null ) {
            echo '<span class="dashicons dashicons-shield" style="color:#ddd;" title="Not tracked"></span> —';
            return;
        }

        if ( $context->has_manifest() ) {
            echo '<span class="dashicons dashicons-shield" style="color:#00a32a;" title="Protected by manifest"></span>'
               . ' <span style="color:#00a32a;font-weight:500;">Protected</span>';
        } else {
            echo '<span class="dashicons dashicons-shield" style="color:#dba617;" title="Learning mode — no manifest yet"></span>'
               . ' <span style="color:#dba617;font-weight:500;">Learning</span>';
        }
    }

    /* ---- AJAX handlers ---- */

    public function ajax_save_settings(): void {
        \check_ajax_referer( 'axiom_admin_nonce', 'nonce' );
        if ( ! \current_user_can( 'manage_options' ) ) {
            \wp_send_json_error( [ 'message' => 'Insufficient permissions.' ], 403 );
        }

        $opts = $_POST['options'] ?? [];
        $sanitized = $this->sanitize_settings( $opts );
        \update_option( 'axiom_settings', $sanitized );

        \wp_send_json_success( [ 'message' => 'Settings saved.' ] );
    }

    public function ajax_generate_manifest(): void {
        \check_ajax_referer( 'axiom_admin_nonce', 'nonce' );
        if ( ! \current_user_can( 'manage_options' ) ) {
            \wp_send_json_error( [ 'message' => 'Insufficient permissions.' ], 403 );
        }

        $plugin_slug = \sanitize_text_field( $_POST['plugin_slug'] ?? '' );
        if ( $plugin_slug === '' ) {
            \wp_send_json_error( [ 'message' => 'No plugin specified.' ] );
            return;
        }

        $this->load_kernel();
        $profiler = $this->kernel?->profiler();

        // If profiler exists with observed data, generate from behavior.
        if ( $profiler !== null ) {
            $path = $profiler->write_manifest( $plugin_slug );
            if ( $path ) {
                \wp_send_json_success( [ 'message' => "Manifest generated from observed behaviour: {$path}." ] );
                return;
            }
        }

        // Fallback: write a default manifest skeleton with open permissions.
        $manifest_dir = WP_CONTENT_DIR . '/axiom/manifests';
        if ( ! \is_dir( $manifest_dir ) ) {
            \wp_mkdir_p( $manifest_dir );
        }

        $file     = $manifest_dir . '/' . $plugin_slug . '.json';
        $manifest = \Axiom\Profiler\ManifestGenerator::skeleton( $plugin_slug );

        if ( \Axiom\Profiler\ManifestGenerator::write( $manifest, $file ) ) {
            \wp_send_json_success( [ 'message' => "Default manifest created for {$plugin_slug}. Review and adjust the permissions under Plugins." ] );
        } else {
            \wp_send_json_error( [ 'message' => 'Failed to write manifest file.' ] );
        }
    }

    public function ajax_view_log(): void {
        \check_ajax_referer( 'axiom_admin_nonce', 'nonce' );
        if ( ! \current_user_can( 'manage_options' ) ) {
            \wp_send_json_error( [ 'message' => 'Insufficient permissions.' ], 403 );
        }

        $level  = \sanitize_text_field( $_POST['level'] ?? '' );
        $search = \sanitize_text_field( $_POST['search'] ?? '' );
        $offset = max( 0, (int) ( $_POST['offset'] ?? 0 ) );
        $limit  = min( 100, max( 10, (int) ( $_POST['limit'] ?? 50 ) ) );

        $log_file = WP_CONTENT_DIR . '/axiom/audit-' . gmdate( 'Y-m-d' ) . '.log';
        if ( ! file_exists( $log_file ) ) {
            \wp_send_json_success( [ 'entries' => [], 'total' => 0 ] );
        }

        $lines = file( $log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
        $entries = [];

        foreach ( $lines as $line ) {
            $entry = json_decode( $line, true );
            if ( $entry === null ) {
                continue;
            }
            if ( $level !== '' && ( $entry['level'] ?? '' ) !== $level ) {
                continue;
            }
            if ( $search !== '' ) {
                $haystack = strtolower( $entry['message'] . ' ' . \wp_json_encode( $entry['context'] ?? [] ) );
                if ( ! str_contains( $haystack, strtolower( $search ) ) ) {
                    continue;
                }
            }
            $entries[] = $entry;
        }

        $total = count( $entries );
        $entries = array_slice( array_reverse( $entries ), $offset, $limit );

        \wp_send_json_success( [ 'entries' => $entries, 'total' => $total ] );
    }

    public function ajax_clear_log(): void {
        \check_ajax_referer( 'axiom_admin_nonce', 'nonce' );
        if ( ! \current_user_can( 'manage_options' ) ) {
            \wp_send_json_error( [ 'message' => 'Insufficient permissions.' ], 403 );
        }

        $log_file = WP_CONTENT_DIR . '/axiom/audit-' . gmdate( 'Y-m-d' ) . '.log';
        file_put_contents( $log_file, '' );

        \wp_send_json_success( [ 'message' => 'Audit log cleared.' ] );
    }

    public function ajax_refresh_overview(): void {
        \check_ajax_referer( 'axiom_admin_nonce', 'nonce' );
        if ( ! \current_user_can( 'manage_options' ) ) {
            \wp_send_json_error( [ 'message' => 'Insufficient permissions.' ], 403 );
        }

        $this->load_kernel();

        $log_file = WP_CONTENT_DIR . '/axiom/audit-' . gmdate( 'Y-m-d' ) . '.log';
        $log_count = 0;
        $blocked_count = 0;
        if ( file_exists( $log_file ) ) {
            $lines = file( $log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
            $log_count = count( $lines );
            foreach ( $lines as $line ) {
                $entry = json_decode( $line, true );
                if ( ( $entry['level'] ?? '' ) === 'security' ) {
                    $blocked_count++;
                }
            }
        }

        $has_manifest = 0;
        $no_manifest  = 0;
        foreach ( \wp_get_active_and_valid_plugins() as $plugin ) {
            $plugin_dir = dirname( $plugin );
            $slug = basename( $plugin_dir );
            if ( $plugin_dir === WP_PLUGIN_DIR || $slug === '.' || $slug === '/' || $slug === '\\' ) {
                $slug = basename( $plugin, '.php' );
            }
            $manifest_file = WP_CONTENT_DIR . '/axiom/manifests/' . $slug . '.json';
            $bp_file = dirname( $plugin ) . '/blueprint.json';
            if ( file_exists( $manifest_file ) || file_exists( $bp_file ) ) {
                $has_manifest++;
            } else {
                $no_manifest++;
            }
        }

        $mode = $this->kernel?->config()?->mode() ?? 'unknown';

        \wp_send_json_success( [
            'mode'         => $mode,
            'has_manifest' => $has_manifest,
            'no_manifest'  => $no_manifest,
            'log_count'    => $log_count,
            'blocked'      => $blocked_count,
            'total_plugins' => $has_manifest + $no_manifest,
        ] );
    }

    /* ---- Manifest editor AJAX ---- */

    public function ajax_get_manifest(): void {
        \check_ajax_referer( 'axiom_admin_nonce', 'nonce' );
        if ( ! \current_user_can( 'manage_options' ) ) {
            \wp_send_json_error( [ 'message' => 'Insufficient permissions.' ], 403 );
        }

        $slug = \sanitize_text_field( $_POST['plugin_slug'] ?? '' );
        if ( $slug === '' ) {
            \wp_send_json_error( [ 'message' => 'No plugin specified.' ] );
        }

        $manifest = $this->load_manifest_data( $slug );
        if ( $manifest !== null ) {
            \wp_send_json_success( $manifest );
        }

        // Return a default template for new manifests (matching skeleton format).
        \wp_send_json_success( \Axiom\Profiler\ManifestGenerator::skeleton( $slug ) );
    }

    public function ajax_save_manifest(): void {
        \check_ajax_referer( 'axiom_admin_nonce', 'nonce' );
        if ( ! \current_user_can( 'manage_options' ) ) {
            \wp_send_json_error( [ 'message' => 'Insufficient permissions.' ], 403 );
        }

        $slug = \sanitize_text_field( $_POST['plugin_slug'] ?? '' );
        $raw  = $_POST['manifest'] ?? [];
        if ( $slug === '' ) {
            \wp_send_json_error( [ 'message' => 'Invalid plugin slug.' ] );
        }

        // Decode JSON string if sent as string (from JS JSON.stringify).
        if ( \is_string( $raw ) ) {
            $raw = \json_decode( $raw, true );
        }

        if ( ! \is_array( $raw ) || empty( $raw ) ) {
            \wp_send_json_error( [ 'message' => 'Invalid manifest data.' ] );
        }

        $manifest_dir = WP_CONTENT_DIR . '/axiom/manifests';
        if ( ! \is_dir( $manifest_dir ) ) {
            \wp_mkdir_p( $manifest_dir );
        }

        $file = $manifest_dir . '/' . $slug . '.json';
        $json = \json_encode( $raw, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
        if ( \file_put_contents( $file, $json, LOCK_EX ) !== false ) {
            \wp_send_json_success( [ 'message' => "Manifest saved for {$slug}." ] );
        }

        \wp_send_json_error( [ 'message' => 'Failed to write manifest file.' ] );
    }

    private function load_manifest_data( string $slug ): ?array {
        $paths = [
            WP_CONTENT_DIR . '/axiom/manifests/' . $slug . '.json',
        ];
        foreach ( $paths as $path ) {
            if ( \file_exists( $path ) ) {
                $data = \json_decode( \file_get_contents( $path ), true );
                if ( \is_array( $data ) ) {
                    return $data;
                }
            }
        }
        // Also check each active plugin's directory.
        foreach ( \wp_get_active_and_valid_plugins() as $plugin ) {
            $pdir = \dirname( $plugin );
            $pslug = \basename( $pdir );
            if ( $pdir === WP_PLUGIN_DIR || $pslug === '.' || $pslug === '/' || $pslug === '\\' ) {
                $pslug = \basename( $plugin, '.php' );
            }
            if ( $pslug === $slug ) {
                $bp = $pdir . '/blueprint.json';
                if ( \file_exists( $bp ) ) {
                    $data = \json_decode( \file_get_contents( $bp ), true );
                    if ( \is_array( $data ) ) {
                        return $data;
                    }
                }
            }
        }
        return null;
    }

    private function sanitize_settings( array $raw ): array {
        $defaults = [
            'mode'            => 'learning',
            'cpu_limit_ms'    => 500,
            'memory_limit_mb' => 64,
            'strict_sql'      => false,
            'log_level'       => 'info',
        ];

        $valid_modes = [ 'learning', 'audit', 'enforce', 'disabled' ];
        $valid_levels = [ 'debug', 'info', 'warning', 'error', 'security' ];

        return [
            'mode'            => in_array( $raw['mode'] ?? '', $valid_modes, true ) ? $raw['mode'] : $defaults['mode'],
            'cpu_limit_ms'    => max( 50, min( 10000, (int) ( $raw['cpu_limit_ms'] ?? $defaults['cpu_limit_ms'] ) ) ),
            'memory_limit_mb' => max( 8, min( 1024, (int) ( $raw['memory_limit_mb'] ?? $defaults['memory_limit_mb'] ) ) ),
            'strict_sql'      => ! empty( $raw['strict_sql'] ),
            'log_level'       => in_array( $raw['log_level'] ?? '', $valid_levels, true ) ? $raw['log_level'] : $defaults['log_level'],
        ];
    }
}
