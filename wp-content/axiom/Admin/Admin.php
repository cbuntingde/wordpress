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
        if ( ! is_admin() ) {
            return;
        }

        add_action( 'admin_menu', [ $this, 'register_menus' ], 9 );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_assets' ] );
        add_action( 'wp_ajax_axiom_save_settings', [ $this, 'ajax_save_settings' ] );
        add_action( 'wp_ajax_axiom_generate_manifest', [ $this, 'ajax_generate_manifest' ] );
        add_action( 'wp_ajax_axiom_view_log', [ $this, 'ajax_view_log' ] );
        add_action( 'wp_ajax_axiom_clear_log', [ $this, 'ajax_clear_log' ] );
        add_action( 'wp_ajax_axiom_refresh_overview', [ $this, 'ajax_refresh_overview' ] );
    }

    public function register_menus(): void {
        add_menu_page(
            'Axiom Security',
            'Axiom Security',
            'manage_options',
            'axiom-security',
            [ $this, 'render_dashboard' ],
            'dashicons-shield',
            3
        );

        add_submenu_page(
            'axiom-security',
            'Dashboard',
            'Dashboard',
            'manage_options',
            'axiom-security',
            [ $this, 'render_dashboard' ]
        );

        add_submenu_page(
            'axiom-security',
            'Settings',
            'Settings',
            'manage_options',
            'axiom-settings',
            [ $this, 'render_settings' ]
        );

        add_submenu_page(
            'axiom-security',
            'Plugins',
            'Plugins',
            'manage_options',
            'axiom-plugins',
            [ $this, 'render_plugins' ]
        );

        add_submenu_page(
            'axiom-security',
            'Audit Log',
            'Audit Log',
            'manage_options',
            'axiom-audit-log',
            [ $this, 'render_audit_log' ]
        );
    }

    public function enqueue_assets( string $hook ): void {
        $valid = [
            'toplevel_page_axiom-security',
            'axiom-security_page_axiom-settings',
            'axiom-security_page_axiom-plugins',
            'axiom-security_page_axiom-audit-log',
        ];

        if ( ! in_array( $hook, $valid, true ) ) {
            return;
        }

        wp_enqueue_style(
            'axiom-admin',
            $this->assets_url . '/css/admin.css',
            [],
            AXIOM_KERNEL_VERSION
        );

        wp_enqueue_script(
            'axiom-admin',
            $this->assets_url . '/js/admin.js',
            [ 'jquery' ],
            AXIOM_KERNEL_VERSION,
            true
        );

        wp_localize_script( 'axiom-admin', 'axiomAdmin', [
            'ajaxUrl' => admin_url( 'admin-ajax.php' ),
            'nonce'   => wp_create_nonce( 'axiom_admin_nonce' ),
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

    /* ---- AJAX handlers ---- */

    public function ajax_save_settings(): void {
        check_ajax_referer( 'axiom_admin_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => 'Insufficient permissions.' ], 403 );
        }

        $opts = $_POST['options'] ?? [];
        $sanitized = $this->sanitize_settings( $opts );
        update_option( 'axiom_settings', $sanitized );

        wp_send_json_success( [ 'message' => 'Settings saved.' ] );
    }

    public function ajax_generate_manifest(): void {
        check_ajax_referer( 'axiom_admin_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => 'Insufficient permissions.' ], 403 );
        }

        $plugin_slug = sanitize_text_field( $_POST['plugin_slug'] ?? '' );
        if ( $plugin_slug === '' ) {
            wp_send_json_error( [ 'message' => 'No plugin specified.' ] );
        }

        $profiler = $this->kernel?->profiler();
        if ( $profiler === null ) {
            update_option( 'axiom_pending_manifest', $plugin_slug );
            wp_send_json_success( [ 'message' => 'Manifest generation queued. Visit the plugin page after the next request with learning mode active.' ] );
        }

        $path = $profiler?->write_manifest( $plugin_slug );
        if ( $path ) {
            wp_send_json_success( [ 'message' => "Manifest written to {$path}." ] );
        } else {
            wp_send_json_error( [ 'message' => 'No profiling data available for this plugin.' ] );
        }
    }

    public function ajax_view_log(): void {
        check_ajax_referer( 'axiom_admin_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => 'Insufficient permissions.' ], 403 );
        }

        $level  = sanitize_text_field( $_POST['level'] ?? '' );
        $search = sanitize_text_field( $_POST['search'] ?? '' );
        $offset = max( 0, (int) ( $_POST['offset'] ?? 0 ) );
        $limit  = min( 100, max( 10, (int) ( $_POST['limit'] ?? 50 ) ) );

        $log_file = WP_CONTENT_DIR . '/axiom/audit-' . gmdate( 'Y-m-d' ) . '.log';
        if ( ! file_exists( $log_file ) ) {
            wp_send_json_success( [ 'entries' => [], 'total' => 0 ] );
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
                $haystack = strtolower( $entry['message'] . ' ' . wp_json_encode( $entry['context'] ?? [] ) );
                if ( ! str_contains( $haystack, strtolower( $search ) ) ) {
                    continue;
                }
            }
            $entries[] = $entry;
        }

        $total = count( $entries );
        $entries = array_slice( array_reverse( $entries ), $offset, $limit );

        wp_send_json_success( [ 'entries' => $entries, 'total' => $total ] );
    }

    public function ajax_clear_log(): void {
        check_ajax_referer( 'axiom_admin_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => 'Insufficient permissions.' ], 403 );
        }

        $log_file = WP_CONTENT_DIR . '/axiom/audit-' . gmdate( 'Y-m-d' ) . '.log';
        file_put_contents( $log_file, '' );

        wp_send_json_success( [ 'message' => 'Audit log cleared.' ] );
    }

    public function ajax_refresh_overview(): void {
        check_ajax_referer( 'axiom_admin_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => 'Insufficient permissions.' ], 403 );
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
        foreach ( wp_get_active_and_valid_plugins() as $plugin ) {
            $slug = basename( dirname( $plugin ) );
            $manifest_file = WP_CONTENT_DIR . '/axiom/manifests/' . $slug . '.json';
            $bp_file = dirname( $plugin ) . '/blueprint.json';
            if ( file_exists( $manifest_file ) || file_exists( $bp_file ) ) {
                $has_manifest++;
            } else {
                $no_manifest++;
            }
        }

        $mode = $this->kernel?->config()?->mode() ?? 'unknown';

        wp_send_json_success( [
            'mode'         => $mode,
            'has_manifest' => $has_manifest,
            'no_manifest'  => $no_manifest,
            'log_count'    => $log_count,
            'blocked'      => $blocked_count,
            'total_plugins' => $has_manifest + $no_manifest,
        ] );
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
