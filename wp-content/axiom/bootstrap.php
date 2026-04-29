<?php
/**
 * Axiom Kernel Bootstrap
 *
 * Initializes the Axiom sandboxing kernel for Project Axiom-WP.
 * Loads all kernel subsystems and patches WordPress core globals.
 *
 * @package Axiom
 * @subpackage Bootstrap
 */

declare(strict_types=1);

namespace Axiom;

use Axiom\Kernel\Kernel;

const AXIOM_KERNEL_VERSION = '1.0.1';
const AXIOM_KERNEL_DIR     = __DIR__;

spl_autoload_register( static function ( string $class ): void {
    $prefix = 'Axiom\\';
    if ( strncmp( $class, $prefix, strlen( $prefix ) ) !== 0 ) {
        return;
    }

    $relative_class = substr( $class, strlen( $prefix ) );
    $file           = AXIOM_KERNEL_DIR . '/' . str_replace( '\\', '/', $relative_class ) . '.php';

    if ( file_exists( $file ) ) {
        require $file;
    }
} );

if ( ! defined( 'AXIOM_LOADED' ) ) {
    define( 'AXIOM_LOADED', true );

    \add_action( 'plugins_loaded', static function (): void {
        Kernel::get_instance()->init();

        $admin = \Axiom\Admin\Admin::get_instance();

        // Register AJAX handlers early — plugins_loaded fires for all
        // requests including admin-ajax.php (admin_init does not).
        $admin->register_ajax_handlers();

        if ( \is_admin() ) {
            // Register menus at plugins_loaded — admin_menu fires before
            // admin_init in this fork (see wp-admin/admin.php:163 vs 180).
            \add_action( 'admin_menu', [ $admin, 'register_menus' ], 9 );

            // Add isolation column to native plugins list table.
            $admin->register_plugin_list_column();

            // All other admin hooks (asset enqueue) on admin_init.
            \add_action( 'admin_init', static function () use ( $admin ): void {
                $admin->init();
            }, 0 );
        }
    }, 0 );
}
