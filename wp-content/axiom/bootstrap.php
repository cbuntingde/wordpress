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

const AXIOM_KERNEL_VERSION = '1.0.0';
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

    Kernel::get_instance()->init();
}
