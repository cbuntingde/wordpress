<?php
/**
 * Axiom Security — Must-Use Plugin Loader
 *
 * Loads the Axiom kernel bootstrap during WordPress's MU plugin
 * phase, ensuring all WordPress functions are available.
 *
 * @package Axiom
 */

declare(strict_types=1);

defined( 'ABSPATH' ) || exit;

$axiom_bootstrap = WP_CONTENT_DIR . '/axiom/bootstrap.php';

if ( file_exists( $axiom_bootstrap ) ) {
    require_once $axiom_bootstrap;
}
