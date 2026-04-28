<?php
/**
 * Axiom Audit Log — Security Event Viewer
 *
 * @package Axiom\Admin\Views
 */

defined( 'ABSPATH' ) || exit;

$log_file = WP_CONTENT_DIR . '/axiom/audit-' . gmdate( 'Y-m-d' ) . '.log';
$has_log  = file_exists( $log_file ) && filesize( $log_file ) > 0;
?>
<div class="wrap ax-wrap">

    <h1 class="ax-page-title">Audit Log</h1>

    <?php settings_errors( 'axiom_notices' ); ?>

    <div class="ax-card">
        <div class="ax-card-header">
            <h2 class="ax-card-title">Security Events</h2>
            <div>
                <button class="ax-btn ax-btn-sm ax-btn-danger" id="axiom-clear-log">Clear Log</button>
            </div>
        </div>
        <div class="ax-card-body">

            <div class="ax-log-filters">
                <select class="ax-select" id="ax-log-level" style="max-width:160px;">
                    <option value="">All Levels</option>
                    <option value="debug">Debug</option>
                    <option value="info">Info</option>
                    <option value="warning">Warning</option>
                    <option value="error">Error</option>
                    <option value="security">Security</option>
                    <option value="learning">Learning</option>
                </select>

                <input class="ax-search" type="search" id="ax-log-search" placeholder="Search entries..." style="max-width:240px;">

                <span class="ax-text-muted" style="font-size:12px;">Today's log only</span>
            </div>

            <div id="axiom-log-container">
                <?php if ( ! $has_log ) : ?>
                    <div class="ax-log-empty">No log entries for today.</div>
                <?php endif; ?>
                <div id="axiom-log-entries"></div>
            </div>

        </div>
        <div class="ax-card-footer">
            <span class="ax-text-muted" style="font-size:12px;">
                Log file: <code>wp-content/axiom/audit-<?php echo esc_html( gmdate( 'Y-m-d' ) ); ?>.log</code>
            </span>
        </div>
    </div>

</div>
