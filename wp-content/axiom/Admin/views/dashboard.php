<?php
/**
 * Axiom Dashboard — Overview
 *
 * @package Axiom\Admin\Views
 */

defined( 'ABSPATH' ) || exit;

$current_mode = $config?->mode() ?? 'unknown';
$mode_label   = ucfirst( $current_mode );
?>
<div class="wrap ax-wrap">

    <h1 class="ax-page-title">Plugin Security</h1>

    <?php settings_errors( 'axiom_notices' ); ?>

    <div class="ax-layout">

        <main class="ax-main">

            <div class="ax-stats" id="axiom-overview-stats">
                <div class="ax-stat">
                    <div class="ax-stat-value" id="ax-stat-mode"><?php echo esc_html( $mode_label ); ?></div>
                    <div class="ax-stat-label">Mode</div>
                </div>
                <div class="ax-stat">
                    <div class="ax-stat-value" id="ax-stat-plugins">-</div>
                    <div class="ax-stat-label">Active Plugins</div>
                </div>
                <div class="ax-stat is-success">
                    <div class="ax-stat-value" id="ax-stat-manifest">-</div>
                    <div class="ax-stat-label">With Manifest</div>
                </div>
                <div class="ax-stat is-warning">
                    <div class="ax-stat-value" id="ax-stat-nomanifest">-</div>
                    <div class="ax-stat-label">Without Manifest</div>
                </div>
                <div class="ax-stat">
                    <div class="ax-stat-value" id="ax-stat-log">-</div>
                    <div class="ax-stat-label">Audit Events Today</div>
                </div>
                <div class="ax-stat is-error">
                    <div class="ax-stat-value" id="ax-stat-blocked">-</div>
                    <div class="ax-stat-label">Blocked Actions</div>
                </div>
            </div>

            <div class="ax-card ax-mt-md">
                <div class="ax-card-header">
                    <h2 class="ax-card-title">Current Status</h2>
                    <span class="ax-mode-badge is-<?php echo esc_attr( $current_mode ); ?>">
                        <?php echo esc_html( $mode_label ); ?> Mode
                    </span>
                </div>
                <div class="ax-card-body">
                    <?php if ( $current_mode === 'learning' ) : ?>
                        <p>Learning Mode is active. The <strong>Profiler</strong> is watching all plugin activity and recording what each plugin does. No actions are blocked.</p>
                        <p class="ax-text-muted">The stats below show audit events captured today &mdash; if you see events, the profiler has data and can auto-generate manifests. When ready, review the generated manifests under <strong>Plugins</strong>, then switch to <strong>Enforce</strong> mode in Settings.</p>
                    <?php elseif ( $current_mode === 'audit' ) : ?>
                        <p>Audit Mode is active. Axiom logs all unapproved actions but does not block them. Review the Audit Log to see what plugins are doing outside their manifests.</p>
                    <?php elseif ( $current_mode === 'enforce' ) : ?>
                        <p>Enforce Mode is active. Plugins are restricted to their declared manifests. Check the Audit Log for any blocked actions.</p>
                    <?php else : ?>
                        <p>Axiom is currently disabled. No security enforcement is active.</p>
                    <?php endif; ?>
                </div>
                <div class="ax-card-footer">
                    <a href="?page=axiom-settings" class="ax-btn ax-btn-primary">Configure Settings</a>
                    <a href="?page=axiom-audit-log" class="ax-btn ax-btn-secondary">View Audit Log</a>
                </div>
            </div>

            <div class="ax-card">
                <div class="ax-card-header">
                    <h2 class="ax-card-title">Quick Actions</h2>
                </div>
                <div class="ax-card-body">
                    <div class="ax-btn-group">
                        <a href="?page=axiom-plugins" class="ax-btn ax-btn-secondary">Manage Plugin Manifests</a>
                        <a href="?page=axiom-audit-log" class="ax-btn ax-btn-secondary">Review Audit Log</a>
                        <a href="?page=axiom-settings" class="ax-btn ax-btn-secondary">Change Security Mode</a>
                    </div>
                </div>
            </div>

        </main>

        <aside class="ax-sidebar">

            <div class="ax-card">
                <div class="ax-card-header">
                    <h3 class="ax-card-title">About Axiom</h3>
                </div>
                <div class="ax-card-body">
                    <p class="ax-text-muted" style="font-size:13px;">
                        Axiom protects your site by running each plugin in its own
                        secure space with a permission slip (manifest) that controls
                        exactly what it can access.
                    </p>
                    <p class="ax-text-muted" style="font-size:12px;">
                        Version <?php echo esc_html( \Axiom\AXIOM_KERNEL_VERSION ); ?>
                    </p>
                </div>
            </div>

            <div class="ax-card">
                <div class="ax-card-header">
                    <h3 class="ax-card-title">Resource Limits</h3>
                </div>
                <div class="ax-card-body" style="font-size:13px;">
                    <p><strong>CPU:</strong> <?php echo esc_html( $config?->cpu_limit_ms() ?? '500' ); ?>ms per hook</p>
                    <p><strong>Memory:</strong> <?php echo esc_html( $config?->memory_limit_mb() ?? '64' ); ?>MB per hook</p>
                    <p class="ax-text-muted" style="font-size:12px;">Exceeding these limits terminates the plugin isolate gracefully.</p>
                </div>
            </div>

        </aside>

    </div>

</div>
