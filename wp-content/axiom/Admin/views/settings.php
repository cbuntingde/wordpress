<?php
/**
 * Axiom Settings — Security Configuration
 *
 * @package Axiom\Admin\Views
 */

defined( 'ABSPATH' ) || exit;

$current = get_option( 'axiom_settings', [] );
$mode    = $current['mode'] ?? $config?->mode() ?? 'learning';
$cpu     = $current['cpu_limit_ms'] ?? $config?->cpu_limit_ms() ?? 500;
$mem     = $current['memory_limit_mb'] ?? $config?->memory_limit_mb() ?? 64;
$strict  = $current['strict_sql'] ?? $config?->strict_sql() ?? false;
$level   = $current['log_level'] ?? $config?->log_level() ?? 'info';
?>
<div class="wrap ax-wrap">

    <h1 class="ax-page-title">Axiom Settings</h1>

    <?php settings_errors( 'axiom_notices' ); ?>

    <div class="ax-layout">

        <main class="ax-main">

            <div class="ax-card">
                <div class="ax-card-header">
                    <h2 class="ax-card-title">Security Mode</h2>
                </div>
                <div class="ax-card-body">
                    <form id="axiom-settings-form" method="post">

                        <div class="ax-field-row">
                            <label class="ax-label" for="ax-mode">Operating Mode</label>
                            <div>
                                <select class="ax-select" id="ax-mode" name="axiom_settings[mode]">
                                    <option value="learning" <?php selected( $mode, 'learning' ); ?>>Learning — Watch & record (safe for onboarding)</option>
                                    <option value="audit" <?php selected( $mode, 'audit' ); ?>>Audit — Log violations, allow execution</option>
                                    <option value="enforce" <?php selected( $mode, 'enforce' ); ?>>Enforce — Block unapproved actions (production)</option>
                                    <option value="disabled" <?php selected( $mode, 'disabled' ); ?>>Disabled — No sandboxing</option>
                                </select>
                                <p class="ax-field-desc">
                                    <strong>Learning</strong> watches plugins and generates permission slips automatically.
                                    <strong>Enforce</strong> is the production-ready mode that blocks unapproved activity.
                                </p>
                            </div>
                        </div>

                        <hr class="ax-divider">

                        <h3 style="margin:0 0 8px;font-size:14px;">Resource Limits</h3>

                        <div class="ax-field-row">
                            <label class="ax-label" for="ax-cpu">CPU Limit (ms)</label>
                            <div>
                                <input class="ax-input" type="number" id="ax-cpu" name="axiom_settings[cpu_limit_ms]"
                                       value="<?php echo esc_attr( $cpu ); ?>" min="50" max="10000" step="50">
                                <p class="ax-field-desc">Maximum milliseconds a plugin can run during a single hook callback. Default: 500.</p>
                            </div>
                        </div>

                        <div class="ax-field-row">
                            <label class="ax-label" for="ax-mem">Memory Limit (MB)</label>
                            <div>
                                <input class="ax-input" type="number" id="ax-mem" name="axiom_settings[memory_limit_mb]"
                                       value="<?php echo esc_attr( $mem ); ?>" min="8" max="1024" step="8">
                                <p class="ax-field-desc">Maximum megabytes a plugin can use during a single hook callback. Default: 64.</p>
                            </div>
                        </div>

                        <hr class="ax-divider">

                        <h3 style="margin:0 0 8px;font-size:14px;">Enforcement</h3>

                        <div class="ax-field-row">
                            <label class="ax-label" for="ax-strict">Strict SQL Mode</label>
                            <div>
                                <label style="display:flex;align-items:center;gap:8px;padding-top:6px;">
                                    <input type="checkbox" id="ax-strict" name="axiom_settings[strict_sql]" value="1" <?php checked( $strict, true ); ?>>
                                    <span>Enable strict SQL validation</span>
                                </label>
                                <p class="ax-field-desc">When enabled, the SQL checker performs deeper validation against the manifest.</p>
                            </div>
                        </div>

                        <hr class="ax-divider">

                        <h3 style="margin:0 0 8px;font-size:14px;">Logging</h3>

                        <div class="ax-field-row">
                            <label class="ax-label" for="ax-loglevel">Log Level</label>
                            <div>
                                <select class="ax-select" id="ax-loglevel" name="axiom_settings[log_level]">
                                    <option value="debug" <?php selected( $level, 'debug' ); ?>>Debug — Everything</option>
                                    <option value="info" <?php selected( $level, 'info' ); ?>>Info — Normal operations</option>
                                    <option value="warning" <?php selected( $level, 'warning' ); ?>>Warning — Only issues</option>
                                    <option value="error" <?php selected( $level, 'error' ); ?>>Error — Only errors</option>
                                    <option value="security" <?php selected( $level, 'security' ); ?>>Security — Only blocked actions</option>
                                </select>
                                <p class="ax-field-desc">Minimum severity to record in the audit log.</p>
                            </div>
                        </div>

                        <hr class="ax-divider">

                        <div style="padding-top:8px;">
                            <button type="submit" class="ax-btn ax-btn-primary">Save Changes</button>
                        </div>

                    </form>
                </div>
            </div>

        </main>

        <aside class="ax-sidebar">

            <div class="ax-card">
                <div class="ax-card-header">
                    <h3 class="ax-card-title">Configuration</h3>
                </div>
                <div class="ax-card-body" style="font-size:13px;">
                    <p>You can also set these values in <code>wp-config.php</code>:</p>
                    <pre style="font-size:11px;background:#f0f0f1;padding:8px;border-radius:4px;overflow-x:auto;">define('AXIOM_MODE', 'enforce');
define('AXIOM_CPU_LIMIT_MS', 500);
define('AXIOM_MEMORY_LIMIT_MB', 64);</pre>
                    <p class="ax-text-muted" style="font-size:12px;">Constants override the saved settings.</p>
                </div>
            </div>

        </aside>

    </div>

</div>
