<?php
/**
 * Axiom Plugins — Manifest Management
 *
 * @package Axiom\Admin\Views
 */

defined( 'ABSPATH' ) || exit;

$plugins = wp_get_active_and_valid_plugins();
?>
<div class="wrap ax-wrap">

    <h1 class="ax-page-title">Plugin Manifests</h1>

    <?php settings_errors( 'axiom_notices' ); ?>

    <div class="ax-card">
        <div class="ax-card-header">
            <h2 class="ax-card-title">Active Plugins</h2>
        </div>
        <div class="ax-card-body" style="padding:0;">
            <div class="ax-table-wrap">
                <table class="ax-table">
                    <thead>
                        <tr>
                            <th>Plugin</th>
                            <th>Manifest</th>
                            <th>Isolation</th>
                            <th>SQL Queries</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ( empty( $plugins ) ) : ?>
                            <tr>
                                <td colspan="5" style="text-align:center;color:var(--ax-text-muted);padding:24px;">
                                    No active plugins found.
                                </td>
                            </tr>
                        <?php endif; ?>

                        <?php foreach ( $plugins as $plugin_file ) :
                            $slug           = basename( dirname( $plugin_file ) );
                            $manifest_paths = [
                                dirname( $plugin_file ) . '/blueprint.json',
                                WP_CONTENT_DIR . '/axiom/manifests/' . $slug . '.json',
                            ];
                            $has_manifest = false;
                            $manifest_data = null;
                            foreach ( $manifest_paths as $mpath ) {
                                if ( file_exists( $mpath ) ) {
                                    $has_manifest = true;
                                    $manifest_data = json_decode( file_get_contents( $mpath ), true );
                                    break;
                                }
                            }

                            $context = defined( 'AXIOM_LOADED' ) && AXIOM_LOADED
                                ? \Axiom\Kernel\Kernel::get_instance()->get_plugin_context( $slug )
                                : null;

                            $sql_count    = $context?->sql_queries() ?? 0;
                            $hook_count   = $context?->hook_invocations() ?? 0;
                            $isolation    = $manifest_data['isolation'] ?? 'namespace';
                            $manifest_src = $manifest_data ? 'blueprint.json' : '—';
                            $plugin_name  = $slug;

                            $plugin_data = get_plugin_data( $plugin_file, false, false );
                            $plugin_name = $plugin_data['Name'] ?: $slug;
                        ?>
                        <tr>
                            <td>
                                <strong><?php echo esc_html( $plugin_name ); ?></strong>
                                <br><span class="ax-text-muted" style="font-size:11px;"><?php echo esc_html( $slug ); ?></span>
                            </td>
                            <td>
                                <?php if ( $has_manifest ) : ?>
                                    <span class="ax-status-dot is-active"></span> Present
                                <?php else : ?>
                                    <span class="ax-status-dot is-warning"></span> Missing
                                <?php endif; ?>
                            </td>
                            <td><?php echo esc_html( $isolation ); ?></td>
                            <td><?php echo esc_html( $sql_count ); ?></td>
                            <td>
                                <?php if ( ! $has_manifest ) : ?>
                                    <button class="ax-btn ax-btn-sm ax-btn-secondary ax-generate-manifest"
                                            data-plugin="<?php echo esc_attr( $slug ); ?>">
                                        Generate Manifest
                                    </button>
                                <?php else : ?>
                                    <button class="ax-btn ax-btn-sm ax-btn-secondary ax-generate-manifest"
                                            data-plugin="<?php echo esc_attr( $slug ); ?>">
                                        Regenerate
                                    </button>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="ax-card">
        <div class="ax-card-header">
            <h2 class="ax-card-title">What Is a Manifest?</h2>
        </div>
        <div class="ax-card-body">
            <p style="font-size:13px;">
                A <strong>manifest</strong> (or permission slip) is a <code>blueprint.json</code> file 
                that declares exactly what a plugin is allowed to do. It covers:
            </p>
            <ul style="font-size:13px;line-height:1.8;">
                <li><strong>Database tables</strong> the plugin can read, write, or modify</li>
                <li><strong>Files</strong> the plugin can access on the server</li>
                <li><strong>Network domains</strong> the plugin can contact</li>
                <li><strong>WordPress hooks</strong> the plugin can subscribe to</li>
                <li><strong>Resource limits</strong> for CPU and memory</li>
            </ul>
            <p style="font-size:13px;">
                Use <strong>Learning Mode</strong> to automatically generate manifests based on
                observed plugin behavior. Then review and switch to <strong>Enforce Mode</strong>
                to lock down permissions.
            </p>
        </div>
    </div>

</div>
