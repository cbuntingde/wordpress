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
                            $plugin_dir     = dirname( $plugin_file );
                            $slug           = basename( $plugin_dir );
                            if ( $plugin_dir === WP_PLUGIN_DIR || $slug === '.' || $slug === '/' || $slug === '\\' ) {
                                $slug = basename( $plugin_file, '.php' );
                            }
                            $manifest_paths = [
                                ( $plugin_dir === '.' ? WP_PLUGIN_DIR : $plugin_dir ) . '/blueprint.json',
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
                                <button class="ax-btn ax-btn-sm ax-btn-tertiary ax-edit-manifest"
                                        data-plugin="<?php echo esc_attr( $slug ); ?>"
                                        style="margin-left:4px;">
                                    <?php echo $has_manifest ? 'Edit' : 'Create'; ?>
                                </button>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Manifest Editor Modal -->
    <div id="ax-manifest-editor" class="ax-modal" style="display:none;">
        <div class="ax-modal-backdrop" style="position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:100000;"></div>
        <div class="ax-modal-content" style="position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:80%;max-width:960px;max-height:90vh;background:#fff;border-radius:8px;box-shadow:0 8px 32px rgba(0,0,0,0.2);z-index:100001;overflow:hidden;display:flex;flex-direction:column;">
            <div class="ax-modal-header" style="display:flex;align-items:center;justify-content:space-between;padding:16px 24px;border-bottom:1px solid #e0e0e0;">
                <h3 style="margin:0;font-size:16px;">Manifest Editor: <span id="ax-editor-plugin-name"></span></h3>
                <button id="ax-editor-close" style="background:none;border:none;font-size:20px;cursor:pointer;padding:4px 8px;">&times;</button>
            </div>
            <div class="ax-modal-body" style="flex:1;overflow-y:auto;padding:16px 24px;">
                <p class="ax-text-muted" style="font-size:13px;margin-top:0;">
                    Configure what this plugin is allowed to do. Changes take effect immediately in enforce mode.
                </p>

                <div id="ax-editor-error" style="color:#d63638;font-size:13px;margin-bottom:12px;display:none;"></div>

                <!-- Isolation -->
                <div class="ax-field-row">
                    <label class="ax-label" for="ax-editor-isolation">Isolation Mode</label>
                    <div>
                        <select id="ax-editor-isolation" class="ax-input" style="max-width:300px;">
                            <option value="namespace">Namespace — isolate by namespace</option>
                            <option value="process">Process — isolate in separate process</option>
                            <option value="none">None — no isolation</option>
                        </select>
                        <p class="ax-field-desc">How strictly the plugin is separated from others.</p>
                    </div>
                </div>

                <!-- Resource Limits -->
                <fieldset class="ax-editor-section">
                    <legend class="ax-section-title">Resource Limits</legend>
                    <div class="ax-field-row">
                        <label class="ax-label" for="ax-editor-cpu">CPU Limit (ms)</label>
                        <div>
                            <input type="number" id="ax-editor-cpu" class="ax-input" min="50" max="10000" step="50" style="max-width:160px;">
                            <p class="ax-field-desc">Maximum CPU time per request (50–10000ms).</p>
                        </div>
                    </div>
                    <div class="ax-field-row">
                        <label class="ax-label" for="ax-editor-memory">Memory Limit (MB)</label>
                        <div>
                            <input type="number" id="ax-editor-memory" class="ax-input" min="8" max="1024" step="8" style="max-width:160px;">
                            <p class="ax-field-desc">Maximum memory usage (8–1024 MB).</p>
                        </div>
                    </div>
                </fieldset>

                <!-- Database Permissions -->
                <fieldset class="ax-editor-section">
                    <legend class="ax-section-title">Database Permissions</legend>
                    <p class="ax-text-muted" style="font-size:12px;margin:-8px 0 8px;">Comma-separated table names the plugin can access.</p>
                    <div class="ax-field-row">
                        <label class="ax-label" for="ax-editor-db-read">Read Tables</label>
                        <input type="text" id="ax-editor-db-read" class="ax-input" placeholder="e.g. wp_posts, wp_postmeta">
                    </div>
                    <div class="ax-field-row">
                        <label class="ax-label" for="ax-editor-db-write">Write Tables</label>
                        <input type="text" id="ax-editor-db-write" class="ax-input" placeholder="e.g. wp_posts, wp_postmeta">
                    </div>
                    <div class="ax-field-row">
                        <label class="ax-label" for="ax-editor-db-delete">Delete Tables</label>
                        <input type="text" id="ax-editor-db-delete" class="ax-input" placeholder="e.g. wp_posts">
                    </div>
                    <div class="ax-field-row">
                        <label class="ax-label" for="ax-editor-db-alter">Alter Tables</label>
                        <input type="text" id="ax-editor-db-alter" class="ax-input" placeholder="e.g. wp_posts">
                    </div>
                </fieldset>

                <!-- Filesystem -->
                <fieldset class="ax-editor-section">
                    <legend class="ax-section-title">Filesystem Access</legend>
                    <div class="ax-field-row">
                        <label class="ax-label" for="ax-editor-filesystem">Allowed Paths</label>
                        <div>
                            <input type="text" id="ax-editor-filesystem" class="ax-input" placeholder="e.g. /path/to/dir, /path/to/file.txt">
                            <p class="ax-field-desc">Comma-separated file/directory paths the plugin can read or write.</p>
                        </div>
                    </div>
                </fieldset>

                <!-- Network -->
                <fieldset class="ax-editor-section">
                    <legend class="ax-section-title">Network Access</legend>
                    <div class="ax-field-row">
                        <label class="ax-label" for="ax-editor-network">Outbound Domains</label>
                        <div>
                            <input type="text" id="ax-editor-network" class="ax-input" placeholder="e.g. api.example.com, cdn.example.com">
                            <p class="ax-field-desc">Comma-separated domains the plugin can contact.</p>
                        </div>
                    </div>
                </fieldset>

                <!-- WP Hooks -->
                <fieldset class="ax-editor-section">
                    <legend class="ax-section-title">WordPress Hooks</legend>
                    <div class="ax-field-row">
                        <label class="ax-label" for="ax-editor-hooks-read">Read-Only Hooks</label>
                        <input type="text" id="ax-editor-hooks-read" class="ax-input" placeholder="e.g. the_content, wp_head">
                    </div>
                    <div class="ax-field-row">
                        <label class="ax-label" for="ax-editor-hooks-write">Write Hooks</label>
                        <div>
                            <input type="text" id="ax-editor-hooks-write" class="ax-input" placeholder="e.g. save_post, wp_insert_post">
                            <p class="ax-field-desc">Hooks the plugin can modify data through. Comma-separated.</p>
                        </div>
                    </div>
                </fieldset>

                <!-- Options -->
                <fieldset class="ax-editor-section">
                    <legend class="ax-section-title">Options Permissions</legend>
                    <div class="ax-field-row">
                        <label class="ax-label" for="ax-editor-options-read">Read Options</label>
                        <input type="text" id="ax-editor-options-read" class="ax-input" placeholder="e.g. siteurl, blogname">
                    </div>
                    <div class="ax-field-row">
                        <label class="ax-label" for="ax-editor-options-write">Write Options</label>
                        <div>
                            <input type="text" id="ax-editor-options-write" class="ax-input" placeholder="e.g. myplugin_settings">
                            <p class="ax-field-desc">Comma-separated option names the plugin can read or write.</p>
                        </div>
                    </div>
                </fieldset>

                <!-- Users -->
                <fieldset class="ax-editor-section">
                    <legend class="ax-section-title">User Permissions</legend>
                    <div class="ax-field-row">
                        <label class="ax-label" for="ax-editor-users-read">Read User Data</label>
                        <div>
                            <input type="text" id="ax-editor-users-read" class="ax-input" placeholder="e.g. administrator, subscriber">
                            <p class="ax-field-desc">Comma-separated roles whose data the plugin can read.</p>
                        </div>
                    </div>
                </fieldset>

                <!-- System -->
                <fieldset class="ax-editor-section">
                    <legend class="ax-section-title">System Capabilities</legend>
                    <div class="ax-field-row">
                        <label class="ax-label" for="ax-editor-system">Allowed Syscalls</label>
                        <div>
                            <input type="text" id="ax-editor-system" class="ax-input" placeholder="e.g. exec, shell_exec, proc_open">
                            <p class="ax-field-desc">Comma-separated system functions. Leave empty to block all.</p>
                        </div>
                    </div>
                </fieldset>

            </div>
            <div class="ax-modal-footer" style="display:flex;align-items:center;justify-content:flex-end;gap:8px;padding:12px 24px;border-top:1px solid #e0e0e0;">
                <button class="ax-btn ax-btn-secondary" id="ax-editor-close-btn">Cancel</button>
                <button class="ax-btn ax-btn-primary" id="ax-editor-save">Save Manifest</button>
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
