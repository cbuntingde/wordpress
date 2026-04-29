<?php
/**
 * Axiom Plugin Security — Core Orchestrator
 *
 * WordPress core-level plugin security system. Monitors and restricts
 * plugin access to database, filesystem, network, hooks, and resources.
 * Manifests define permitted capabilities per plugin.
 *
 * Modes:
 *   - disabled:   System inactive, zero overhead.
 *   - learning:   Auto-generates manifests from observed behavior.
 *   - audit:      Checks manifests, logs violations, does not block.
 *   - enforce:    Checks manifests, blocks violations, full isolation.
 *
 * @since 6.7.0
 * @package WordPress
 * @subpackage Security
 */

#[AllowDynamicProperties]
final class Axiom_Plugin_Security {

	private static ?Axiom_Plugin_Security $instance = null;
	private bool $bootstrapped = false;

	/** @var array<string, Axiom_Manifest> */
	private array $plugin_manifests = array();

	/** @var array<string, string> */
	private array $plugin_files = array();

	/** @var array<string, bool> */
	private array $active_isolates = array();

	/** @var array<string, int> */
	private array $isolate_depth = array();

	private ?string $current_plugin = null;
	private array $plugin_stack = array();

	private ?int $tick_start = null;
	private bool $ticks_registered = false;
	private int $monitoring_start = 0;

	/**
	 * Guards
	 */
	private ?Axiom_Database_Guard $database_guard = null;
	private ?Axiom_Resource_Guard $resource_guard = null;

	/*
	 * ─── Singleton ─────────────────────────────────────────────────
	 */

	public static function instance(): self {
		if ( self::$instance === null ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/*
	 * ─── Mode / Config ─────────────────────────────────────────────
	 */

	public static function is_enabled(): bool {
		return self::mode() !== 'disabled';
	}

	public static function mode(): string {
		if ( function_exists( 'get_option' ) ) {
			$mode = get_option( 'axiom_security_mode', 'learning' );
		} else {
			$mode = 'learning';
		}
		$allowed = array( 'disabled', 'learning', 'audit', 'enforce' );
		if ( ! in_array( $mode, $allowed, true ) ) {
			$mode = 'learning';
		}
		return $mode;
	}

	public static function mode_constant_defined(): bool {
		return defined( 'AXIOM_SECURITY_MODE' )
			&& in_array( AXIOM_SECURITY_MODE, array( 'disabled', 'learning', 'audit', 'enforce' ), true );
	}

	public static function is_learning(): bool {
		return self::mode() === 'learning';
	}

	public static function is_enforce(): bool {
		return self::mode() === 'enforce';
	}

	public static function is_audit(): bool {
		return self::mode() === 'audit';
	}

	/**
	 * Initialize constants and static state.
	 * Called early from wp-settings.php.
	 */
	public static function init(): void {
		if ( ! defined( 'AXIOM_SECURITY_DB_VERSION' ) ) {
			define( 'AXIOM_SECURITY_DB_VERSION', '1.0.0' );
		}

		if ( function_exists( 'get_option' ) ) {
			if ( defined( 'AXIOM_SECURITY_MODE' ) ) {
				$mode = AXIOM_SECURITY_MODE;
				$allowed = array( 'disabled', 'learning', 'audit', 'enforce' );
				if ( in_array( $mode, $allowed, true ) && get_option( 'axiom_security_mode', null ) === null ) {
					update_option( 'axiom_security_mode', $mode, true );
				}
			} elseif ( get_option( 'axiom_security_mode', null ) === null ) {
				update_option( 'axiom_security_mode', 'learning', true );
			}
		}

		if ( defined( 'AXIOM_SECURITY_TRUSTED' ) && is_string( AXIOM_SECURITY_TRUSTED ) ) {
			$trusted = array_map( 'trim', explode( ',', AXIOM_SECURITY_TRUSTED ) );
			Axiom_Manifest_Validator::instance()->set_trusted_plugins( $trusted );
		}
	}

	/**
	 * Bootstrap subsystems. Called after wpdb is ready but before plugins load.
	 */
	public function bootstrap(): void {
		if ( $this->bootstrapped ) {
			return;
		}

		if ( self::is_learning() ) {
			Axiom_Profiler::instance();
		}

		$this->database_guard = new Axiom_Database_Guard();
		$this->resource_guard = new Axiom_Resource_Guard();
		$this->resource_guard->register();

		if ( self::is_enforce() ) {
			$this->database_guard->install();
		}

		if ( function_exists( 'is_admin' ) && is_admin() ) {
			$this->register_admin_hooks();
		}

		$this->bootstrapped = true;

		Axiom_Audit_Logger::instance()->log(
			Axiom_Audit_Logger::INFO,
			'system_start',
			'Axiom Plugin Security initialized',
			array(
				'mode'    => self::mode(),
				'version' => AXIOM_SECURITY_DB_VERSION,
			)
		);
	}

	/*
	 * ─── Plugin Registration ──────────────────────────────────────
	 */

	public function register_plugin( string $slug, string $file ): void {
		$this->plugin_files[ $slug ] = $file;

		$manifest = Axiom_Manifest_Validator::instance()->load_manifest( $slug );
		$name     = $this->plugin_name( $file );

		if ( $manifest === null ) {
			if ( self::is_learning() ) {
				$manifest = Axiom_Manifest::default_manifest( $slug, $name );
				Axiom_Manifest_Validator::instance()->save_manifest( $slug, $manifest );
				Axiom_Audit_Logger::instance()->log(
					Axiom_Audit_Logger::INFO,
					'manifest_created',
					"Default manifest created for '{$name}' ({$slug}) in learning mode",
					array( 'plugin' => $slug ),
					$slug
				);
			} else {
				Axiom_Audit_Logger::instance()->log(
					Axiom_Audit_Logger::WARNING,
					'plugin_unprotected',
					"Plugin '{$name}' ({$slug}) loaded without a security manifest",
					array( 'plugin' => $slug, 'mode' => self::mode() ),
					$slug
				);
			}
		} else {
			$profile = $manifest->profile();
			Axiom_Audit_Logger::instance()->log(
				Axiom_Audit_Logger::INFO,
				'plugin_loaded',
				"Plugin '{$name}' ({$slug}) loaded with {$profile} manifest",
				array( 'plugin' => $slug, 'profile' => $profile ),
				$slug
			);
		}

		if ( $manifest !== null ) {
			$this->plugin_manifests[ $slug ] = $manifest;
		}
	}

	public function get_plugin_manifest( string $slug ): ?Axiom_Manifest {
		return $this->plugin_manifests[ $slug ] ?? null;
	}

	public function get_plugin_file( string $slug ): ?string {
		return $this->plugin_files[ $slug ] ?? null;
	}

	public function get_all_registered_plugins(): array {
		return array_keys( $this->plugin_files );
	}

	/**
	 * Store the currently-loading plugin slug for WP_Hook attribution.
	 */
	public function set_current_plugin( ?string $slug ): void {
		$this->current_plugin = $slug;
	}

	public function get_current_plugin(): ?string {
		return $this->current_plugin;
	}

	/*
	 * ─── Isolate (Context Switching) ───────────────────────────────
	 */

	public function enter_isolate( string $plugin_slug, string $hook_name = '' ): void {
		$depth = $this->isolate_depth[ $plugin_slug ] ?? 0;
		if ( $depth === 0 && ! isset( $this->plugin_manifests[ $plugin_slug ] ) && ( self::is_audit() || self::is_enforce() ) ) {
			Axiom_Audit_Logger::instance()->log(
				Axiom_Audit_Logger::SECURITY,
				'unprotected_callback',
				"Unprotected plugin '{$plugin_slug}' executed hook '{$hook_name}' — no manifest",
				array( 'plugin' => $plugin_slug, 'hook' => $hook_name ),
				$plugin_slug
			);
		}

		$this->isolate_depth[ $plugin_slug ] = $depth + 1;

		if ( $depth === 0 ) {
			$this->active_isolates[ $plugin_slug ] = true;
		}

		array_push( $this->plugin_stack, $plugin_slug );
	}

	public function leave_isolate( string $plugin_slug ): void {
		$depth = $this->isolate_depth[ $plugin_slug ] ?? 0;
		if ( $depth <= 1 ) {
			unset( $this->active_isolates[ $plugin_slug ] );
			unset( $this->isolate_depth[ $plugin_slug ] );
		} else {
			$this->isolate_depth[ $plugin_slug ] = $depth - 1;
		}

		array_pop( $this->plugin_stack );
	}

	public function is_in_isolate( string $plugin_slug ): bool {
		return isset( $this->active_isolates[ $plugin_slug ] );
	}

	public function current_isolate(): ?string {
		$last = end( $this->plugin_stack );
		return $last !== false ? $last : null;
	}

	/*
	 * ─── Admin Integration ─────────────────────────────────────────
	 */

	public function register_admin_hooks(): void {
		add_action( 'admin_menu', array( $this, 'add_admin_submenu' ), 20 );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
		add_filter( 'manage_plugins_columns', array( $this, 'add_isolation_column' ) );
		add_action( 'manage_plugins_custom_column', array( $this, 'render_isolation_column' ), 10, 3 );
		add_action( 'wp_dashboard_setup', array( $this, 'add_dashboard_widget' ) );
	}

	public function add_admin_submenu(): void {
		$hook = add_submenu_page(
			'plugins.php',
			__( 'Plugin Security', 'default' ),
			__( 'Plugin Security', 'default' ),
			'manage_options',
			'axiom-security',
			array( $this, 'render_admin_page' )
		);

		add_action( "load-{$hook}", array( $this, 'handle_admin_actions' ) );
	}

	public function enqueue_admin_assets( string $hook ): void {
		if ( ! str_contains( $hook, 'axiom-security' ) && $hook !== 'plugins.php' && $hook !== 'index.php' ) {
			return;
		}

		$css = "
<style>
/* Minimal custom styles for patterns WP admin has no native class for */

.ax-stat-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    margin-bottom: 20px;
}
.ax-stat-grid .card {
    max-width: none;
    flex: 1;
    min-width: 180px;
}
.ax-stat-value {
    font-size: 26px;
    font-weight: 700;
    color: #1d2327;
    line-height: 1.2;
}

.ax-isolation-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 10px 3px 6px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 500;
    line-height: 18px;
    white-space: nowrap;
    border: 1px solid transparent;
}
.ax-isolation-badge svg { flex-shrink: 0; }
.ax-isolation-badge-protected { background: #edfaef; color: #014010; border-color: #b8e6bf; }
.ax-isolation-badge-learning { background: #fcf9e8; color: #3d2502; border-color: #f0dbb4; }
.ax-isolation-badge-unprotected { background: #f6f7f7; color: #646970; border-color: #dcdcde; }
.ax-isolation-badge-disabled { background: #f0f0f1; color: #a7aaad; border-color: #dcdcde; }
.ax-isolation-badge .ax-label { font-weight: 600; }
.ax-isolation-badge .ax-sub { font-weight: 400; opacity: 0.75; }

.ax-profile-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(210px, 1fr));
    gap: 8px;
    margin: 8px 0;
}
.ax-profile-card {
    background: #fff;
    border: 2px solid #dcdcde;
    border-radius: 4px;
    padding: 16px;
    cursor: pointer;
    transition: all 150ms ease;
}
.ax-profile-card:hover { border-color: #2271b1; box-shadow: 0 2px 8px rgba(34,113,177,0.12); }
.ax-profile-card.selected { border-color: #2271b1; background: #f0f6fc; }
.ax-profile-card h3 { margin: 0 0 2px; font-size: 14px; font-weight: 600; }
.ax-profile-card p { margin: 0; font-size: 12px; color: #646970; line-height: 1.4; }

.ax-custom-fields { display: none; margin-top: 8px; padding: 16px; background: #f6f7f7; border: 1px solid #dcdcde; border-radius: 4px; }
.ax-custom-fields.visible { display: block; }

.ax-edit-row > td { padding: 0 !important; background: transparent !important; }
.ax-edit-inner { padding: 16px 24px; background: #f6f7f7; border-top: 2px solid #72aee6; }

.ax-filter-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 16px;
    flex-wrap: wrap;
}
.ax-filter-bar .ax-label { font-size: 12px; font-weight: 600; color: #646970; }
.ax-filter-bar .ax-spacer { flex: 1; }
</style>";
		echo $css;
	}

	/*
	 * ─── Plugins List Column ───────────────────────────────────────
	 */

	public function add_isolation_column( array $columns ): array {
		$new = array();
		foreach ( $columns as $key => $label ) {
			$new[ $key ] = $label;
			if ( $key === 'auto-updates' ) {
				$new['axiom_isolation'] = __( 'Isolation', 'default' );
			}
		}
		return $new;
	}

	public function render_isolation_column( string $column_name, string $plugin_file ): void {
		if ( $column_name !== 'axiom_isolation' ) {
			return;
		}

		$slug = dirname( $plugin_file );
		if ( $slug === '.' || $slug === '' ) {
			$slug = basename( $plugin_file, '.php' );
		}

		if ( ! self::is_enabled() ) {
			$this->render_isolation_badge( 'disabled', '&#x2716;', 'Security Off' );
			return;
		}

		if ( isset( $this->plugin_manifests[ $slug ] ) ) {
			$manifest = $this->plugin_manifests[ $slug ];
			$profile  = $manifest->profile();
			$profile_label = ucfirst( $profile );
			$this->render_isolation_badge( 'protected', '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>', $profile_label, 'Active' );
			return;
		}

		if ( self::is_learning() ) {
			$this->render_isolation_badge( 'learning', '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>', 'Learning', 'Auto-configuring' );
			return;
		}

		$this->render_isolation_badge( 'unprotected', '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>', 'Unprotected', 'No manifest' );
	}

	private function render_isolation_badge( string $type, string $icon, string $label, string $sub = '' ): void {
		echo '<span class="ax-isolation-badge ax-isolation-badge-' . esc_attr( $type ) . '">';
		echo $icon; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<span class="ax-label">' . esc_html( $label ) . '</span>';
		if ( $sub ) {
			echo ' <span class="ax-sub">' . esc_html( $sub ) . '</span>';
		}
		echo '</span>';
	}

	/*
	 * ─── Dashboard Widget ──────────────────────────────────────────
	 */

	public function add_dashboard_widget(): void {
		wp_add_dashboard_widget(
			'axiom_security_dashboard',
			__( 'Plugin Security Overview', 'default' ),
			array( $this, 'render_dashboard_widget' )
		);
	}

	public function render_dashboard_widget(): void {
		$mode      = self::mode();
		$total     = count( $this->plugin_files );
		$protected = count( $this->plugin_manifests );
		$audit     = Axiom_Audit_Logger::instance();
		$events    = $audit->count( array( 'level' => Axiom_Audit_Logger::SECURITY ) );

		echo '<div style="padding:4px 0;">';
		echo '<div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #dcdcde;"><strong>' . __( 'Mode', 'default' ) . '</strong> <span>' . esc_html( ucfirst( $mode ) ) . '</span></div>';
		echo '<div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #dcdcde;"><strong>' . __( 'Active Plugins', 'default' ) . '</strong> <span>' . esc_html( (string) $total ) . '</span></div>';
		echo '<div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #dcdcde;"><strong>' . __( 'Protected', 'default' ) . '</strong> <span>' . esc_html( (string) $protected ) . '</span></div>';
		echo '<div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #dcdcde;"><strong>' . __( 'Security Events', 'default' ) . '</strong> <span>' . esc_html( (string) $events ) . '</span></div>';
		echo '<p style="margin:12px 0 0;"><a href="' . esc_url( admin_url( 'plugins.php?page=axiom-security' ) ) . '" class="button">' . __( 'Manage Plugin Security', 'default' ) . '</a></p>';
		echo '</div>';
	}

	/*
	 * ─── Admin Page ────────────────────────────────────────────────
	 */

	public function handle_admin_actions(): void {
		if ( isset( $_POST['axiom_save_mode'] ) && check_admin_referer( 'axiom-save-mode' ) ) {
			$mode = sanitize_text_field( wp_unslash( $_POST['axiom_security_mode'] ?? '' ) );
			$allowed = array( 'disabled', 'learning', 'audit', 'enforce' );
			if ( in_array( $mode, $allowed, true ) ) {
				update_option( 'axiom_security_mode', $mode );
				$redirect = add_query_arg( 'axiom_updated', '1', wp_get_referer() );
				wp_safe_redirect( $redirect );
				exit;
			}
		}

		if ( isset( $_POST['axiom_save_manifest'] ) && check_admin_referer( 'axiom-save-manifest' ) ) {
			$slug  = sanitize_text_field( wp_unslash( $_POST['axiom_plugin_slug'] ?? '' ) );
			$json  = wp_unslash( $_POST['axiom_manifest_json'] ?? '' );
			$data  = json_decode( $json, true );
			if ( $slug && is_array( $data ) && isset( $data['id'] ) ) {
				$manifest = new Axiom_Manifest( $data );
				Axiom_Manifest_Validator::instance()->save_manifest( $slug, $manifest );
				$this->plugin_manifests[ $slug ] = $manifest;
				$redirect = add_query_arg( 'axiom_updated', '2', wp_get_referer() );
				wp_safe_redirect( $redirect );
				exit;
			}
		}

		if ( isset( $_POST['axiom_generate_manifest'] ) && check_admin_referer( 'axiom-generate-manifest' ) ) {
			$slug    = sanitize_text_field( wp_unslash( $_POST['axiom_plugin_slug'] ?? '' ) );
			$profile = sanitize_text_field( wp_unslash( $_POST['axiom_profile'] ?? Axiom_Manifest::PROFILE_STANDARD ) );
			if ( $slug ) {
				$file     = $this->plugin_files[ $slug ] ?? WP_PLUGIN_DIR . '/' . $slug;
				$name     = $this->plugin_name( $file );
				$manifest = null;

				if ( $profile === Axiom_Manifest::PROFILE_CUSTOM || ! Axiom_Profiler::instance()->has_data( $slug ) ) {
					$manifest = Axiom_Manifest::from_profile( $profile, $slug, $name );
				}

				if ( $manifest === null && Axiom_Profiler::instance()->has_data( $slug ) ) {
					$manifest = Axiom_Profiler::instance()->generate_manifest( $slug, $name );
				}

				if ( $manifest === null ) {
					$manifest = Axiom_Manifest::from_profile( $profile, $slug, $name );
				}
				if ( $manifest ) {
					Axiom_Manifest_Validator::instance()->save_manifest( $slug, $manifest );
					$this->plugin_manifests[ $slug ] = $manifest;
				}
				$redirect = add_query_arg( 'axiom_updated', '3', wp_get_referer() );
				wp_safe_redirect( $redirect );
				exit;
			}
		}

		if ( isset( $_POST['axiom_delete_manifest'] ) && check_admin_referer( 'axiom-delete-manifest' ) ) {
			$slug = sanitize_text_field( wp_unslash( $_POST['axiom_plugin_slug'] ?? '' ) );
			if ( $slug ) {
				Axiom_Manifest_Validator::instance()->delete_manifest( $slug );
				unset( $this->plugin_manifests[ $slug ] );
				$redirect = add_query_arg( 'axiom_updated', '4', wp_get_referer() );
				wp_safe_redirect( $redirect );
				exit;
			}
		}

		if ( isset( $_POST['axiom_clear_audit'] ) && check_admin_referer( 'axiom-clear-audit' ) ) {
			Axiom_Audit_Logger::instance()->purge();
			$redirect = add_query_arg( 'axiom_updated', '5', wp_get_referer() );
			wp_safe_redirect( $redirect );
			exit;
		}
	}

	public function render_admin_page(): void {
		$tab = sanitize_key( $_GET['tab'] ?? 'dashboard' );

		if ( isset( $_GET['axiom_updated'] ) ) {
			$msg = array(
				'1' => __( 'Security mode updated.', 'default' ),
				'2' => __( 'Manifest saved.', 'default' ),
				'3' => __( 'Manifest generated.', 'default' ),
				'4' => __( 'Manifest deleted.', 'default' ),
				'5' => __( 'Audit log cleared.', 'default' ),
			);
			$code = sanitize_text_field( wp_unslash( $_GET['axiom_updated'] ) );
			if ( isset( $msg[ $code ] ) ) {
				echo '<div class="notice notice-success is-dismissible"><p>' . esc_html( $msg[ $code ] ) . '</p></div>';
			}
		}

		?>
		<div class="wrap">

		<h1><?php esc_html_e( 'Plugin Security', 'default' ); ?></h1>

		<nav class="nav-tab-wrapper wp-clearfix" aria-label="<?php esc_attr_e( 'Plugin Security sections', 'default' ); ?>">
			<a href="<?php echo esc_url( add_query_arg( 'tab', 'dashboard', remove_query_arg( 'axiom_updated' ) ) ); ?>" class="nav-tab <?php echo $tab === 'dashboard' ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Dashboard', 'default' ); ?></a>
			<a href="<?php echo esc_url( add_query_arg( 'tab', 'plugins', remove_query_arg( 'axiom_updated' ) ) ); ?>" class="nav-tab <?php echo $tab === 'plugins' ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Plugins', 'default' ); ?></a>
			<a href="<?php echo esc_url( add_query_arg( 'tab', 'settings', remove_query_arg( 'axiom_updated' ) ) ); ?>" class="nav-tab <?php echo $tab === 'settings' ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Settings', 'default' ); ?></a>
			<a href="<?php echo esc_url( add_query_arg( 'tab', 'audit', remove_query_arg( 'axiom_updated' ) ) ); ?>" class="nav-tab <?php echo $tab === 'audit' ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Audit Log', 'default' ); ?></a>
		</nav>

		<?php
		switch ( $tab ) {
			case 'plugins':
				$this->render_plugins_tab();
				break;
			case 'settings':
				$this->render_settings_tab();
				break;
			case 'audit':
				$this->render_audit_tab();
				break;
			default:
				$this->render_dashboard_tab();
				break;
		}
		echo '</div>';
	}

	private function render_dashboard_tab(): void {
		$mode      = self::mode();
		$total     = count( $this->plugin_files );
		$protected = count( $this->plugin_manifests );
		$audit     = Axiom_Audit_Logger::instance();
		$events    = $audit->count();
		$sec_events = $audit->count( array( 'level' => Axiom_Audit_Logger::SECURITY ) );
		?>
		<div class="ax-stat-grid">
			<div class="card">
				<p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:#646970;margin:0 0 4px;"><?php esc_html_e( 'Security Mode', 'default' ); ?></p>
				<div class="ax-stat-value"><?php echo esc_html( ucfirst( $mode ) ); ?></div>
				<p style="font-size:13px;color:#646970;margin:4px 0 0;"><?php echo $mode === 'enforce' ? esc_html__( 'Full enforcement active', 'default' ) : esc_html__( 'Controls how plugin security is enforced', 'default' ); ?></p>
			</div>
			<div class="card">
				<p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:#646970;margin:0 0 4px;"><?php esc_html_e( 'Protected', 'default' ); ?></p>
				<div class="ax-stat-value"><?php echo esc_html( "{$protected} / {$total}" ); ?></div>
				<p style="font-size:13px;color:#646970;margin:4px 0 0;"><?php echo $protected > 0 ? esc_html( sprintf( __( '%d plugins have security manifests', 'default' ), $protected ) ) : esc_html__( 'No plugins have manifests yet', 'default' ); ?></p>
			</div>
			<div class="card">
				<p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:#646970;margin:0 0 4px;"><?php esc_html_e( 'Total Events', 'default' ); ?></p>
				<div class="ax-stat-value"><?php echo esc_html( (string) $events ); ?></div>
				<p style="font-size:13px;color:#646970;margin:4px 0 0;"><?php echo $sec_events > 0 ? esc_html( sprintf( __( '%d security events', 'default' ), $sec_events ) ) : esc_html__( 'All events logged', 'default' ); ?></p>
			</div>
		</div>
		<?php
		$this->render_quick_plugin_table();
	}

	private function render_quick_plugin_table(): void {
		$plugins = $this->plugin_files;
		if ( empty( $plugins ) ) {
			return;
		}
		?>
		<div class="card" style="max-width:none;">
			<h2 class="title"><?php esc_html_e( 'Plugin Status', 'default' ); ?></h2>
			<div style="margin:0 -2em -1em;">
				<table class="wp-list-table widefat fixed striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Plugin', 'default' ); ?></th>
							<th><?php esc_html_e( 'Status', 'default' ); ?></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $plugins as $slug => $file ) : ?>
						<tr>
							<td><strong><?php echo esc_html( $this->plugin_name( $file ) ?: $slug ); ?></strong></td>
							<td>
							<?php if ( isset( $this->plugin_manifests[ $slug ] ) ) : ?>
								<span class="ax-isolation-badge ax-isolation-badge-protected"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> <?php esc_html_e( 'Protected', 'default' ); ?></span>
							<?php elseif ( self::is_learning() ) : ?>
								<span class="ax-isolation-badge ax-isolation-badge-learning"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg> <?php esc_html_e( 'Learning', 'default' ); ?></span>
							<?php else : ?>
								<span class="ax-isolation-badge ax-isolation-badge-unprotected"><?php esc_html_e( 'Unprotected', 'default' ); ?></span>
							<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	private function render_plugins_tab(): void {
		$plugins = $this->plugin_files;
		?>
		<h2 style="margin-top:20px;"><?php esc_html_e( 'Plugin Manifests', 'default' ); ?></h2>
		<p><?php esc_html_e( 'Each active plugin has a security manifest defining its permitted capabilities.', 'default' ); ?></p>
		<table class="wp-list-table widefat fixed striped" style="margin-top:10px;">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Plugin', 'default' ); ?></th>
					<th><?php esc_html_e( 'Manifest', 'default' ); ?></th>
					<th style="text-align:right;"><?php esc_html_e( 'Actions', 'default' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $plugins as $slug => $file ) : ?>
				<?php
				$manifest = $this->plugin_manifests[ $slug ] ?? Axiom_Manifest_Validator::instance()->load_manifest( $slug );
				$has_manifest = $manifest !== null;
				$name = $this->plugin_name( $file ) ?: $slug;
				?>
				<tr>
					<td><strong><?php echo esc_html( $name ); ?></strong><br><code><?php echo esc_html( $slug ); ?></code></td>
					<td>
					<?php if ( $has_manifest ) : ?>
						<span class="ax-isolation-badge ax-isolation-badge-protected"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> <?php esc_html_e( 'Active', 'default' ); ?></span>
					<?php elseif ( self::is_learning() ) : ?>
						<span class="ax-isolation-badge ax-isolation-badge-learning"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg> <?php esc_html_e( 'Learning', 'default' ); ?></span>
					<?php else : ?>
						<span class="ax-isolation-badge ax-isolation-badge-unprotected"><?php esc_html_e( 'None', 'default' ); ?></span>
					<?php endif; ?>
					</td>
					<td style="text-align:right;white-space:nowrap;">
					<?php if ( $has_manifest ) : ?>
						<button type="button" class="button button-small" onclick="document.getElementById('ax-edit-<?php echo esc_attr( $slug ); ?>').style.display='table-row'">
							<?php esc_html_e( 'Edit', 'default' ); ?>
						</button>
						<form method="post" style="display:inline-flex;align-items:center;gap:4px;">
							<?php wp_nonce_field( 'axiom-generate-manifest' ); ?>
							<input type="hidden" name="axiom_generate_manifest" value="1" />
							<input type="hidden" name="axiom_plugin_slug" value="<?php echo esc_attr( $slug ); ?>" />
							<select name="axiom_profile" style="min-width:90px;font-size:12px;height:26px;">
								<option value="<?php echo esc_attr( Axiom_Manifest::PROFILE_STANDARD ); ?>"><?php esc_html_e( 'Standard', 'default' ); ?></option>
								<option value="<?php echo esc_attr( Axiom_Manifest::PROFILE_RESTRICTED ); ?>"><?php esc_html_e( 'Restricted', 'default' ); ?></option>
								<option value="<?php echo esc_attr( Axiom_Manifest::PROFILE_PERMISSIVE ); ?>"><?php esc_html_e( 'Permissive', 'default' ); ?></option>
							</select>
							<button type="submit" class="button button-small"><?php esc_html_e( 'Regen', 'default' ); ?></button>
						</form>
						<form method="post" style="display:inline-flex;align-items:center;gap:4px;" onsubmit="return confirm('<?php echo esc_js( __( 'Delete this manifest?', 'default' ) ); ?>');">
							<?php wp_nonce_field( 'axiom-delete-manifest' ); ?>
							<input type="hidden" name="axiom_delete_manifest" value="1" />
							<input type="hidden" name="axiom_plugin_slug" value="<?php echo esc_attr( $slug ); ?>" />
							<button type="submit" class="button button-small" style="color:#d63638;border-color:#d63638;"><?php esc_html_e( 'Delete', 'default' ); ?></button>
						</form>
					<?php else : ?>
						<form method="post" style="display:inline-flex;align-items:center;gap:4px;">
							<?php wp_nonce_field( 'axiom-generate-manifest' ); ?>
							<input type="hidden" name="axiom_generate_manifest" value="1" />
							<input type="hidden" name="axiom_plugin_slug" value="<?php echo esc_attr( $slug ); ?>" />
							<select name="axiom_profile" style="min-width:90px;font-size:12px;height:26px;">
								<option value="<?php echo esc_attr( Axiom_Manifest::PROFILE_STANDARD ); ?>"><?php esc_html_e( 'Standard', 'default' ); ?></option>
								<option value="<?php echo esc_attr( Axiom_Manifest::PROFILE_RESTRICTED ); ?>"><?php esc_html_e( 'Restricted', 'default' ); ?></option>
								<option value="<?php echo esc_attr( Axiom_Manifest::PROFILE_PERMISSIVE ); ?>"><?php esc_html_e( 'Permissive', 'default' ); ?></option>
							</select>
							<button type="submit" class="button button-primary button-small"><?php esc_html_e( 'Generate', 'default' ); ?></button>
						</form>
					<?php endif; ?>
					</td>
				</tr>
				<?php if ( $has_manifest ) : ?>
				<tr id="ax-edit-<?php echo esc_attr( $slug ); ?>" class="ax-edit-row" style="display:none;">
					<td colspan="3">
						<div class="ax-edit-inner">
							<?php $this->render_manifest_form( $slug, $manifest ); ?>
						</div>
					</td>
				</tr>
				<?php endif; ?>
			<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	private function render_settings_tab(): void {
		$current  = self::mode();
		$constant_overridden = self::mode_constant_defined();
		?>
		<div class="card" style="max-width:640px;">
			<h2 class="title"><?php esc_html_e( 'Security Mode', 'default' ); ?></h2>
			<?php if ( $constant_overridden ) : ?>
				<div class="notice notice-info inline" style="margin:0 0 16px;">
					<p><?php echo esc_html( sprintf( __( 'Mode locked by wp-config.php constant (AXIOM_SECURITY_MODE = %s). Remove the constant to enable UI control.', 'default' ), AXIOM_SECURITY_MODE ) ); ?></p>
				</div>
			<?php endif; ?>
			<form method="post">
				<?php wp_nonce_field( 'axiom-save-mode' ); ?>
				<label for="axiom_security_mode" style="display:block;font-weight:500;margin-bottom:6px;"><?php esc_html_e( 'Choose the security mode for all plugins:', 'default' ); ?></label>
				<select name="axiom_security_mode" id="axiom_security_mode" style="min-width:200px;" <?php disabled( $constant_overridden ); ?>>
					<option value="learning" <?php selected( $current, 'learning' ); ?>><?php esc_html_e( 'Learning — Auto-configure manifests', 'default' ); ?></option>
					<option value="audit" <?php selected( $current, 'audit' ); ?>><?php esc_html_e( 'Audit — Log violations, no blocking', 'default' ); ?></option>
					<option value="enforce" <?php selected( $current, 'enforce' ); ?>><?php esc_html_e( 'Enforce — Block violations', 'default' ); ?></option>
					<option value="disabled" <?php selected( $current, 'disabled' ); ?>><?php esc_html_e( 'Disabled — Turn off', 'default' ); ?></option>
				</select>
				<div style="margin-top:16px;font-size:13px;color:#646970;line-height:1.6;">
					<strong style="color:#1d2327;"><?php esc_html_e( 'Learning', 'default' ); ?></strong> &mdash; <?php esc_html_e( 'Auto-generates manifests as plugins run. Best for onboarding.', 'default' ); ?><br>
					<strong style="color:#1d2327;"><?php esc_html_e( 'Audit', 'default' ); ?></strong> &mdash; <?php esc_html_e( 'Checks manifests and logs violations without blocking. Safe for staging.', 'default' ); ?><br>
					<strong style="color:#1d2327;"><?php esc_html_e( 'Enforce', 'default' ); ?></strong> &mdash; <?php esc_html_e( 'Full enforcement — violations are blocked and logged. Recommended for production.', 'default' ); ?><br>
					<strong style="color:#1d2327;"><?php esc_html_e( 'Disabled', 'default' ); ?></strong> &mdash; <?php esc_html_e( 'System off. No monitoring or enforcement.', 'default' ); ?>
				</div>
				<div style="margin-top:16px;">
					<button type="submit" name="axiom_save_mode" class="button button-primary"><?php esc_html_e( 'Save Settings', 'default' ); ?></button>
				</div>
			</form>
		</div>
		<?php
	}

	private function render_audit_tab(): void {
		$audit    = Axiom_Audit_Logger::instance();
		$filter   = sanitize_key( $_GET['ax_level'] ?? '' );
		$query    = array( 'limit' => 200 );
		$level_labels = array(
			''             => __( 'All Levels', 'default' ),
			'security'     => __( 'Security', 'default' ),
			'error'        => __( 'Error', 'default' ),
			'warning'      => __( 'Warning', 'default' ),
			'learning'     => __( 'Learning', 'default' ),
			'info'         => __( 'Info', 'default' ),
		);
		if ( $filter !== '' && isset( $level_labels[ $filter ] ) ) {
			$query['level'] = $filter;
		}
		$events = $audit->query( $query );
		$total_opts = array();
		if ( $filter !== '' ) {
			$total_opts['level'] = $filter;
		}
		$total = $audit->count( $total_opts );
		?>
		<h2 style="margin-top:20px;"><?php esc_html_e( 'Audit Log', 'default' ); ?></h2>
		<p><?php esc_html_e( 'Security events recorded by the plugin security system.', 'default' ); ?></p>

		<div class="ax-filter-bar">
			<form method="get" style="display:flex;align-items:center;gap:8px;">
				<input type="hidden" name="page" value="axiom-security" />
				<input type="hidden" name="tab" value="audit" />
				<span class="ax-label"><?php esc_html_e( 'Level:', 'default' ); ?></span>
				<select name="ax_level" onchange="this.form.submit()">
				<?php foreach ( $level_labels as $val => $label ) : ?>
					<option value="<?php echo esc_attr( $val ); ?>" <?php selected( $filter, $val ); ?>><?php echo esc_html( $label ); ?></option>
				<?php endforeach; ?>
				</select>
				<noscript><button type="submit" class="button button-small"><?php esc_html_e( 'Filter', 'default' ); ?></button></noscript>
			</form>
			<span class="ax-label" style="margin-left:8px;"><?php echo esc_html( sprintf( __( '%d events', 'default' ), $total ) ); ?></span>
			<span class="ax-spacer"></span>
			<form method="post" style="display:inline;" onsubmit="return confirm('<?php echo esc_js( __( 'Clear all audit log entries? This cannot be undone.', 'default' ) ); ?>');">
				<?php wp_nonce_field( 'axiom-clear-audit' ); ?>
				<input type="hidden" name="axiom_clear_audit" value="1" />
				<button type="submit" class="button button-small" style="color:#d63638;border-color:#d63638;"><?php esc_html_e( 'Clear Log', 'default' ); ?></button>
			</form>
		</div>

		<?php if ( empty( $events ) ) : ?>
			<p><em><?php esc_html_e( 'No events recorded.', 'default' ); ?></em></p>
		<?php else : ?>
			<table class="wp-list-table widefat fixed striped" style="margin-top:10px;">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Time', 'default' ); ?></th>
						<th><?php esc_html_e( 'Level', 'default' ); ?></th>
						<th><?php esc_html_e( 'Plugin', 'default' ); ?></th>
						<th><?php esc_html_e( 'Event', 'default' ); ?></th>
						<th><?php esc_html_e( 'Context', 'default' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $events as $e ) : ?>
					<tr>
						<td style="white-space:nowrap;"><?php echo esc_html( $e['event_time'] ); ?></td>
						<td style="color:<?php echo $e['level'] === 'security' || $e['level'] === 'error' ? '#d63638' : ( $e['level'] === 'warning' ? '#d97706' : ( $e['level'] === 'learning' ? '#2271b1' : '#646970' ) ); ?>;font-weight:<?php echo $e['level'] === 'security' ? '700' : '400'; ?>;"><?php echo esc_html( $e['level'] ); ?></td>
						<td><code><?php echo esc_html( $e['plugin_slug'] ?? '&mdash;' ); ?></code></td>
						<td><?php echo esc_html( $e['event_type'] ); ?><br><small style="color:#646970;"><?php echo esc_html( $e['message'] ); ?></small></td>
						<td style="font-size:12px;color:#646970;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><?php echo esc_html( $e['context'] ?? '' ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
		<?php
	}

	/*
	 * ─── Helpers ───────────────────────────────────────────────────
	 */

	private function render_manifest_form( string $slug, Axiom_Manifest $manifest ): void {
		$data     = $manifest->to_array();
		$perms    = $data['permissions'] ?? array();
		$limits   = $data['resource_limits'] ?? array();
		$db       = $perms['db'] ?? array();
		$hook_list = $perms['wp']['hooks'] ?? array();
		$opt      = $perms['wp']['options'] ?? array();
		$users    = $perms['wp']['users'] ?? array();
		$system   = $perms['system'] ?? array();
		$current_profile = $manifest->profile();
		?>
		<div class="ax-manifest-editor">
			<h3 style="margin:0 0 2px 0;"><?php echo esc_html( sprintf( __( 'Security Profile: %s', 'default' ), $manifest->name() ) ); ?></h3>
			<p style="margin:0 0 4px 0; font-size:12px; color:#6b7280;"><?php esc_html_e( 'Choose a security profile. Standard works for most plugins.', 'default' ); ?></p>

			<form method="post">
				<?php wp_nonce_field( 'axiom-save-manifest' ); ?>
				<input type="hidden" name="axiom_save_manifest" value="1" />
				<input type="hidden" name="axiom_plugin_slug" value="<?php echo esc_attr( $slug ); ?>" />
				<input type="hidden" name="axiom_manifest_json" id="ax-json-<?php echo esc_attr( $slug ); ?>" value="" />

				<div class="ax-profile-grid" id="ax-profile-grid-<?php echo esc_attr( $slug ); ?>">

					<div class="ax-profile-card <?php echo $current_profile === Axiom_Manifest::PROFILE_STANDARD ? 'selected' : ''; ?>" data-profile="<?php echo esc_attr( Axiom_Manifest::PROFILE_STANDARD ); ?>" onclick="selectProfile('<?php echo esc_js( $slug ); ?>', '<?php echo esc_js( Axiom_Manifest::PROFILE_STANDARD ); ?>')">
						<div class="ax-icon">&#x1f6e1;</div>
						<h3><?php esc_html_e( 'Standard', 'default' ); ?></h3>
						<p><?php esc_html_e( 'Balanced protection for most plugins.', 'default' ); ?></p>
						<div class="ax-badge-rec"><?php esc_html_e( 'Recommended', 'default' ); ?></div>
						<div class="ax-cap-summary">
							<?php esc_html_e( 'Read all tables, write options &amp; meta, common hooks, no exec.', 'default' ); ?>
						</div>
					</div>

					<div class="ax-profile-card <?php echo $current_profile === Axiom_Manifest::PROFILE_RESTRICTED ? 'selected' : ''; ?>" data-profile="<?php echo esc_attr( Axiom_Manifest::PROFILE_RESTRICTED ); ?>" onclick="selectProfile('<?php echo esc_js( $slug ); ?>', '<?php echo esc_js( Axiom_Manifest::PROFILE_RESTRICTED ); ?>')">
						<div class="ax-icon">&#x1f512;</div>
						<h3><?php esc_html_e( 'Restricted', 'default' ); ?></h3>
						<p><?php esc_html_e( 'Minimal access for unknown plugins.', 'default' ); ?></p>
						<div class="ax-cap-summary">
							<?php esc_html_e( 'Read-only to key tables, own options only, essential hooks only, tight resource limits.', 'default' ); ?>
						</div>
					</div>

					<div class="ax-profile-card <?php echo $current_profile === Axiom_Manifest::PROFILE_PERMISSIVE ? 'selected' : ''; ?>" data-profile="<?php echo esc_attr( Axiom_Manifest::PROFILE_PERMISSIVE ); ?>" onclick="selectProfile('<?php echo esc_js( $slug ); ?>', '<?php echo esc_js( Axiom_Manifest::PROFILE_PERMISSIVE ); ?>')">
						<div class="ax-icon">&#x1f310;</div>
						<h3><?php esc_html_e( 'Permissive', 'default' ); ?></h3>
						<p><?php esc_html_e( 'Broad access for trusted plugins.', 'default' ); ?></p>
						<div class="ax-cap-summary">
							<?php esc_html_e( 'Full table access, filesystem write, all hooks, all options, higher resource limits.', 'default' ); ?>
						</div>
					</div>

					<div class="ax-profile-card <?php echo $current_profile === Axiom_Manifest::PROFILE_CUSTOM ? 'selected' : ''; ?>" data-profile="<?php echo esc_attr( Axiom_Manifest::PROFILE_CUSTOM ); ?>" onclick="selectProfile('<?php echo esc_js( $slug ); ?>', '<?php echo esc_js( Axiom_Manifest::PROFILE_CUSTOM ); ?>')">
						<div class="ax-icon">&#x2699;&#xfe0f;</div>
						<h3><?php esc_html_e( 'Custom', 'default' ); ?></h3>
						<p><?php esc_html_e( 'Fine-tune every permission.', 'default' ); ?></p>
						<div class="ax-cap-summary">
							<?php esc_html_e( 'Manually configure all capabilities, file paths, and resource limits.', 'default' ); ?>
						</div>
					</div>
				</div>

				<div class="ax-custom-fields <?php echo $current_profile === Axiom_Manifest::PROFILE_CUSTOM ? 'visible' : ''; ?>" id="ax-custom-<?php echo esc_attr( $slug ); ?>">
					<h4><?php esc_html_e( 'Database', 'default' ); ?></h4>
					<table class="form-table">
						<tr><th scope="row"><?php esc_html_e( 'Read', 'default' ); ?></th><td><input type="text" id="ax-db-read-<?php echo esc_attr( $slug ); ?>" class="large-text" value="<?php echo esc_attr( implode( ', ', $db['read'] ?? array() ) ); ?>" placeholder="wp_*" /></td></tr>
						<tr><th scope="row"><?php esc_html_e( 'Write', 'default' ); ?></th><td><input type="text" id="ax-db-write-<?php echo esc_attr( $slug ); ?>" class="large-text" value="<?php echo esc_attr( implode( ', ', $db['write'] ?? array() ) ); ?>" placeholder="wp_options, wp_*" /></td></tr>
						<tr><th scope="row"><?php esc_html_e( 'Delete', 'default' ); ?></th><td><input type="text" id="ax-db-delete-<?php echo esc_attr( $slug ); ?>" class="large-text" value="<?php echo esc_attr( implode( ', ', $db['delete'] ?? array() ) ); ?>" placeholder="" /></td></tr>
						<tr><th scope="row"><?php esc_html_e( 'Alter (DDL)', 'default' ); ?></th><td><input type="text" id="ax-db-alter-<?php echo esc_attr( $slug ); ?>" class="large-text" value="<?php echo esc_attr( implode( ', ', $db['alter'] ?? array() ) ); ?>" placeholder="" /></td></tr>
					</table>

					<h4><?php esc_html_e( 'Filesystem', 'default' ); ?></h4>
					<table class="form-table">
						<tr><th scope="row"><?php esc_html_e( 'Paths', 'default' ); ?></th><td><input type="text" id="ax-fs-<?php echo esc_attr( $slug ); ?>" class="large-text" value="<?php echo esc_attr( implode( ', ', $perms['filesystem'] ?? array() ) ); ?>" placeholder="read:wp-content/uploads/*" /></td></tr>
					</table>

					<h4><?php esc_html_e( 'Network', 'default' ); ?></h4>
					<table class="form-table">
						<tr><th scope="row"><?php esc_html_e( 'Outbound Domains', 'default' ); ?></th><td><input type="text" id="ax-net-<?php echo esc_attr( $slug ); ?>" class="large-text" value="<?php echo esc_attr( implode( ', ', $perms['network']['outbound'] ?? array() ) ); ?>" placeholder="*.wordpress.org" /></td></tr>
					</table>

					<h4><?php esc_html_e( 'Hooks', 'default' ); ?></h4>
					<table class="form-table">
						<tr><th scope="row"><?php esc_html_e( 'Allowed Hooks', 'default' ); ?></th><td><input type="text" id="ax-hooks-<?php echo esc_attr( $slug ); ?>" class="large-text" value="<?php echo esc_attr( implode( ', ', $hook_list['write'] ?? array() ) ); ?>" placeholder="init, wp_ajax_*" /></td></tr>
					</table>

					<h4><?php esc_html_e( 'Options', 'default' ); ?></h4>
					<table class="form-table">
						<tr><th scope="row"><?php esc_html_e( 'Read', 'default' ); ?></th><td><input type="text" id="ax-opt-read-<?php echo esc_attr( $slug ); ?>" class="large-text" value="<?php echo esc_attr( implode( ', ', $opt['read'] ?? array() ) ); ?>" placeholder="*" /></td></tr>
						<tr><th scope="row"><?php esc_html_e( 'Write', 'default' ); ?></th><td><input type="text" id="ax-opt-write-<?php echo esc_attr( $slug ); ?>" class="large-text" value="<?php echo esc_attr( implode( ', ', $opt['write'] ?? array() ) ); ?>" placeholder="plugin_*" /></td></tr>
					</table>

					<h4><?php esc_html_e( 'Users', 'default' ); ?></h4>
					<table class="form-table">
						<tr><th scope="row"><?php esc_html_e( 'Readable Caps', 'default' ); ?></th><td><input type="text" id="ax-users-<?php echo esc_attr( $slug ); ?>" class="large-text" value="<?php echo esc_attr( implode( ', ', $users['read'] ?? array() ) ); ?>" placeholder="*" /></td></tr>
					</table>

					<h4><?php esc_html_e( 'System', 'default' ); ?></h4>
					<table class="form-table">
						<tr><th scope="row"><?php esc_html_e( 'Shell Exec', 'default' ); ?></th><td><label><input type="checkbox" id="ax-exec-<?php echo esc_attr( $slug ); ?>" value="1" <?php checked( in_array( 'exec', $system, true ) ); ?> /> <?php esc_html_e( 'Allow exec, shell_exec, system, passthru', 'default' ); ?></label></td></tr>
					</table>

					<h4><?php esc_html_e( 'Resource Limits', 'default' ); ?></h4>
					<table class="form-table">
						<tr><th scope="row"><?php esc_html_e( 'CPU (ms)', 'default' ); ?></th><td><input type="number" id="ax-cpu-<?php echo esc_attr( $slug ); ?>" class="small-text" value="<?php echo esc_attr( (string) ( $limits['cpu_ms'] ?? 5000 ) ); ?>" min="0" step="100" /></td></tr>
						<tr><th scope="row"><?php esc_html_e( 'Memory (MB)', 'default' ); ?></th><td><input type="number" id="ax-mem-<?php echo esc_attr( $slug ); ?>" class="small-text" value="<?php echo esc_attr( (string) ( $limits['memory_mb'] ?? 128 ) ); ?>" min="0" step="8" /></td></tr>
					</table>
				</div>

				<script>
				function selectProfile(slug, profile) {
					var cards = document.querySelectorAll('#ax-profile-grid-' + slug + ' .ax-profile-card');
					for (var i = 0; i < cards.length; i++) {
						cards[i].classList.toggle('selected', cards[i].dataset.profile === profile);
					}
					var custom = document.getElementById('ax-custom-' + slug);
					custom.classList.toggle('visible', profile === 'custom');

					buildManifestJson(slug, profile);
				}
				function buildManifestJson(slug, profile) {
					var nameEl = document.querySelector('#ax-edit-' + slug + ' h3');
					var name = nameEl ? nameEl.textContent.replace(/^[^:]+:\s*/, '') : slug;

					var data;
					if (profile === 'restricted') {
						data = <?php echo wp_json_encode( Axiom_Manifest::restricted_profile( '{{SLUG}}' )->to_array() ); ?>;
					} else if (profile === 'permissive') {
						data = <?php echo wp_json_encode( Axiom_Manifest::permissive_profile( '{{SLUG}}' )->to_array() ); ?>;
					} else if (profile === 'custom') {
						data = {
							id: slug,
							name: name,
							manifest_version: '1.0',
							profile: 'custom',
							permissions: {
								db: {
									read: (document.getElementById('ax-db-read-' + slug).value || '').split(',').map(function(s) { return s.trim(); }).filter(Boolean),
									write: (document.getElementById('ax-db-write-' + slug).value || '').split(',').map(function(s) { return s.trim(); }).filter(Boolean),
									delete: (document.getElementById('ax-db-delete-' + slug).value || '').split(',').map(function(s) { return s.trim(); }).filter(Boolean),
									alter: (document.getElementById('ax-db-alter-' + slug).value || '').split(',').map(function(s) { return s.trim(); }).filter(Boolean)
								},
								filesystem: (document.getElementById('ax-fs-' + slug).value || '').split(',').map(function(s) { return s.trim(); }).filter(Boolean),
								network: { outbound: (document.getElementById('ax-net-' + slug).value || '').split(',').map(function(s) { return s.trim(); }).filter(Boolean) },
								wp: {
									hooks: { read_only: ['*'], write: (document.getElementById('ax-hooks-' + slug).value || '').split(',').map(function(s) { return s.trim(); }).filter(Boolean) },
									options: {
										read: (document.getElementById('ax-opt-read-' + slug).value || '').split(',').map(function(s) { return s.trim(); }).filter(Boolean),
										write: (document.getElementById('ax-opt-write-' + slug).value || '').split(',').map(function(s) { return s.trim(); }).filter(Boolean)
									},
									users: { read: (document.getElementById('ax-users-' + slug).value || '').split(',').map(function(s) { return s.trim(); }).filter(Boolean) }
								},
								system: document.getElementById('ax-exec-' + slug) && document.getElementById('ax-exec-' + slug).checked ? ['exec'] : []
							},
							resource_limits: {
								cpu_ms: parseInt(document.getElementById('ax-cpu-' + slug).value) || 5000,
								memory_mb: parseInt(document.getElementById('ax-mem-' + slug).value) || 128
							}
						};
					} else {
						data = <?php echo wp_json_encode( Axiom_Manifest::standard_profile( '{{SLUG}}' )->to_array() ); ?>;
					}
					data.id = slug;
					data.name = name;
					data.profile = profile;
					document.getElementById('ax-json-' + slug).value = JSON.stringify(data);
				}
				</script>

				<p style="margin:8px 0 0 0;">
					<button type="submit" class="button button-primary"><?php esc_html_e( 'Save Manifest', 'default' ); ?></button>
					<button type="button" class="button" onclick="document.getElementById('ax-edit-<?php echo esc_attr( $slug ); ?>').style.display='none'"><?php esc_html_e( 'Cancel', 'default' ); ?></button>
				</p>
			</form>
		</div>
		<?php
	}

	private function plugin_name( string $file ): string {
		if ( ! file_exists( $file ) ) {
			return basename( $file, '.php' );
		}
		$data = get_plugin_data( $file, false, false );
		return $data['Name'] ?: basename( $file, '.php' );
	}
}

/*
 * ─── Database Guard ────────────────────────────────────────────────
 */

#[AllowDynamicProperties]
final class Axiom_Database_Guard {

	private bool $installed = false;

	public function install(): void {
		if ( $this->installed ) {
			return;
		}
		add_filter( 'query', array( $this, 'intercept_query' ), PHP_INT_MAX, 1 );
		$this->installed = true;
	}

	public function intercept_query( string $sql ): string {
		if ( ! Axiom_Plugin_Security::is_enabled() || empty( $sql ) ) {
			return $sql;
		}

		$plugin_slug = Axiom_Plugin_Security::instance()->current_isolate();
		if ( $plugin_slug === null ) {
			return $sql;
		}

		if ( Axiom_Manifest_Validator::instance()->is_trusted( $plugin_slug ) ) {
			return $sql;
		}

		$parsed = $this->lex_sql( $sql );
		if ( $parsed === null ) {
			return $sql;
		}

		$operation = $parsed['operation'];
		$tables    = $parsed['tables'];

		foreach ( $tables as $table ) {
			$permitted = Axiom_Manifest_Validator::instance()->check( $plugin_slug, "db:{$operation}", $table );

			if ( ! $permitted ) {
				if ( Axiom_Plugin_Security::is_learning() ) {
					Axiom_Profiler::instance()->record_action( $plugin_slug, 'sql', array(
						'operation' => $operation,
						'table'     => $table,
						'sql'       => $sql,
					) );
				}

				if ( Axiom_Plugin_Security::is_enforce() || Axiom_Plugin_Security::is_audit() ) {
					Axiom_Audit_Logger::instance()->log(
						Axiom_Audit_Logger::SECURITY,
						'query_blocked',
						"SQL query blocked for '{$plugin_slug}' — table '{$table}' not in manifest",
						array(
							'plugin'    => $plugin_slug,
							'operation' => $operation,
							'table'     => $table,
							'sql'       => substr( $sql, 0, 500 ),
						),
						$plugin_slug
					);

					if ( Axiom_Plugin_Security::is_enforce() ) {
						return '';
					}
				}
			}
		}

		return $sql;
	}

	public function lex_sql( string $sql ): ?array {
		$sql   = trim( $sql );
		$upper = strtoupper( $sql );

		$operation = 'read';
		if ( str_starts_with( $upper, 'INSERT' ) || str_starts_with( $upper, 'UPDATE' ) || str_starts_with( $upper, 'REPLACE' ) ) {
			$operation = 'write';
		} elseif ( str_starts_with( $upper, 'DELETE' ) ) {
			$operation = 'delete';
		} elseif ( str_starts_with( $upper, 'CREATE' ) || str_starts_with( $upper, 'ALTER' ) || str_starts_with( $upper, 'DROP' ) || str_starts_with( $upper, 'TRUNCATE' ) ) {
			$operation = 'alter';
		} elseif ( str_starts_with( $upper, 'SELECT' ) ) {
			$operation = 'read';
		} else {
			return null;
		}

		$tables = $this->extract_tables( $sql );
		return array( 'operation' => $operation, 'tables' => $tables );
	}

	private function extract_tables( string $sql ): array {
		$tables = array();
		$patterns = array(
			'/\bFROM\s+`?(\w+)`?/i',
			'/\bJOIN\s+`?(\w+)`?/i',
			'/\bINTO\s+`?(\w+)`?/i',
			'/\bUPDATE\s+`?(\w+)`?/i',
			'/\bTABLE\s+`?(\w+)`?/i',
		);
		foreach ( $patterns as $pattern ) {
			if ( preg_match_all( $pattern, $sql, $matches ) ) {
				foreach ( $matches[1] as $table ) {
					$table = strtolower( $table );
					if ( ! in_array( $table, $tables, true ) ) {
						$tables[] = $table;
					}
				}
			}
		}
		return $tables;
	}
}

/*
 * ─── Resource Guard ────────────────────────────────────────────────
 */

#[AllowDynamicProperties]
final class Axiom_Resource_Guard {

	private bool $ticks_registered = false;
	private ?string $monitored_plugin = null;
	private int $tick_start = 0;

	public function register(): void {
		if ( $this->ticks_registered ) {
			return;
		}
		if ( function_exists( 'register_tick_function' ) ) {
			register_tick_function( array( $this, 'tick' ) );
		}
		$this->ticks_registered = true;
	}

	public function begin( string $plugin_slug ): void {
		$this->monitored_plugin = $plugin_slug;
		$this->tick_start       = (int) ( microtime( true ) * 1000 );
	}

	public function end(): void {
		if ( $this->monitored_plugin === null ) {
			return;
		}
		$this->monitored_plugin = null;
	}

	public function tick(): void {
		if ( $this->monitored_plugin === null ) {
			return;
		}

		$elapsed = (int) ( microtime( true ) * 1000 ) - $this->tick_start;
		$memory  = memory_get_usage( true );
		$memory_mb = $memory / ( 1024 * 1024 );

		$manifest = Axiom_Plugin_Security::instance()->get_plugin_manifest( $this->monitored_plugin );
		$cpu_limit  = $manifest ? $manifest->cpu_limit_ms() : 5000;
		$mem_limit  = $manifest ? $manifest->memory_limit_mb() : 128;

		if ( defined( 'AXIOM_SECURITY_CPU_LIMIT' ) ) {
			$cpu_limit = (int) AXIOM_SECURITY_CPU_LIMIT;
		}
		if ( defined( 'AXIOM_SECURITY_MEMORY_LIMIT' ) ) {
			$mem_limit = (int) AXIOM_SECURITY_MEMORY_LIMIT;
		}

		if ( $elapsed > $cpu_limit || $memory_mb > $mem_limit ) {
			Axiom_Audit_Logger::instance()->log(
				Axiom_Audit_Logger::ERROR,
				'resource_exhaustion',
				"Plugin '{$this->monitored_plugin}' exceeded resource budget ({$elapsed}ms / {$cpu_limit}ms CPU, {$memory_mb}MB / {$mem_limit}MB memory)",
				array(
					'plugin'    => $this->monitored_plugin,
					'elapsed_ms' => $elapsed,
					'memory_mb'  => round( $memory_mb, 2 ),
					'cpu_limit'  => $cpu_limit,
					'mem_limit'  => $mem_limit,
				),
				$this->monitored_plugin
			);
			$this->monitored_plugin = null;
		}
	}
}
