<?php
/**
 * Axiom Plugin Security — Plugin Manifest
 *
 * Represents a plugin's security manifest stored in the options table.
 * Defines the capabilities a plugin is permitted to use across
 * database, filesystem, network, hooks, and WordPress APIs.
 *
 * @since 6.7.0
 * @package WordPress
 * @subpackage Security
 */

#[AllowDynamicProperties]
final class Axiom_Manifest {

	private array $data;

	public function __construct( array $data ) {
		$this->data = $data;
	}

	const PROFILE_STANDARD   = 'standard';
	const PROFILE_RESTRICTED = 'restricted';
	const PROFILE_PERMISSIVE = 'permissive';
	const PROFILE_CUSTOM     = 'custom';

	public static function default_manifest( string $slug, string $name = '' ): self {
		return self::standard_profile( $slug, $name ?: $slug );
	}

	public static function standard_profile( string $id, string $name = '' ): self {
		return new self( array(
			'id'               => $id,
			'name'             => $name ?: $id,
			'manifest_version' => '1.0',
			'profile'          => self::PROFILE_STANDARD,
			'isolation'        => 'namespace',
			'permissions'      => array(
				'db'         => array(
					'read'   => array( 'wp_*' ),
					'write'  => array( 'wp_options', 'wp_postmeta', 'wp_usermeta' ),
					'delete' => array(),
					'alter'  => array(),
				),
				'filesystem' => array(
					'read:wp-content/uploads/*',
					'read:wp-content/plugins/*',
				),
				'network'    => array(
					'outbound' => array( '*.wordpress.org', 'api.wordpress.org' ),
				),
				'wp'         => array(
					'hooks'   => array(
						'read_only' => array( '*' ),
						'write'     => array( 'init', 'wp_head', 'wp_footer', 'admin_init', 'admin_menu', 'wp_enqueue_scripts', 'admin_enqueue_scripts', 'the_content', 'the_title', 'widgets_init', 'wp_ajax_*', 'wp_loaded', 'plugins_loaded', 'rest_api_init', 'wp_login', 'wp_logout', 'wp_authenticate', 'user_register', 'profile_update', 'comment_*', 'transition_post_status', 'save_post_*', 'wp_nav_menu_*' ),
					),
					'options' => array(
						'read'  => array( '*' ),
						'write' => array( 'widget_*', 'theme_mods_*', 'plugin_*', 'axiom_*' ),
					),
					'users'   => array(
						'read' => array( 'read', 'edit_posts', 'publish_posts' ),
					),
				),
				'system'     => array(),
			),
			'resource_limits'  => array(
				'cpu_ms'    => 5000,
				'memory_mb' => 128,
			),
		) );
	}

	public static function restricted_profile( string $id, string $name = '' ): self {
		return new self( array(
			'id'               => $id,
			'name'             => $name ?: $id,
			'manifest_version' => '1.0',
			'profile'          => self::PROFILE_RESTRICTED,
			'isolation'        => 'namespace',
			'permissions'      => array(
				'db'         => array(
					'read'   => array( 'wp_options', 'wp_posts', 'wp_postmeta' ),
					'write'  => array( 'wp_options' ),
					'delete' => array(),
					'alter'  => array(),
				),
				'filesystem' => array(
					'read:wp-content/plugins/' . $id . '/*',
				),
				'network'    => array(
					'outbound' => array(),
				),
				'wp'         => array(
					'hooks'   => array(
						'read_only' => array( '*' ),
						'write'     => array( 'init', 'wp_loaded', 'plugins_loaded', 'admin_init', 'wp_enqueue_scripts', 'admin_enqueue_scripts' ),
					),
					'options' => array(
						'read'  => array( $id . '_*' ),
						'write' => array( $id . '_*' ),
					),
					'users'   => array(
						'read' => array(),
					),
				),
				'system'     => array(),
			),
			'resource_limits'  => array(
				'cpu_ms'    => 1000,
				'memory_mb' => 32,
			),
		) );
	}

	public static function permissive_profile( string $id, string $name = '' ): self {
		return new self( array(
			'id'               => $id,
			'name'             => $name ?: $id,
			'manifest_version' => '1.0',
			'profile'          => self::PROFILE_PERMISSIVE,
			'isolation'        => 'namespace',
			'permissions'      => array(
				'db'         => array(
					'read'   => array( 'wp_*' ),
					'write'  => array( 'wp_*' ),
					'delete' => array( 'wp_*' ),
					'alter'  => array(),
				),
				'filesystem' => array(
					'read:wp-content/*',
					'write:wp-content/uploads/*',
				),
				'network'    => array(
					'outbound' => array( '*' ),
				),
				'wp'         => array(
					'hooks'   => array(
						'read_only' => array( '*' ),
						'write'     => array( '*' ),
					),
					'options' => array(
						'read'  => array( '*' ),
						'write' => array( '*' ),
					),
					'users'   => array(
						'read' => array( '*' ),
					),
				),
				'system'     => array(),
			),
			'resource_limits'  => array(
				'cpu_ms'    => 15000,
				'memory_mb' => 256,
			),
		) );
	}

	public static function from_profile( string $profile, string $id, string $name = '' ): self {
		switch ( $profile ) {
			case self::PROFILE_RESTRICTED:
				return self::restricted_profile( $id, $name );
			case self::PROFILE_PERMISSIVE:
				return self::permissive_profile( $id, $name );
			case self::PROFILE_CUSTOM:
				return self::standard_profile( $id, $name );
			default:
				return self::standard_profile( $id, $name );
		}
	}

	public function profile(): string {
		return $this->data['profile'] ?? self::PROFILE_CUSTOM;
	}

	public function id(): string {
		return $this->data['id'] ?? 'unknown';
	}

	public function name(): string {
		return $this->data['name'] ?? $this->id();
	}

	public function version(): string {
		return $this->data['manifest_version'] ?? '1.0';
	}

	public function isolation_mode(): string {
		return $this->data['isolation'] ?? 'namespace';
	}

	public function permissions(): array {
		return $this->data['permissions'] ?? array();
	}

	public function resource_limits(): array {
		return $this->data['resource_limits'] ?? array();
	}

	public function to_array(): array {
		return $this->data;
	}

	public function can_access_table( string $table, string $operation = 'read' ): bool {
		$allowed = $this->permissions()['db'][ $operation ] ?? $this->permissions()['db']['tables'] ?? array();
		foreach ( $allowed as $pattern ) {
			if ( fnmatch( $pattern, $table ) ) {
				return true;
			}
		}
		return false;
	}

	public function can_access_filesystem( string $path, string $operation = 'read' ): bool {
		$paths = $this->permissions()['filesystem'] ?? array();
		foreach ( $paths as $entry ) {
			$parts  = explode( ':', $entry, 2 );
			$op     = $parts[0] ?? 'read';
			$pattern = $parts[1] ?? $parts[0] ?? '';
			if ( $op === $operation && fnmatch( $pattern, $path ) ) {
				return true;
			}
		}
		return false;
	}

	public function can_network_outbound( string $domain ): bool {
		$allowed = $this->permissions()['network']['outbound'] ?? array();
		foreach ( $allowed as $pattern ) {
			if ( fnmatch( $pattern, $domain ) ) {
				return true;
			}
		}
		return false;
	}

	public function can_subscribe_hook( string $hook_name, bool $write = false ): bool {
		$key  = $write ? 'write' : 'read_only';
		$list = $this->permissions()['wp']['hooks'][ $key ] ?? array();
		foreach ( $list as $pattern ) {
			if ( fnmatch( $pattern, $hook_name ) ) {
				return true;
			}
		}
		return $write ? false : true;
	}

	public function can_read_option( string $option ): bool {
		$allowed = $this->permissions()['wp']['options']['read'] ?? array();
		foreach ( $allowed as $pattern ) {
			if ( fnmatch( $pattern, $option ) ) {
				return true;
			}
		}
		return false;
	}

	public function can_write_option( string $option ): bool {
		$allowed = $this->permissions()['wp']['options']['write'] ?? array();
		foreach ( $allowed as $pattern ) {
			if ( fnmatch( $pattern, $option ) ) {
				return true;
			}
		}
		return false;
	}

	public function can_read_user_data( string $capability ): bool {
		$allowed = $this->permissions()['wp']['users']['read'] ?? array();
		foreach ( $allowed as $pattern ) {
			if ( fnmatch( $pattern, $capability ) ) {
				return true;
			}
		}
		return false;
	}

	public function can_exec(): bool {
		return in_array( 'exec', $this->permissions()['system'] ?? array(), true );
	}

	public function cpu_limit_ms(): int {
		return $this->resource_limits()['cpu_ms'] ?? 5000;
	}

	public function memory_limit_mb(): int {
		return $this->resource_limits()['memory_mb'] ?? 128;
	}
}

/**
 * Manifest Validator — loads and caches manifests from the options table.
 *
 * Provides the security gate interface that every subsystem calls
 * to check whether a plugin is permitted to perform an action.
 *
 * @since 6.7.0
 */
#[AllowDynamicProperties]
final class Axiom_Manifest_Validator {

	private static ?Axiom_Manifest_Validator $instance = null;
	private array $manifest_cache = array();
	private array $trusted = array();

	public static function instance(): self {
		if ( self::$instance === null ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function set_trusted_plugins( array $slugs ): void {
		$this->trusted = array_flip( $slugs );
	}

	public function is_trusted( string $slug ): bool {
		return isset( $this->trusted[ $slug ] );
	}

	public function load_manifest( string $plugin_slug ): ?Axiom_Manifest {
		if ( isset( $this->manifest_cache[ $plugin_slug ] ) ) {
			return $this->manifest_cache[ $plugin_slug ];
		}

		$raw = get_option( 'axiom_manifest_' . $plugin_slug, null );
		if ( $raw === null ) {
			return null;
		}

		$data = is_string( $raw ) ? json_decode( $raw, true ) : $raw;
		if ( ! is_array( $data ) || empty( $data['id'] ) ) {
			return null;
		}

		$manifest = new Axiom_Manifest( $data );
		$this->manifest_cache[ $plugin_slug ] = $manifest;
		return $manifest;
	}

	public function save_manifest( string $plugin_slug, Axiom_Manifest $manifest ): bool {
		$this->manifest_cache[ $plugin_slug ] = $manifest;
		return update_option( 'axiom_manifest_' . $plugin_slug, wp_json_encode( $manifest->to_array() ), false );
	}

	public function delete_manifest( string $plugin_slug ): bool {
		unset( $this->manifest_cache[ $plugin_slug ] );
		return delete_option( 'axiom_manifest_' . $plugin_slug );
	}

	public function has_manifest( string $plugin_slug ): bool {
		if ( isset( $this->manifest_cache[ $plugin_slug ] ) ) {
			return true;
		}
		return get_option( 'axiom_manifest_' . $plugin_slug, null ) !== null;
	}

	public function check( string $plugin_slug, string $capability, ?string $resource = null ): bool {
		if ( $this->is_trusted( $plugin_slug ) ) {
			return true;
		}

		$manifest = $this->load_manifest( $plugin_slug );

		if ( $manifest === null ) {
			if ( Axiom_Plugin_Security::mode() === 'learning' ) {
				Axiom_Audit_Logger::instance()->log(
					Axiom_Audit_Logger::LEARNING,
					'manifest_missing',
					"Plugin '{$plugin_slug}' has no manifest — allowing in learning mode",
					array( 'capability' => $capability, 'resource' => $resource ),
					$plugin_slug
				);
				return true;
			}
			return false;
		}

		$permitted = self::evaluate( $manifest, $capability, $resource );

		if ( ! $permitted ) {
			if ( Axiom_Plugin_Security::mode() === 'learning' ) {
				Axiom_Audit_Logger::instance()->log(
					Axiom_Audit_Logger::LEARNING,
					'capability_unknown',
					"Plugin '{$plugin_slug}' used capability '{$capability}' not in manifest — learning",
					array( 'capability' => $capability, 'resource' => $resource ),
					$plugin_slug
				);
				return true;
			}

			Axiom_Audit_Logger::instance()->log(
				Axiom_Audit_Logger::SECURITY,
				'capability_denied',
				"Plugin '{$plugin_slug}' denied capability '{$capability}'",
				array( 'capability' => $capability, 'resource' => $resource ),
				$plugin_slug
			);
		}

		return $permitted;
	}

	private static function evaluate( Axiom_Manifest $manifest, string $capability, ?string $resource ): bool {
		$parts = explode( ':', $capability, 3 );

		switch ( $parts[0] ) {
			case 'db':
				$op    = $parts[1] ?? 'read';
				$table = $resource ?? $parts[2] ?? '';
				return $manifest->can_access_table( $table, $op );

			case 'filesystem':
				$op   = $parts[1] ?? 'read';
				$path = $resource ?? '';
				return $manifest->can_access_filesystem( $path, $op );

			case 'network':
				return $manifest->can_network_outbound( $resource ?? '' );

			case 'wp':
				if ( ( $parts[1] ?? '' ) === 'hooks' ) {
					$is_write = ( $parts[2] ?? 'read_only' ) === 'write';
					return $manifest->can_subscribe_hook( $resource ?? '', $is_write );
				}
				if ( ( $parts[1] ?? '' ) === 'options' ) {
					$is_write = ( $parts[2] ?? 'read' ) === 'write';
					return $is_write
						? $manifest->can_write_option( $resource ?? '' )
						: $manifest->can_read_option( $resource ?? '' );
				}
				if ( ( $parts[1] ?? '' ) === 'users' ) {
					return $manifest->can_read_user_data( $parts[2] ?? '' );
				}
				return false;

			case 'exec':
				return $manifest->can_exec();

			default:
				return false;
		}
	}
}
