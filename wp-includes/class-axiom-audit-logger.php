<?php
/**
 * Axiom Plugin Security — Audit Logger
 *
 * Logs security events to a custom database table.
 * Created automatically on first use.
 *
 * @since 6.7.0
 * @package WordPress
 * @subpackage Security
 */

#[AllowDynamicProperties]
final class Axiom_Audit_Logger {

	const INFO     = 'info';
	const WARNING  = 'warning';
	const ERROR    = 'error';
	const SECURITY = 'security';
	const LEARNING = 'learning';

	private static ?Axiom_Audit_Logger $instance = null;
	private static ?string $table                 = null;
	private static bool $schema_checked           = false;

	private array $buffer = array();

	public static function instance(): self {
		if ( self::$instance === null ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function table(): string {
		if ( self::$table === null ) {
			global $wpdb;
			self::$table = $wpdb->prefix . 'axiom_audit';
		}
		return self::$table;
	}

	public function ensure_schema(): void {
		if ( self::$schema_checked ) {
			return;
		}
		self::$schema_checked = true;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$table     = $this->table();
		$charset   = $GLOBALS['wpdb']->get_charset_collate();
		$installed = get_option( 'axiom_audit_db_version', '' );

		if ( $installed === AXIOM_SECURITY_DB_VERSION ) {
			return;
		}

		$sql = "CREATE TABLE IF NOT EXISTS {$table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			event_time datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			level varchar(20) NOT NULL DEFAULT 'info',
			plugin_slug varchar(255) DEFAULT NULL,
			event_type varchar(100) NOT NULL,
			message text DEFAULT NULL,
			context longtext DEFAULT NULL,
			PRIMARY KEY (id),
			KEY event_time (event_time),
			KEY level (level),
			KEY plugin_slug (plugin_slug),
			KEY event_type (event_type)
		) {$charset};";

		dbDelta( $sql );
		update_option( 'axiom_audit_db_version', AXIOM_SECURITY_DB_VERSION );
	}

	public function log( string $level, string $event_type, string $message, ?array $context = null, ?string $plugin_slug = null ): void {
		$entry = array(
			'level'       => $level,
			'event_type'  => $event_type,
			'message'     => $message,
			'context'     => $context !== null ? wp_json_encode( $context ) : null,
			'plugin_slug' => $plugin_slug ?? $this->resolve_current_plugin(),
		);

		if ( did_action( 'init' ) > 0 ) {
			$this->flush_entry( $entry );
		} else {
			$this->buffer[] = $entry;
			if ( count( $this->buffer ) >= 20 ) {
				$this->flush_buffer();
			}
		}
	}

	public function flush_buffer(): void {
		if ( empty( $this->buffer ) ) {
			return;
		}
		$this->ensure_schema();
		global $wpdb;
		$table = $this->table();
		foreach ( $this->buffer as $entry ) {
			$wpdb->insert( $table, $entry );
		}
		$this->buffer = array();
	}

	public function query( array $args = array() ): array {
		$this->flush_buffer();
		$this->ensure_schema();
		global $wpdb;

		$table = $this->table();
		$where = '1=1';
		$params = array();

		if ( ! empty( $args['level'] ) ) {
			$where .= ' AND level = %s';
			$params[] = $args['level'];
		}
		if ( ! empty( $args['plugin_slug'] ) ) {
			$where .= ' AND plugin_slug = %s';
			$params[] = $args['plugin_slug'];
		}
		if ( ! empty( $args['event_type'] ) ) {
			$where .= ' AND event_type = %s';
			$params[] = $args['event_type'];
		}

		$limit  = isset( $args['limit'] ) ? min( (int) $args['limit'], 1000 ) : 100;
		$offset = isset( $args['offset'] ) ? max( (int) $args['offset'], 0 ) : 0;

		$sql = "SELECT * FROM {$table} WHERE {$where} ORDER BY event_time DESC LIMIT %d OFFSET %d";
		$params[] = $limit;
		$params[] = $offset;

		return $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A );
	}

	public function purge(): void {
		$this->flush_buffer();
		$this->ensure_schema();
		global $wpdb;
		$wpdb->query( "TRUNCATE TABLE {$this->table()}" );
	}

	public function count( array $args = array() ): int {
		$this->flush_buffer();
		$this->ensure_schema();
		global $wpdb;
		$table = $this->table();
		$where = '1=1';

		if ( ! empty( $args['level'] ) ) {
			$where .= $wpdb->prepare( ' AND level = %s', $args['level'] );
		}
		if ( ! empty( $args['plugin_slug'] ) ) {
			$where .= $wpdb->prepare( ' AND plugin_slug = %s', $args['plugin_slug'] );
		}

		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE {$where}" );
	}

	private function flush_entry( array $entry ): void {
		$this->ensure_schema();
		global $wpdb;
		$wpdb->insert( $this->table(), $entry );
	}

	private function resolve_current_plugin(): ?string {
		return $GLOBALS['axiom_current_plugin'] ?? null;
	}
}
