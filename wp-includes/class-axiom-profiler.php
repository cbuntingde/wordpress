<?php
/**
 * Axiom Plugin Security — Learning Mode Profiler
 *
 * Observes plugin behavior during learning mode and
 * auto-generates security manifests from observed actions.
 *
 * @since 6.7.0
 * @package WordPress
 * @subpackage Security
 */

#[AllowDynamicProperties]
final class Axiom_Profiler {

	private static ?Axiom_Profiler $instance = null;
	private array $observed = array();

	public static function instance(): self {
		if ( self::$instance === null ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function record_action( string $plugin_slug, string $type, array $data ): void {
		if ( ! isset( $this->observed[ $plugin_slug ] ) ) {
			$this->observed[ $plugin_slug ] = array(
				'db'         => array( 'read' => array(), 'write' => array(), 'delete' => array(), 'alter' => array() ),
				'filesystem' => array(),
				'network'    => array(),
				'hooks'      => array(),
				'options'    => array( 'read' => array(), 'write' => array() ),
				'cap'        => array(),
			);
		}

		$record = &$this->observed[ $plugin_slug ];

		switch ( $type ) {
			case 'sql':
				$op    = $data['operation'] ?? 'read';
				$table = $data['table'] ?? '';
				if ( $table && ! in_array( $table, $record['db'][ $op ], true ) ) {
					$record['db'][ $op ][] = $table;
				}
				break;

			case 'hook':
				$hook = $data['hook'] ?? '';
				if ( $hook && ! in_array( $hook, $record['hooks'], true ) ) {
					$record['hooks'][] = $hook;
				}
				break;

			case 'filesystem':
				$path = $data['path'] ?? '';
				if ( $path && ! in_array( $path, $record['filesystem'], true ) ) {
					$record['filesystem'][] = $path;
				}
				break;

			case 'network':
				$domain = $data['domain'] ?? '';
				if ( $domain && ! in_array( $domain, $record['network'], true ) ) {
					$record['network'][] = $domain;
				}
				break;

			case 'option':
				$key     = $data['option'] ?? '';
				$is_write = $data['write'] ?? false;
				if ( $key && ! in_array( $key, $record['options'][ $is_write ? 'write' : 'read' ], true ) ) {
					$record['options'][ $is_write ? 'write' : 'read' ][] = $key;
				}
				break;

			case 'capability':
				$cap = $data['capability'] ?? '';
				if ( $cap && ! in_array( $cap, $record['cap'], true ) ) {
					$record['cap'][] = $cap;
				}
				break;
		}
	}

	public function generate_manifest( string $plugin_slug, string $plugin_name = '' ): ?Axiom_Manifest {
		$data = $this->observed[ $plugin_slug ] ?? null;
		if ( $data === null ) {
			return null;
		}

		$perms = array(
			'db'         => $data['db'],
			'filesystem' => $this->build_filesystem_perms( $data['filesystem'] ),
			'network'    => array( 'outbound' => $data['network'] ),
			'wp'         => array(
				'hooks'   => array(
					'read_only' => $data['hooks'],
					'write'     => $data['hooks'],
				),
				'options' => $data['options'],
				'users'   => array(
					'read' => $data['cap'],
				),
			),
			'system'     => array(),
		);

		$manifest_data = array(
			'id'               => $plugin_slug,
			'name'             => $plugin_name ?: $plugin_slug,
			'manifest_version' => '1.0',
			'isolation'        => 'namespace',
			'permissions'      => $perms,
			'resource_limits'  => array(
				'cpu_ms'    => 5000,
				'memory_mb' => 128,
			),
		);

		return new Axiom_Manifest( $manifest_data );
	}

	public function has_data( string $plugin_slug ): bool {
		return isset( $this->observed[ $plugin_slug ] );
	}

	public function clear( string $plugin_slug ): void {
		unset( $this->observed[ $plugin_slug ] );
	}

	public function clear_all(): void {
		$this->observed = array();
	}

	private function build_filesystem_perms( array $paths ): array {
		$perms = array();
		foreach ( $paths as $path ) {
			$perms[] = 'read:' . $path;
		}
		return $perms;
	}
}
