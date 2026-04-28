<?php
/**
 * Namespace Wrapper — Virtual PHP Namespace Isolation for Legacy Plugins
 *
 * Implements a streamWrapper that intercepts PHP file inclusions from a
 * plugin's directory and dynamically rewrites the code to wrap all
 * top-level classes, functions, and global code in a unique namespace.
 *
 * This prevents global scope pollution between legacy plugins that declare
 * the same class or function names, enabling safe coexistence without
 * modifying the plugin source files.
 *
 * How it works:
 *   1. A streamWrapper registers a protocol like "axiom-plugin-slug://".
 *   2. When include_once or require_once is called through this protocol,
 *      the wrapper reads the original PHP file.
 *   3. A tokenizer-based rewriter wraps the file in `namespace Axiom\Plugin\Slug { ... }`.
 *   4. All global references ($GLOBALS, \\other_function(), \\Exception) are
 *      remapped to maintain access to the original global scope.
 *
 * @package Axiom\Kernel
 */

declare(strict_types=1);

namespace Axiom\Kernel;

class NamespaceWrapper
{
    private string $plugin_slug;
    private string $plugin_dir;
    private string $protocol;

    /**
     * Stack of contexts for nested includes.
     * @var array<int, array{buffer: string, read: bool}>
     */
    private array $context_stack = [];

    public function __construct( string $plugin_slug, string $plugin_dir = '' )
    {
        $this->plugin_slug = $plugin_slug;
        $this->plugin_dir  = $plugin_dir;
        $this->protocol    = 'axiom-' . preg_replace( '/[^a-z0-9]/', '-', strtolower( $plugin_slug ) );
    }

    /**
     * Register this wrapper's stream protocol.
     */
    public function register(): bool
    {
        if ( in_array( $this->protocol, stream_get_wrappers(), true ) ) {
            stream_wrapper_unregister( $this->protocol );
        }
        return stream_wrapper_register( $this->protocol, self::class );
    }

    /**
     * Build a virtual stream URI for a real file path.
     */
    public function wrap_path( string $real_path ): string
    {
        return $this->protocol . '://' . ltrim( str_replace( '\\', '/', $real_path ), '/' );
    }

    /**
     * Get the wrapped protocol name.
     */
    public function protocol(): string
    {
        return $this->protocol;
    }

    /**
     * Convert a real path to its wrapped URI.
     */
    public function real_to_virtual( string $real_path ): string
    {
        return $this->protocol . '://' . ltrim( str_replace( $this->plugin_dir, '', str_replace( '\\', '/', $real_path ) ), '/' );
    }

    /* ---- streamWrapper interface ---- */

    private mixed $handle = null;
    private string $buffer = '';
    private int $position = 0;

    public function stream_open( string $path, string $mode, int $options, ?string &$opened_path ): bool
    {
        $real_path = $this->resolve_path( $path );
        if ( ! file_exists( $real_path ) ) {
            return false;
        }

        $this->handle = fopen( $real_path, 'rb' );
        if ( $this->handle === false ) {
            return false;
        }

        $original = stream_get_contents( $this->handle );
        fclose( $this->handle );

        $this->buffer  = $this->rewrite( $original, $real_path );
        $this->position = 0;

        return true;
    }

    public function stream_read( int $count ): string
    {
        $chunk = substr( $this->buffer, $this->position, $count );
        $this->position += strlen( $chunk );
        return $chunk !== false ? $chunk : '';
    }

    public function stream_write( string $data ): int
    {
        return 0;
    }

    public function stream_tell(): int
    {
        return $this->position;
    }

    public function stream_eof(): bool
    {
        return $this->position >= strlen( $this->buffer );
    }

    public function stream_seek( int $offset, int $whence = SEEK_SET ): bool
    {
        switch ( $whence ) {
            case SEEK_SET:
                $new_pos = $offset;
                break;
            case SEEK_CUR:
                $new_pos = $this->position + $offset;
                break;
            case SEEK_END:
                $new_pos = strlen( $this->buffer ) + $offset;
                break;
            default:
                return false;
        }
        if ( $new_pos < 0 || $new_pos > strlen( $this->buffer ) ) {
            return false;
        }
        $this->position = $new_pos;
        return true;
    }

    public function stream_stat(): array|false
    {
        return false;
    }

    public function url_stat( string $path, int $flags ): array|false
    {
        $real_path = $this->resolve_path( $path );
        return @stat( $real_path );
    }

    /**
     * Resolve the virtual path back to a real filesystem path.
     */
    private function resolve_path( string $path ): string
    {
        $parts = explode( '://', $path, 2 );
        $file_path = $parts[1] ?? '';
        return $this->plugin_dir . '/' . ltrim( $file_path, '/' );
    }

    /**
     * Dynamically rewrite PHP source to wrap it in a unique namespace.
     *
     * Wraps the entire file in a namespace block and remaps fully-qualified
     * global references (like \Exception, \WP_Query) to maintain core access.
     */
    private function rewrite( string $source, string $file_path ): string
    {
        $namespace_name = 'Axiom\\Plugins\\' . $this->php_namespace_slug();

        $tokens = token_get_all( $source );
        $has_namespace = false;
        $has_class_or_fn = false;

        foreach ( $tokens as $token ) {
            if ( is_array( $token ) ) {
                if ( $token[0] === T_NAMESPACE ) {
                    $has_namespace = true;
                    break;
                }
                if ( $token[0] === T_CLASS || $token[0] === T_FUNCTION ) {
                    $has_class_or_fn = true;
                }
            }
        }

        if ( $has_namespace ) {
            return $source;
        }

        $rewritten = $this->remap_global_references( $source );

        $result = "namespace {$namespace_name} {\n";
        $result .= $rewritten;
        if ( substr( $result, -2 ) !== "?\n" && substr( $result, -2 ) !== "?>" ) {
            $result .= "\n";
        }
        $result .= "}\n";

        return $result;
    }

    /**
     * Remap fully-qualified global namespace references.
     *
     * Inside the namespace block, \WP_Query must still resolve to the
     * global WP_Query, and built-in PHP classes like \Exception must work.
     */
    private function remap_global_references( string $source ): string
    {
        $replacements = [
            '/\\\\Exception/'   => '\\Exception',
            '/\\\\WP_Query/'    => '\\WP_Query',
            '/\\\\WP_Post/'     => '\\WP_Post',
            '/\\\\wpdb/'        => '\\wpdb',
            '/\\\\WP_Error/'    => '\\WP_Error',
            '/\\\\WP_Roles/'    => '\\WP_Roles',
            '/\\\\WP_User/'     => '\\WP_User',
            '/\\\\WP_Hook/'     => '\\WP_Hook',
            '/\\\\WP_Embed/'    => '\\WP_Embed',
            '/\\\\WP_Locale/'   => '\\WP_Locale',
            '/\\\\WP_Rewrite/'  => '\\WP_Rewrite',
            '/\\\\WP_Widget/'   => '\\WP_Widget',
            '/\\\\WP_Http/'     => '\\WP_Http',
        ];

        return preg_replace( array_keys( $replacements ), array_values( $replacements ), $source );
    }

    /**
     * Convert a plugin slug to a valid PHP namespace segment.
     */
    private function php_namespace_slug(): string
    {
        $parts = explode( '/', str_replace( '\\', '/', $this->plugin_slug ) );
        return implode( '\\', array_map( function ( string $part ): string {
            $clean = preg_replace( '/[^a-zA-Z0-9_\x80-\xff]/', '_', $part );
            if ( is_numeric( $clean[0] ?? '_' ) ) {
                $clean = '_' . $clean;
            }
            return $clean;
        }, $parts ) );
    }
}
