<?php
/**
 * Proxy_WPDB — Transparent Delegation with SQL Interception
 *
 * Extends wpdb to intercept every public query entry point.
 * Delegates all real database work to the original $wpdb instance
 * while routing every SQL string through the DatabaseProxy for
 * manifest-based capability validation.
 *
 * Supports the full wpdb public API:
 *   - query(), get_results(), get_row(), get_var(), get_col()
 *   - insert(), update(), replace(), delete()
 *   - prepare(), escape(), etc.
 *
 * @package Axiom\Bridge
 */

declare(strict_types=1);

namespace Axiom\Bridge;

/**
 * @property-read \wpdb $inner The original delegated wpdb instance.
 */
#[AllowDynamicProperties]
class Proxy_WPDB extends \wpdb
{
    private \wpdb $inner;
    private DatabaseProxy $proxy;

    /**
     * Properties that must mirror the inner wpdb state.
     */
    public function __get( string $name ): mixed
    {
        if ( $name === 'inner' ) {
            return $this->inner;
        }
        return $this->inner->$name ?? null;
    }

    public function __set( string $name, mixed $value ): void
    {
        $this->inner->$name = $value;
    }

    public function __isset( string $name ): bool
    {
        return isset( $this->inner->$name );
    }

    /**
     * @param \wpdb        $original The real wpdb instance to delegate to.
     * @param DatabaseProxy $proxy   The Axiom interception layer.
     */
    public function __construct( \wpdb $original, DatabaseProxy $proxy )
    {
        $this->inner = $original;
        $this->proxy = $proxy;

        $this->dbh        = &$original->dbh;
        $this->result     = &$original->result;
        $this->last_result = &$original->last_result;
        $this->last_query  = &$original->last_query;

        $this->col_meta   = &$original->col_meta;
        $this->queries    = &$original->queries;
        $this->num_rows   = &$original->num_rows;
        $this->insert_id  = &$original->insert_id;
        $this->rows_affected = &$original->rows_affected;
        $this->num_queries   = &$original->num_queries;
        $this->last_error    = &$original->last_error;
        $this->error   = &$original->error;
        $this->field_types  = &$original->field_types;
        $this->charset      = &$original->charset;
        $this->collate      = &$original->collate;
        $this->ready        = &$original->ready;
        $this->has_connected = &$original->has_connected;
        $this->blogid       = &$original->blogid;
        $this->siteid       = &$original->siteid;
        $this->tables       = &$original->tables;
        $this->old_tables   = &$original->old_tables;
        $this->dbuser      = &$original->dbuser;
        $this->dbpassword  = &$original->dbpassword;
        $this->dbname      = &$original->dbname;
        $this->dbhost      = &$original->dbhost;
        $this->dbcharset   = &$original->dbcharset;
        $this->dbcollate   = &$original->dbcollate;
        $this->prefix      = &$original->prefix;
        $this->base_prefix = &$original->base_prefix;
        $this->timezone    = &$original->timezone;
        $this->allowed_charset = &$original->allowed_charset;
        $this->current_charset = &$original->current_charset;
        $this->check_current_charset = &$original->check_current_charset;
        $this->func_call   = &$original->func_call;
        $this->is_mysql    = &$original->is_mysql;
        $this->use_mysqli  = &$original->use_mysqli;

        if ( defined( 'SAVEQUERIES' ) && SAVEQUERIES ) {
            $this->queries = &$original->queries;
        }
    }

    /**
     * Intercept the primary query method.
     */
    public function query( string $query ): int|false
    {
        $intercepted = $this->proxy->intercept( $query );

        if ( $intercepted === '' ) {
            $this->last_error = 'Blocked by Axiom security policy.';
            return false;
        }

        return $this->inner->query( $intercepted );
    }

    /**
     * Proxy: insert
     */
    public function insert( string $table, array $data, array|string|null $format = null ): int|false
    {
        $intercepted = $this->proxy->intercept( "INSERT INTO {$table}" );
        if ( $intercepted === '' ) {
            $this->last_error = 'Blocked by Axiom security policy.';
            return false;
        }
        return $this->inner->insert( $table, $data, $format );
    }

    /**
     * Proxy: update
     */
    public function update( string $table, array $data, array $where, array|string|null $format = null, array|string|null $where_format = null ): int|false
    {
        $intercepted = $this->proxy->intercept( "UPDATE {$table}" );
        if ( $intercepted === '' ) {
            $this->last_error = 'Blocked by Axiom security policy.';
            return false;
        }
        return $this->inner->update( $table, $data, $where, $format, $where_format );
    }

    /**
     * Proxy: replace
     */
    public function replace( string $table, array $data, array|string|null $format = null ): int|false
    {
        $intercepted = $this->proxy->intercept( "REPLACE {$table}" );
        if ( $intercepted === '' ) {
            $this->last_error = 'Blocked by Axiom security policy.';
            return false;
        }
        return $this->inner->replace( $table, $data, $format );
    }

    /**
     * Proxy: delete
     */
    public function delete( string $table, array $where, array|string|null $where_format = null ): int|false
    {
        $intercepted = $this->proxy->intercept( "DELETE FROM {$table}" );
        if ( $intercepted === '' ) {
            $this->last_error = 'Blocked by Axiom security policy.';
            return false;
        }
        return $this->inner->delete( $table, $where, $where_format );
    }

    /**
     * Proxy: get_results
     */
    public function get_results( $query = null, $output = OBJECT ): array|object|null
    {
        if ( $query !== null ) {
            $intercepted = $this->proxy->intercept( $query );
            if ( $intercepted === '' ) {
                $this->last_error = 'Blocked by Axiom security policy.';
                return null;
            }
            $query = $intercepted;
        }
        return $this->inner->get_results( $query, $output );
    }

    /**
     * Proxy: get_row
     */
    public function get_row( $query = null, $output = OBJECT, $y = 0 ): array|object|null
    {
        if ( $query !== null ) {
            $intercepted = $this->proxy->intercept( $query );
            if ( $intercepted === '' ) {
                $this->last_error = 'Blocked by Axiom security policy.';
                return null;
            }
            $query = $intercepted;
        }
        return $this->inner->get_row( $query, $output, $y );
    }

    /**
     * Proxy: get_var
     */
    public function get_var( $query = null, $x = 0, $y = 0 ): string|null|int|float
    {
        if ( $query !== null ) {
            $intercepted = $this->proxy->intercept( $query );
            if ( $intercepted === '' ) {
                $this->last_error = 'Blocked by Axiom security policy.';
                return null;
            }
            $query = $intercepted;
        }
        return $this->inner->get_var( $query, $x, $y );
    }

    /**
     * Proxy: get_col
     */
    public function get_col( $query = null, $x = 0 ): array
    {
        if ( $query !== null ) {
            $intercepted = $this->proxy->intercept( $query );
            if ( $intercepted === '' ) {
                $this->last_error = 'Blocked by Axiom security policy.';
                return [];
            }
            $query = $intercepted;
        }
        return $this->inner->get_col( $query, $x );
    }

    /**
     * Delegate prepare directly — no interception needed.
     */
    public function prepare( $query, ...$args ): string|int|float|bool|null
    {
        return $this->inner->prepare( $query, ...$args );
    }

    /**
     * Delegate esc_like directly.
     */
    public function esc_like( string $text ): string
    {
        return $this->inner->esc_like( $text );
    }

    /**
     * Delegate flush directly.
     */
    public function flush( bool $flush = true ): void
    {
        $this->inner->flush( $flush );
    }

    /**
     * Delegate db_connect directly.
     */
    public function db_connect( bool $allow_bail = true ): void
    {
        $this->inner->db_connect( $allow_bail );
    }

    /**
     * Delegate init_charset directly.
     */
    public function init_charset(): bool
    {
        return $this->inner->init_charset();
    }

    /**
     * Delegate set_charset directly.
     */
    public function set_charset( $dbh = null, $charset = null, $collate = null ): void
    {
        $this->inner->set_charset( $dbh, $charset, $collate );
    }

    /**
     * Delegate select directly.
     */
    public function select( $db, $dbh = null ): void
    {
        $this->inner->select( $db, $dbh );
    }

    /**
     * Delegate print_error directly.
     */
    public function print_error( string $str = '' ): void
    {
        $this->inner->print_error( $str );
    }

    /**
     * Delegate show_errors / hide_errors directly.
     */
    public function show_errors( bool $show = true ): bool
    {
        return $this->inner->show_errors( $show );
    }

    public function hide_errors(): bool
    {
        return $this->inner->hide_errors();
    }

    public function suppress_errors( bool $suppress = true ): bool
    {
        return $this->inner->suppress_errors( $suppress );
    }

    /**
     * Delegate get_caller directly.
     */
    public function get_caller(): string
    {
        return $this->inner->get_caller();
    }

    /**
     * Delegate check_database_version directly.
     */
    public function check_database_version(): void
    {
        $this->inner->check_database_version();
    }

    /**
     * Delegate supports_collation directly.
     */
    public function supports_collation(): bool
    {
        return $this->inner->supports_collation();
    }

    /**
     * Delegate has_cap directly.
     */
    public function has_cap( string $db_cap ): bool
    {
        return $this->inner->has_cap( $db_cap );
    }

    /**
     * Delegate db_version directly.
     */
    public function db_version( $dbh_or_table = false ): string|null
    {
        return $this->inner->db_version( $dbh_or_table );
    }

    /**
     * Delegate table_exists directly.
     */
    public function table_exists( string $table ): bool
    {
        return $this->inner->table_exists( $table );
    }

    /**
     * Delegate get_table_from_query directly.
     */
    public function get_table_from_query( string $query ): string|false
    {
        return $this->inner->get_table_from_query( $query );
    }

    /**
     * Delegate processes() directly.
     */
    public function processes(): array|false
    {
        return $this->inner->processes();
    }

    /**
     * Delegate close() directly.
     */
    public function close(): void
    {
        $this->inner->close();
    }

    /**
     * Delegate __wakeup directly.
     */
    public function __wakeup(): void
    {
        $this->inner->__wakeup();
    }

    /**
     * Delegate __sleep directly.
     */
    public function __sleep(): array
    {
        return $this->inner->__sleep();
    }

    /**
     * Delegate bail_handler directly.
     */
    public function bail_handler( string $message ): void
    {
        $this->inner->bail_handler( $message );
    }

    /**
     * Delegate check_connection directly.
     */
    public function check_connection( bool $allow_bail = true ): void
    {
        $this->inner->check_connection( $allow_bail );
    }

    /**
     * Delegate load_col_info directly.
     */
    public function load_col_info(): void
    {
        $this->inner->load_col_info();
    }

    /**
     * Delegate get_col_info directly.
     */
    public function get_col_info( string $info_type = 'name', int $col_offset = -1 ): array|object|null
    {
        return $this->inner->get_col_info( $info_type, $col_offset );
    }

    /**
     * Delegate __call for any dynamic methods on the inner wpdb.
     */
    public function __call( string $name, array $arguments ): mixed
    {
        return $this->inner->$name( ...$arguments );
    }

    /**
     * Delegate static methods.
     */
    public static function __callStatic( string $name, array $arguments ): mixed
    {
        return \wpdb::$name( ...$arguments );
    }
}
