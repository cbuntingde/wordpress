( function( $ ) {
    'use strict';

var AxiomAdmin = {

    init: function() {
        this.bindSettingsForm();
        this.bindManifestButtons();
        this.bindManifestEditor();
        this.bindLogViewer();
        this.bindLogClear();
        this.bindRefreshOverview();
    },

    showNotice: function( type, message, container ) {
        container = container || $( '.ax-wrap .ax-layout' ).first();
        if ( container.length === 0 ) {
            container = $( '.ax-wrap' ).first();
        }
        var notice = $( '<div class="ax-notice ax-notice-' + type + '">' + message + '</div>' );
        container.before( notice );
        setTimeout( function() {
            notice.fadeOut( 300, function() { $( this ).remove(); } );
        }, 4000 );
    },

    /* ---- Settings form ---- */
    bindSettingsForm: function() {
        $( '#axiom-settings-form' ).on( 'submit', function( e ) {
            e.preventDefault();
            var form  = $( this );
            var btn   = form.find( '[type="submit"]' );
            var data  = form.serializeArray();
            var opts  = {};

            $.each( data, function( i, field ) {
                var name = field.name.replace( /^axiom_settings\[([^\]]+)\]$/, '$1' );
                if ( name !== field.name ) {
                    opts[ name ] = field.value;
                }
            } );

            btn.prop( 'disabled', true ).html( '<span class="ax-spinner"></span>' );

            $.post( axiomAdmin.ajaxUrl, {
                action:  'axiom_save_settings',
                nonce:   axiomAdmin.nonce,
                options: opts
            }, function( res ) {
                if ( res.success ) {
                    AxiomAdmin.showNotice( 'success', axiomAdmin.i18n.saved );
                } else {
                    AxiomAdmin.showNotice( 'error', res.data?.message || axiomAdmin.i18n.error );
                }
            } ).always( function() {
                btn.prop( 'disabled', false ).text( 'Save Changes' );
            } );
        } );
    },

    /* ---- Generate manifest ---- */
    bindManifestButtons: function() {
        $( document ).on( 'click', '.ax-generate-manifest', function( e ) {
            e.preventDefault();
            if ( ! confirm( axiomAdmin.i18n.generatePrompt ) ) {
                return;
            }

            var btn  = $( this );
            var slug = btn.data( 'plugin' );

            btn.prop( 'disabled', true ).html( '<span class="ax-spinner"></span>' );

            $.post( axiomAdmin.ajaxUrl, {
                action:      'axiom_generate_manifest',
                nonce:       axiomAdmin.nonce,
                plugin_slug: slug
            }, function( res ) {
                if ( res.success ) {
                    AxiomAdmin.showNotice( 'success', axiomAdmin.i18n.generated );
                    btn.text( 'Regenerate' );
                } else {
                    AxiomAdmin.showNotice( 'error', res.data?.message || axiomAdmin.i18n.error );
                    btn.prop( 'disabled', false ).text( 'Generate Manifest' );
                }
            } ).fail( function() {
                btn.prop( 'disabled', false ).text( 'Generate Manifest' );
                AxiomAdmin.showNotice( 'error', axiomAdmin.i18n.error );
            } );
        } );
    },

    /* ---- Manifest editor ---- */
    bindManifestEditor: function() {
        var editor = $( '#ax-manifest-editor' );
        if ( editor.length === 0 ) {
            return;
        }

        var currentSlug = '';

        function close() {
            editor.hide();
            currentSlug = '';
        }

        function commaVal( id ) {
            var v = $( id ).val();
            return v ? v.split( ',' ).map( function( s ) { return s.trim(); } ).filter( function( s ) { return s !== ''; } ) : [];
        }

        function buildManifest() {
            return {
                id: currentSlug,
                name: $( '#ax-editor-plugin-name' ).text(),
                manifest_version: '1.0',
                isolation: $( '#ax-editor-isolation' ).val(),
                permissions: {
                    db: {
                        read:   commaVal( '#ax-editor-db-read' ),
                        write:  commaVal( '#ax-editor-db-write' ),
                        delete: commaVal( '#ax-editor-db-delete' ),
                        alter:  commaVal( '#ax-editor-db-alter' )
                    },
                    filesystem: commaVal( '#ax-editor-filesystem' ),
                    network: {
                        outbound: commaVal( '#ax-editor-network' )
                    },
                    wp: {
                        hooks: {
                            read_only: commaVal( '#ax-editor-hooks-read' ),
                            write:     commaVal( '#ax-editor-hooks-write' )
                        },
                        options: {
                            read:  commaVal( '#ax-editor-options-read' ),
                            write: commaVal( '#ax-editor-options-write' )
                        },
                        users: {
                            read: commaVal( '#ax-editor-users-read' )
                        }
                    },
                    system: commaVal( '#ax-editor-system' )
                },
                resource_limits: {
                    cpu_ms:    parseInt( $( '#ax-editor-cpu' ).val(), 10 ) || 500,
                    memory_mb: parseInt( $( '#ax-editor-memory' ).val(), 10 ) || 64
                }
            };
        }

        function populateForm( data ) {
            var p = data.permissions || {};
            var db = p.db || {};
            var wp = p.wp || {};
            var hooks = wp.hooks || {};
            var options = wp.options || {};
            var users = wp.users || {};
            var limits = data.resource_limits || {};

            $( '#ax-editor-isolation' ).val( data.isolation || 'namespace' );
            $( '#ax-editor-cpu' ).val( limits.cpu_ms || 500 );
            $( '#ax-editor-memory' ).val( limits.memory_mb || 64 );

            $( '#ax-editor-db-read' ).val( ( db.read || [] ).join( ', ' ) );
            $( '#ax-editor-db-write' ).val( ( db.write || [] ).join( ', ' ) );
            $( '#ax-editor-db-delete' ).val( ( db.delete || [] ).join( ', ' ) );
            $( '#ax-editor-db-alter' ).val( ( db.alter || [] ).join( ', ' ) );
            $( '#ax-editor-filesystem' ).val( ( p.filesystem || [] ).join( ', ' ) );
            $( '#ax-editor-network' ).val( ( ( p.network && p.network.outbound ) || [] ).join( ', ' ) );
            $( '#ax-editor-hooks-read' ).val( ( hooks.read_only || [] ).join( ', ' ) );
            $( '#ax-editor-hooks-write' ).val( ( hooks.write || [] ).join( ', ' ) );
            $( '#ax-editor-options-read' ).val( ( options.read || [] ).join( ', ' ) );
            $( '#ax-editor-options-write' ).val( ( options.write || [] ).join( ', ' ) );
            $( '#ax-editor-users-read' ).val( ( users.read || [] ).join( ', ' ) );
            $( '#ax-editor-system' ).val( ( p.system || [] ).join( ', ' ) );
        }

        function open( slug ) {
            currentSlug = slug;
            $( '#ax-editor-plugin-name' ).text( slug );

            $.post( axiomAdmin.ajaxUrl, {
                action:      'axiom_get_manifest',
                nonce:       axiomAdmin.nonce,
                plugin_slug: slug
            }, function( res ) {
                if ( res.success ) {
                    populateForm( res.data );
                    $( '#ax-editor-error' ).hide();
                    editor.show();
                } else {
                    AxiomAdmin.showNotice( 'error', res.data?.message || 'Failed to load manifest.' );
                }
            } );
        }

        $( document ).on( 'click', '.ax-edit-manifest', function( e ) {
            e.preventDefault();
            open( $( this ).data( 'plugin' ) );
        } );

        $( '#ax-editor-close, #ax-editor-close-btn' ).on( 'click', close );

        $( '#ax-editor-save' ).on( 'click', function() {
            var btn = $( this );
            var manifest = buildManifest();

            btn.prop( 'disabled', true ).html( '<span class="ax-spinner"></span>' );

            $.post( axiomAdmin.ajaxUrl, {
                action:      'axiom_save_manifest',
                nonce:       axiomAdmin.nonce,
                plugin_slug: currentSlug,
                manifest:    manifest
            }, function( res ) {
                if ( res.success ) {
                    AxiomAdmin.showNotice( 'success', 'Manifest saved for ' + currentSlug + '.' );
                    close();
                    setTimeout( function() { location.reload(); }, 1000 );
                } else {
                    AxiomAdmin.showNotice( 'error', res.data?.message || 'Failed to save manifest.' );
                }
            } ).always( function() {
                btn.prop( 'disabled', false ).text( 'Save Manifest' );
            } );
        } );
    },

    /* ---- Audit log viewer ---- */
    bindLogViewer: function() {
        if ( $( '#axiom-log-container' ).length === 0 ) {
            return;
        }

        var self = this;

        function loadLog() {
            var level  = $( '#ax-log-level' ).val();
            var search = $( '#ax-log-search' ).val();

            $.post( axiomAdmin.ajaxUrl, {
                action: 'axiom_view_log',
                nonce:  axiomAdmin.nonce,
                level:  level,
                search: search
            }, function( res ) {
                var container = $( '#axiom-log-entries' );
                container.empty();

                if ( ! res.success || ! res.data.entries.length ) {
                    container.html( '<div class="ax-log-empty">No log entries found.</div>' );
                    return;
                }

                $.each( res.data.entries, function( i, entry ) {
                    var time  = entry.timestamp || '';
                    var msg   = entry.message || '';
                    var level = entry.level || 'info';
                    var ctx   = JSON.stringify( entry.context || {} );

                    var row = '<div class="ax-log-entry">' +
                        '<span class="ax-log-time">' + time + '</span> ' +
                        '<span class="ax-log-level ' + level + '">' + level + '</span>' +
                        '<div class="ax-log-message">' + msg + '</div>' +
                        '<div class="ax-log-context">' + ctx + '</div>' +
                        '</div>';
                    container.append( row );
                } );
            } );
        }

        $( '#ax-log-level, #ax-log-search' ).on( 'change keyup', function() {
            clearTimeout( self._logTimer );
            self._logTimer = setTimeout( loadLog, 300 );
        } );

        loadLog();
    },

    /* ---- Clear log ---- */
    bindLogClear: function() {
        $( '#axiom-clear-log' ).on( 'click', function( e ) {
            e.preventDefault();
            if ( ! confirm( axiomAdmin.i18n.confirmClear ) ) {
                return;
            }

            var btn = $( this );
            btn.prop( 'disabled', true ).html( '<span class="ax-spinner"></span>' );

            $.post( axiomAdmin.ajaxUrl, {
                action: 'axiom_clear_log',
                nonce:  axiomAdmin.nonce
            }, function( res ) {
                if ( res.success ) {
                    $( '#axiom-log-entries' ).html( '<div class="ax-log-empty">Log cleared.</div>' );
                    AxiomAdmin.showNotice( 'success', axiomAdmin.i18n.logCleared );
                }
            } ).always( function() {
                btn.prop( 'disabled', false ).text( 'Clear Log' );
            } );
        } );
    },

    /* ---- Refresh overview stats ---- */
    bindRefreshOverview: function() {
        if ( $( '#axiom-overview-stats' ).length === 0 ) {
            return;
        }

        $.post( axiomAdmin.ajaxUrl, {
            action: 'axiom_refresh_overview',
            nonce:  axiomAdmin.nonce
        }, function( res ) {
            if ( ! res.success ) {
                return;
            }
            var d = res.data;
            $( '#ax-stat-mode' ).text( d.mode.charAt( 0 ).toUpperCase() + d.mode.slice( 1 ) );
            $( '#ax-stat-plugins' ).text( d.total_plugins );
            $( '#ax-stat-manifest' ).text( d.has_manifest );
            $( '#ax-stat-nomanifest' ).text( d.no_manifest );
            $( '#ax-stat-log' ).text( d.log_count );
            $( '#ax-stat-blocked' ).text( d.blocked );
        } );
    }

};

$( document ).ready( function() {
    AxiomAdmin.init();
} );

} )( jQuery );
