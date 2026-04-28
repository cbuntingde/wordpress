# Project Axiom-WP: Zero-Trust Security Architecture

## 1. Zero-Trust Principles

Every plugin is treated as **untrusted by default**, regardless of its source or
reputation. Trust is not inherited from the WordPress ecosystem — it must be
**explicitly declared** in a `blueprint.json` manifest and **enforced at runtime**
by the Axiom Kernel.

| Principle | Application |
|---|---|
| **Verify explicitly** | No capability is assumed. Every `$wpdb->query()`, `wp_remote_get()`, and `add_action()` is checked against the manifest. |
| **Least privilege** | Plugins receive only the permissions their manifest declares. Wildcard patterns (`wp_*`) are allowed but audited. |
| **Assume breach** | The Kernel isolates every plugin at runtime. A compromised plugin cannot read another plugin's data, list files outside its scope, or execute system commands — even if WordPress itself is fully compromised. |

---

## 2. Security Boundaries

### 2.1 Database Boundary

```
Untrusted Plugin                Axiom Proxy_WPDB                 Real MySQL
       │                              │                              │
       │  $wpdb->get_results(...)      │                              │
       │─────────────────────────────> │                              │
       │                              │  ManifestValidator.check()   │
       │                              │  ─────────────────────────>  │
       │                              │  SQL Lexer (tables, ops)     │
       │                              │  ─────────────────────────>  │
       │                              │                              │
       │  ⚠ Blocked (no manifest)     │                              │
       │ <──────────────────────────── │                              │
       │                              │  ✓ Permitted                 │
       │                              │ ───────────────────────────> │
       │  Results (filtered)          │ <─────────────────────────── │
       │ <──────────────────────────── │                              │
```

- Every SQL statement is **lexed** to extract table names and operation type.
- The operation (`SELECT` → `read`, `INSERT` → `write`, `DROP` → `alter`) is
  validated against `db:{operation}:{table}` in the manifest.
- **Enforce mode:** violating queries return `false` with `$wpdb->last_error` set.
- **Audit mode:** queries proceed but are logged.
- **Learning mode:** queries proceed and are recorded for manifest generation.

### 2.2 Filesystem Boundary

| Access Type | Enforcement |
|---|---|
| `fopen()`, `file_get_contents()` | Allowed only for paths matching `filesystem:read:{pattern}` |
| `fwrite()`, `file_put_contents()` | Allowed only for paths matching `filesystem:write:{pattern}` |
| `include`/`require` | Unrestricted (controlled by namespace isolation) |

Filesystem checks are applied via the `ManifestValidator` on opt-in hooks.
The `NamespaceWrapper` stream protocol provides additional defense by rewriting
included files into isolated namespaces.

### 2.3 Network Boundary

- Outbound HTTP requests (`wp_remote_get`, `wp_remote_post`, etc.) are checked
  against `network:outbound:{domain}` patterns in the manifest.
- Wildcard patterns (e.g. `*.akismet.com`) are supported.
- DNS rebinding protection: the domain is validated at request time, not cached.

### 2.4 Hook (API) Boundary

- Plugins may only subscribe to hooks listed in `wp:hooks:read_only` or
  `wp:hooks:write` in their manifest.
- The **HookMarshaller** wraps every callback invocation:
  1. Resolves the owning plugin from the callback registry.
  2. Enters the plugin's isolate context.
  3. Sanitizes hook arguments (passwords stripped in enforce mode).
  4. Monitors CPU and memory via `ResourceGovernor`.
  5. Catches exceptions gracefully — no plugin crash takes down the site.
- Hook callbacks are serialized by plugin: plugin A's callbacks run in
  plugin A's isolate. Global state mutations are captured and sync'd back
  only through the `StateSnapshotEngine`.

---

## 3. The Manifest System (`blueprint.json`)

### 3.1 Manifest Location (searched in order)

1. `<plugin-root>/blueprint.json`
2. `wp-content/axiom/manifests/<slug>.json`

### 3.2 Manifest Schema

```jsonc
{
  // REQUIRED: Unique plugin identifier (matches the plugin slug)
  "id": "akismet",

  // REQUIRED: Schema version (currently "1.0")
  "manifest_version": "1.0",

  // Isolation mode: "namespace" (legacy) or "wasm" (modern)
  "isolation": "namespace",

  // REQUIRED: Permissions block
  "permissions": {
    // Database access: operation → list of table patterns (fnmatch)
    "db": {
      "read":   ["wp_comments", "wp_options"],
      "write":  ["wp_options"],
      "delete": [],
      "alter":  []
    },

    // Filesystem access: "operation:glob_pattern"
    "filesystem": [
      "read:wp-content/plugins/akismet/*"
    ],

    // Network access
    "network": {
      "outbound": ["rest.akismet.com"]
    },

    // WordPress API access
    "wp": {
      "hooks": {
        "read_only": ["init", "comment_*"],
        "write":     ["init"]
      },
      "options": {
        "read":  ["akismet_*"],
        "write": ["akismet_*"]
      },
      "users": {
        "read": ["read"]
      }
    },

    // System access (shell execution, etc.)
    "system": []
  },

  // Resource quotas (per-hook-callback)
  "resource_limits": {
    "cpu_ms": 200,
    "memory_mb": 32
  }
}
```

### 3.3 Manifest Generation

In **Learning Mode**, the `AutomatedProfiler` watches every plugin action:

1. All SQL queries are logged → table patterns extracted.
2. All filesystem accesses are logged → path patterns extracted.
3. All hook subscriptions are logged → hook patterns extracted.
4. All outbound HTTP requests are logged → domain patterns extracted.
5. A draft `blueprint.json` is written to `wp-content/axiom/manifests/<slug>.json`.

The generated manifest is a **starting point** — the site administrator should
review and tighten permissions before switching to enforce mode.

---

## 4. Threat Model

### 4.1 In-Scope Threats

| Threat | Mitigation |
|---|---|
| SQL injection via plugin | SQL lexer validates target tables against manifest; all actual query execution still uses `$wpdb->prepare()` internally |
| Plugin-to-plugin data leakage | `StateSnapshotEngine` isolates global state per plugin; `NamespaceWrapper` prevents class/function collisions |
| Resource exhaustion (CPU/memory bomb) | `ResourceGovernor` with `register_tick_function` — terminates isolate at configured limits |
| File disclosure (arbitrary read) | `ManifestValidator` checks filesystem paths against `filesystem:read` patterns |
| Remote code execution via SSRF | Network manifest restricts outbound domains |
| Supply-chain (compromised plugin) | Manifest acts as an allowlist; compromised plugin cannot exceed declared capabilities |

### 4.2 Out-of-Scope Threats

| Threat | Reason |
|---|---|
| PHP-level sandbox escape | A NamespaceWrapper isolate is still PHP — a motivated attacker with code exec in the isolate can theoretically escape. Use Wasm isolates for true sandboxing. |
| Side-channel timing attacks | Not addressed at this layer. |
| WordPress core vulnerabilities | Core is trusted. The Kernel is part of core. |

---

## 5. Configuration Security

### 5.1 Recommended Production Settings

```php
// wp-config.php
define('AXIOM_MODE', 'enforce');
define('AXIOM_LEARNING_MODE', false);
define('AXIOM_CPU_LIMIT_MS', 500);
define('AXIOM_MEMORY_LIMIT_MB', 64);
define('AXIOM_STRICT_SQL', true);
define('AXIOM_LOG_LEVEL', 'security');
define('AXIOM_TRUSTED_PLUGINS', ''); // No trusted exceptions
```

### 5.2 Recommended Onboarding Flow

1. **Learning mode** — Install plugins, exercise all features.
2. **Review** — Examine generated manifests in `wp-content/axiom/manifests/`.
3. **Tighten** — Remove wildcard patterns, narrow table lists.
4. **Audit mode** — Run in staging with `AXIOM_MODE=audit`.
5. **Enforce** — Switch to production with `AXIOM_MODE=enforce`.

---

## 6. Audit Trail

All security events are written to structured JSON log files at:
`wp-content/axiom/audit-YYYY-MM-DD.log`

Each log entry contains:
```json
{
  "timestamp": "2026-04-28T12:00:00.000000Z",
  "level": "security",
  "message": "SQL query blocked",
  "context": {
    "plugin": "some-plugin",
    "table": "wp_users",
    "operation": "read",
    "sql": "SELECT * FROM wp_users"
  },
  "memory": 8388608,
  "request": "/wp-admin/admin.php?page=some-page"
}
```

Log levels:
- `debug` — Verbose diagnostics (not written to file by default)
- `info` — Normal operational events (kernel init, isolate enter/leave)
- `warning` — Manifest violations in audit/learning mode
- `error` — Resource exhaustion, plugin crashes
- `security` — Blocked actions in enforce mode (always logged)
- `learning` — God-mode actions recorded during learning mode

---

## 7. Performance Budget

The Axiom Kernel targets a **maximum 15% overhead** on standard WordPress
requests. This budget is allocated as follows:

| Component | Budget |
|---|---|
| SQL lexer + manifest check | ~3% per query |
| HookMarshaller dispatch | ~5% per callback |
| ResourceGovernor tick | ~2% (negligible when idle) |
| StateSnapshot capture | ~3% per context switch |
| AuditLogger I/O | ~2% (buffered, flushed at shutdown) |

To stay within budget:
- The SQL lexer uses lightweight regex patterns, not AST parsing.
- `ManifestValidator` caches parsed manifests in memory.
- `AuditLogger` buffers entries and flushes in a single write at shutdown.
- `ResourceGovernor` only samples memory on ticks (not every line).

---

## 8. Incident Response

If a plugin violates its manifest in **enforce mode**:

1. **Database**: The query returns `false`. `$wpdb->last_error` is set to
   `"Blocked by Axiom security policy."`.
2. **Hooks**: The callback is skipped. A `ResourceExhaustedException` is
   caught by the HookMarshaller. Execution continues with the next plugin.
3. **Logging**: A `security`-level event is written to the audit log.
4. **Admin notice**: If `WP_DEBUG` is enabled, an admin notice is displayed.

The violating plugin is **not deactivated** — it continues to run, but with
reduced capabilities. This ensures the site remains operational while the
administrator reviews and updates the manifest.

---

## 9. Testing Security

```bash
# Run Axiom unit tests
phpunit wp-content/axiom/tests/

# Verify plugin isolation
# Expected: akismet cannot query wp_users unless declared
php -r "
  define('WP_USE_THEMES', false);
  require 'wp-blog-header.php';
  \$wpdb->query('SELECT * FROM wp_users');
  // Blocked by Proxy_WPDB in enforce mode
"

# Audit log inspection
tail -f wp-content/axiom/audit-*.log | grep '"level":"security"'
```

---

## 10. Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                     WordPress Request                            │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│                     wp-settings.php                               │
│                                                                   │
│  1. Load Axiom autoloader                                         │
│  2. Load WordPress core                                           │
│  3. Init Axiom Kernel (installs Proxy_WPDB, HookMarshaller)      │
│  4. Load Axiom-registered plugins                                 │
│  5. do_action('plugins_loaded') → HookMarshaller                  │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Axiom Kernel                                    │
│                                                                   │
│  ┌──────────────┐  ┌─────────────┐  ┌────────────────────────┐   │
│  │ Manifest     │  │ Database    │  │ StateSnapshot           │   │
│  │ Validator    │  │ Proxy       │  │ Engine                  │   │
│  │ (CBS checks) │  │ (SQL lexer) │  │ (global sync-back)      │   │
│  └──────────────┘  └─────────────┘  └────────────────────────┘   │
│                                                                   │
│  ┌──────────────┐  ┌─────────────┐  ┌────────────────────────┐   │
│  │ Hook         │  │ Resource    │  │ Isolate                 │   │
│  │ Marshaller   │  │ Governor    │  │ Manager                 │   │
│  │ (ctx switch) │  │ (CPU/mem)   │  │ (Wasm/Namespace)        │   │
│  └──────────────┘  └─────────────┘  └────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐     │
│  │ Automated Profiler (Learning Mode)                        │     │
│  │ Watches → Logs → Generates blueprint.json                 │     │
│  └──────────────────────────────────────────────────────────┘     │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Plugin Isolates                                 │
│                                                                   │
│  ┌──────────────┐  ┌─────────────┐  ┌────────────────────────┐   │
│  │ Plugin A     │  │ Plugin B    │  │ Plugin C (Wasm)        │   │
│  │ (Namespace)  │  │ (Namespace) │  │ (V8 Isolate)           │   │
│  │ Manifest: A  │  │ Manifest: B │  │ Manifest: C            │   │
│  │ Budget: 200ms│  │ Budget: 500ms│  │ Budget: 100ms          │   │
│  │ Tables: comm │  │ Tables: posts│  │ Tables: options        │   │
│  └──────────────┘  └─────────────┘  └────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

---

*This document describes the security architecture of Project Axiom-WP,
a WordPress fork with kernel-level plugin sandboxing.*
