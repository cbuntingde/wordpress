# Axiom: A Safer WordPress

> **Note:** This fork was an experiment to explore sandboxing WordPress plugins — keeping each plugin in its own protected space so it can't interfere with others, access unauthorized data, or crash your site. The core idea: every plugin gets a security manifest that defines exactly what it's allowed to do.

<div align="center">
  <img src="https://i.postimg.cc/05Jjb68p/Screenshot-2026-04-29-134203.png" alt="Axiom Dashboard" width="23%" />
  <img src="https://i.postimg.cc/66Gqy79C/Screenshot-2026-04-29-134210.png" alt="Axiom Settings" width="23%" />
  <img src="https://i.postimg.cc/2jByVqzF/Screenshot-2026-04-29-134217.png" alt="Axiom Plugins" width="23%" />
  <img src="https://i.postimg.cc/CMf5zZFC/Screenshot-2026-04-29-134224.png" alt="Axiom Audit Log" width="23%" />
</div>

Axiom is a security-focused version of WordPress that safely runs plugins in their own protected spaces so they can't interfere with each other, access things they shouldn't, or crash your site.

## The Problem It Solves

Normally, WordPress plugins can do anything they want. A simple spam-fighting plugin could theoretically read your user passwords, delete your content, or send your data somewhere else — and you would never know. Plugins can also clash with each other, causing confusing errors or blank screens.

Traditional security plugins try to spot bad behavior after it happens. Axiom prevents it before it starts.

## How It Works

### Every Plugin Gets a Security Manifest

Each plugin gets a manifest that lists exactly what it's allowed to do:

- **Which database tables it can read or write** — a comment plugin can read the comments table but not your user accounts
- **Which files it can access** — it can read its own files but not your theme files or other plugins
- **Which websites it can contact** — a spam checker can reach its own service but not a random server
- **Which WordPress events it can listen to** — it can watch for new comments but not for password changes

Manifests are stored in the WordPress options table and are checked at runtime by the security layer.

### Security Profiles

Each manifest follows one of four security profiles:

| Profile | What It Allows | Best For |
|---|---|---|
| **Restricted** | Minimal DB access (own options), own plugin files only, essential hooks | Unknown or untrusted plugins |
| **Standard** | Read all tables, write options and meta, common hooks, no exec | Most plugins (default) |
| **Permissive** | Full table access, filesystem write, all hooks and options, higher resource limits | Well-known, trusted plugins |
| **Custom** | Fine-tune every permission manually | Manual configuration |

### Learning Mode (Simple Onboarding)

Axiom has a **Learning Mode** that watches what a plugin does, takes notes, and automatically creates a manifest for you. You can then review and approve it before switching to full protection mode.

In learning mode, the profiler observes every SQL query, hook subscription, filesystem access, and outbound HTTP request a plugin makes, then generates a manifest from observed behavior.

### Hook-Level Isolation

Axiom tracks which plugin registered each callback using `WP_Hook` attribution. When a hook fires, the security system enters the plugin's isolate context so database and resource guards apply to everything the callback does. This means:

- Plugin A can't see or change Plugin B's settings
- Plugin A can't use functions or names that Plugin B is using
- If Plugin A crashes, Plugin B keeps running normally

### Resource Limits

Each manifest defines per-plugin time and memory limits. If a plugin exceeds its allowance:

- That plugin's execution is stopped
- The rest of your site keeps working
- An event is recorded in the audit log

No more "white screen of death" because one plugin went haywire.

## What This Means For You

| If you are... | Axiom helps by... |
|---|---|
| A site owner | Preventing one bad plugin from taking down your entire site |
| A developer | Giving you clear reports of what plugins are actually doing |
| An agency | Running multiple client sites with confidence that plugins won't clash |
| Anyone | Knowing that plugins only do what you approved them to do |

## Getting Started

### 1. Install Normally

Axiom works like regular WordPress. Upload it to your server, create your database, and run the installer.

### 2. Enable Learning Mode (Recommended First Step)

Add this line to your `wp-config.php` file:

```php
define('AXIOM_SECURITY_MODE', 'learning');
```

This tells Axiom to watch your plugins and take notes without blocking anything. Use your site normally and exercise all your plugins' features.

### 3. Review the Manifests

After using your site with Learning Mode enabled, check the manifests Axiom created. They are stored in the WordPress options table and visible under **Plugins → Plugin Security** in the admin dashboard. Each manifest is a simple list of what that plugin did while being watched.

### 4. Turn On Protection

When you're satisfied with the manifests, switch to enforcement mode:

```php
define('AXIOM_SECURITY_MODE', 'enforce');
```

Now Axiom will block any plugin activity that isn't on its approved list. Violations are recorded in the audit log so you can adjust the manifest.

### Step-by-Step Quick Start

```
1. Upload Axiom files to your server
2. Run the WordPress installer as usual
3. Add this to wp-config.php:
   define('AXIOM_SECURITY_MODE', 'learning');
4. Use your site for a few days
5. Review manifests under Plugins → Plugin Security in the admin
6. Update wp-config.php to:
   define('AXIOM_SECURITY_MODE', 'enforce');
7. Check the audit log under Plugins → Plugin Security → Audit Log
```

## Admin Dashboard

Axiom includes a full admin page under **Plugins → Plugin Security** in your WordPress admin. It has four tabs:

| Tab | What You Can Do |
|---|---|
| **Dashboard** | See security mode at a glance, active plugin counts, manifest coverage, and security events |
| **Plugins** | See which plugins have manifests, edit manifests inline, switch security profiles, regenerate from observed behavior |
| **Settings** | Switch modes (learning/audit/enforce/disabled) |
| **Audit Log** | Browse, filter by level, and search security events; clear the log |

The dashboard is available to administrators with the `manage_options` capability.

## What's Different From Regular WordPress

Axiom is still WordPress. All your themes, plugins, and content work the same way. The difference is underneath: a security layer that watches and controls what plugins can do.

**Nothing changes for your visitors.** They see the same site they always have. No slowdowns, no extra logins, no confusing messages.

**Nothing changes for your content.** Your posts, pages, media, and settings are stored in the same database format.

**Everything changes for security.** Plugins gain protection from each other, you gain visibility into what they're doing, and your site gains resilience against crashes and bad behavior.

## Files We Added

```
wp-includes/
  class-axiom-plugin-security.php    ← Core orchestrator, database guard,
                                         resource governor, and admin UI
  class-axiom-manifest.php           ← Manifest representation and validator
  class-axiom-audit-logger.php       ← Database-backed security event logging
  class-axiom-profiler.php           ← Learning mode behavior profiler
```

## Files We Changed

```
wp-settings.php                      ← Loads Axiom core classes and boots the
                                       security system during WordPress startup
wp-includes/class-wp-hook.php        ← Tracks which plugin registered each
                                       callback for hook-level isolation
```

## Switching Modes

| Mode | What It Does |
|---|---|
| `learning` | Watches everything, takes notes, generates manifests automatically |
| `audit` | Watches everything, takes notes, warns about unapproved actions |
| `enforce` | Blocks unapproved actions, records everything |
| `disabled` | Runs like regular WordPress (no security layer) |

You can change modes anytime by editing `wp-config.php` or via the **Plugin Security → Settings** admin page. No need to reinstall or restart anything.

## Trusted Plugins

To bypass security checks for specific plugins, set this in `wp-config.php`:

```php
define('AXIOM_SECURITY_TRUSTED', 'akismet,hello-dolly');
```

Trusted plugins are exempt from manifest validation. Use sparingly.

---

Axiom is WordPress, made safer.
