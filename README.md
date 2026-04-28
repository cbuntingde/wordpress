# Axiom: A Safer WordPress

Axiom is a security-focused version of WordPress that safely runs plugins
in their own protected spaces so they can't interfere with each other, access
things they shouldn't, or crash your site.

## The Problem It Solves

Normally, WordPress plugins can do anything they want. A simple spam-fighting
plugin could theoretically read your user passwords, delete your content, or
send your data somewhere else — and you would never know. Plugins can also
clash with each other, causing confusing errors or blank screens.

Traditional security plugins try to spot bad behavior after it happens.
Axiom prevents it before it starts.

## How It Works (Plain English)

### Every Plugin Gets a Permission Slip

Each plugin gets a simple permission slip (called a **blueprint**) that lists
exactly what it's allowed to do:

- **Which database tables it can read or write** — for example, a comment
  plugin can read the comments table but not your user accounts
- **Which files it can access** — it can read its own files but not your
  theme files or other plugins
- **Which websites it can contact** — a spam checker can reach its own
  service but not a random server you didn't authorize
- **Which WordPress events it can listen to** — it can watch for new
  comments but not for password changes

### The Watchdog System

Axiom assigns every plugin a personal watchdog that:

1. Checks the permission slip every time the plugin tries to do something
2. Stops the action if it's not on the approved list
3. Records everything so you can review it later

### Learning Mode (Simple Onboarding)

Most plugins don't come with a permission slip. Axiom has a **Learning
Mode** that watches what a plugin does, takes notes, and automatically
creates a permission slip for you. You can then review and approve it before
switching to full protection mode.

Think of it like this: you let the plugin move around your house while you
watch, write down everywhere it goes and what it touches, then lock the doors
behind it so it can only go where you approved.

### Plugins Can't Hurt Each Other

Axiom runs each plugin in its own workspace. This means:

- Plugin A can't see or change Plugin B's settings
- Plugin A can't use functions or names that Plugin B is using
- If Plugin A crashes, Plugin B keeps running normally

This is especially helpful when two plugins accidentally try to use the same
name for something — Axiom keeps them separated so they coexist peacefully.

### No Plugin Can Hog Resources

Sometimes a plugin goes into a loop or tries to use too much memory. Axiom
sets a **time limit** and a **memory limit** for every plugin. If a plugin
exceeds its allowance:

- That plugin is gently stopped
- The rest of your site keeps working perfectly
- An entry is recorded so you know which plugin caused the trouble

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

Axiom works like regular WordPress. Upload it to your server, create your
database, and run the installer — the same as always.

### 2. Enable Learning Mode (Recommended First Step)

Add this line to your `wp-config.php` file:

```php
define('AXIOM_MODE', 'learning');
```

This tells Axiom to watch your plugins and take notes without blocking
anything. Use your site normally and exercise all your plugins' features.

### 3. Review the Permission Slips

After using your site for a while with Learning Mode enabled, check the
permission slips Axiom created for you:

```
wp-content/axiom/manifests/
```

Each file is named after a plugin. Open one in a text editor — it's a simple
list of what that plugin did while being watched.

### 4. Turn On Protection

When you're satisfied with the permission slips, switch to protection mode:

```php
define('AXIOM_MODE', 'enforce');
```

Now Axiom will block any plugin activity that isn't on its approved list.
If something gets blocked, it's recorded in the audit log so you can adjust
the permission slip.

### Step-by-Step Quick Start

```
1. Upload Axiom files to your server
2. Run the WordPress installer as usual
3. Add this to wp-config.php:
   define('AXIOM_MODE', 'learning');
4. Use your site for a few days
5. Review the permission slips in wp-content/axiom/manifests/
6. Update wp-config.php to:
   define('AXIOM_MODE', 'enforce');
7. Check the audit log at wp-content/axiom/audit-*.log if anything breaks
```

## What's Different From Regular WordPress

Axiom is still WordPress. All your themes, plugins, and content work the
same way. The difference is underneath: a security layer that watches and
controls what plugins can do.

**Nothing changes for your visitors.** They see the same site they always
have. No slowdowns, no extra logins, no confusing messages.

**Nothing changes for your content.** Your posts, pages, media, and settings
are stored in the same database format.

**Everything changes for security.** Plugins gain protection from each other,
you gain visibility into what they're doing, and your site gains resilience
against crashes and bad behavior.

## Files We Added

```
wp-content/axiom/                  ← The security system
  bootstrap.php                    ← Starts everything up
  axiom-config.php                 ← Your control panel for security settings
  Kernel/                          ← The brain of the system
  Bridge/                          ← The connection layer that watches plugins
  Security/                        ← The permission checker  
  Profiler/                        ← The learning mode and logging system
  manifests/                       ← Your plugin permission slips go here
SECURITY.md                        ← Detailed security documentation (technical)
```

## Files We Changed

```
wp-settings.php                    ← Five small changes to start the security
                                     system at the right time during startup
```

## Where To Find The Audit Log

```
wp-content/axiom/audit-2026-04-28.log    ← Organized by date
```

Each line is a record of a security event. If you see entries marked
"security" or "warning" after switching to protection mode, it means a
plugin tried to do something not on its permission slip.

## Switching Modes

| Mode | What It Does |
|---|---|
| `learning` | Watches everything, takes notes, generates permission slips automatically |
| `audit` | Watches everything, takes notes, but also warns you about unapproved actions |
| `enforce` | Blocks unapproved actions, records everything |
| `disabled` | Runs like regular WordPress (no security layer) |

You can change modes anytime by editing `wp-config.php`. No need to
reinstall or restart anything.

## Limits You Can Set

All of these go in your `wp-config.php` file:

```php
define('AXIOM_CPU_LIMIT_MS', 500);       // Time limit per plugin action (milliseconds)
define('AXIOM_MEMORY_LIMIT_MB', 64);      // Memory limit per plugin action (megabytes)
define('AXIOM_STRICT_SQL', true);         // Extra-strict database checking
define('AXIOM_LOG_LEVEL', 'security');     // How much detail to record
```

## Need Help?

Check the `SECURITY.md` file for the complete technical documentation.

---

Axiom is WordPress, made safer.
