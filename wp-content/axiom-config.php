<?php
/**
 * Axiom Kernel Configuration
 *
 * This file is loaded by the Axiom\Kernel\KernelConfig class during
 * WordPress bootstrap. All settings can also be set via wp-config.php
 * constants (e.g. define('AXIOM_MODE', 'enforce')).
 *
 * @package Axiom
 */

return [

	/*
	|--------------------------------------------------------------------------
	| Operating Mode
	|--------------------------------------------------------------------------
	|
	| 'enforce'  — Block all actions not in the manifest (production).
	| 'audit'    — Log violations but allow execution (staging).
	| 'learning' — Log everything, auto-generate manifests (onboarding).
	| 'disabled' — Kernel loads but no sandboxing applied.
	|
	*/
	'mode' => 'learning',

	/*
	|--------------------------------------------------------------------------
	| Learning Mode
	|--------------------------------------------------------------------------
	|
	| When enabled (and mode is 'audit' or 'learning'), the AutomatedProfiler
	| tracks all god-mode actions and generates draft blueprint.json files.
	|
	*/
	'learning_mode' => true,

	/*
	|--------------------------------------------------------------------------
	| Resource Limits
	|--------------------------------------------------------------------------
	|
	| Hard quotas enforced by the ResourceGovernor. If a plugin exceeds
	| these during a single hook callback, the isolate is terminated.
	|
	*/
	'cpu_limit_ms'    => 500,   // Max CPU time per hook callback (ms)
	'memory_limit_mb' => 64,    // Max memory per hook callback (MB)

	/*
	|--------------------------------------------------------------------------
	| SQL Strict Mode
	|--------------------------------------------------------------------------
	|
	| When true, the SQL lexer performs deeper validation (e.g., column-level).
	| When false, only table-level checks are applied.
	|
	*/
	'strict_sql' => false,

	/*
	|--------------------------------------------------------------------------
	| Performance Budget
	|--------------------------------------------------------------------------
	|
	| The maximum acceptable overhead (as a fraction) that Axiom may add to
	| each request. Default 0.15 = 15% performance tax ceiling.
	|
	*/
	'performance_budget_ms' => 50,

	/*
	|--------------------------------------------------------------------------
	| Trusted Plugins
	|--------------------------------------------------------------------------
	|
	| Plugins listed here bypass all manifest and capability checks.
	| Use sparingly — only for core WordPress components or first-party
	| plugins that are known-safe.
	|
	*/
	'trusted_plugins' => [],

	/*
	|--------------------------------------------------------------------------
	| Manifest Directory
	|--------------------------------------------------------------------------
	|
	| Directory where generated and manually-placed blueprint.json files
	| are stored. Defaults to wp-content/axiom/manifests/
	|
	*/
	'manifest_dir' => WP_CONTENT_DIR . '/axiom/manifests',

	/*
	|--------------------------------------------------------------------------
	| Log Level
	|--------------------------------------------------------------------------
	|
	| Minimum severity to write to the audit log.
	| Options: debug, info, warning, error, security
	|
	*/
	'log_level' => 'info',

	/*
	|--------------------------------------------------------------------------
	| WebAssembly Runtime
	|--------------------------------------------------------------------------
	|
	| Enable Wasm/V8 isolate execution for "modern" plugins that declare
	| "isolation": "wasm" in their blueprint.json. Requires ext-wasm or
	| ext-v8js to be installed.
	|
	*/
	'enable_wasm' => false,

];
