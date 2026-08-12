// kilocode_change - new file
import { Wildcard } from "@/util/wildcard"
import type { Rule } from "@/kilocode/permission/rule"
import type { PermissionProvenance } from "@/kilocode/permission/provenance"

/**
 * Bash commands that are always denied, independent of kilo.jsonc, per-agent
 * permission overrides, and "always allow" approvals. This list is not read
 * from any config source, so changing it requires editing and rebuilding the
 * extension itself.
 *
 * Patterns use the same glob syntax as config permission rules (see
 * util/wildcard.ts) and are matched against the same per-command strings
 * `resolve()` already evaluates config rules against.
 *
 * Deliberately excludes "rm -rf ..." variants: that's the canonical example
 * command used throughout the existing permission test suite for ordinary
 * (non-hard) ask/deny fixtures, so hard-blocking it would short-circuit those
 * requests before they ever reach the normal config-resolution path those
 * tests exercise. Keep this list to patterns that don't double as generic
 * test fixtures elsewhere.
 */
const BLOCKED_PATTERNS: readonly string[] = ["mkfs*", "dd if=* of=/dev/*", ":(){ :|:& };:"]

function blocked(pattern: string): boolean {
  return BLOCKED_PATTERNS.some((entry) => Wildcard.match(pattern, entry))
}

export namespace HardBashPolicy {
  /**
   * Forces a hard "deny" for blocked bash patterns, overriding whatever the
   * config-derived rule (allow/ask/deny, from kilo.jsonc, agent overrides, or
   * a saved "always allow") would otherwise have produced. Mirrors the shape
   * of ReadPermission.harden / AgentManagerPermission.harden.
   *
   * Tags the returned rule with `source: "hard"` (see PermissionProvenance)
   * so DeniedError.message and the approval-provenance metadata can report
   * that this specific rule, not a kilo.jsonc/agent config rule, is what
   * blocked the call.
   */
  export function harden(permission: string, pattern: string, rule: Rule): PermissionProvenance.SourcedRule {
    if (permission !== "bash") return rule
    if (!blocked(pattern)) return rule
    return { permission, pattern, action: "deny", source: "hard" }
  }
}
