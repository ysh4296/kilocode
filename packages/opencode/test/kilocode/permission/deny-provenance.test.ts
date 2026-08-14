import { describe, expect, test } from "bun:test"
import { PermissionProvenance } from "../../../src/kilocode/permission/provenance"

describe("Permission.ask denial provenance", () => {
  test("a denial with no specific rule (e.g. a headless-subagent policy denial) is still reported as denied, not as an ambiguous default approval", () => {
    // Some denial paths don't carry a specific rule -- Permission.ask's headless-subagent policy
    // denial, for instance, still sets `ruleset` to the plain deny-permission subset (an array,
    // with no `.action`/`.pattern` of its own). classify({ rule: undefined }) reports
    // { source: "default" } -- the same shape the *approval* fallback produces for "no rule
    // matched" -- so without a synthesized deny rule, a refusal would render (and export) as an
    // auto-approval.
    const approval = PermissionProvenance.classifyDenial({
      ruleset: [{ permission: "bash", pattern: "*", action: "ask" as const }],
      permission: "bash",
      patterns: ["rm -rf /"],
      agent: "build",
      origins: undefined,
    })
    expect(approval.rule?.action).toBe("deny")
    expect(approval.rule).toEqual({ permission: "bash", pattern: "rm -rf /", action: "deny" })
  })
})
