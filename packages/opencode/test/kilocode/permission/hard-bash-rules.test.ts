// kilocode_change - new file
import { expect, test } from "bun:test"
import { Permission } from "../../../src/permission"

const allowAllBash: Permission.Ruleset = [{ permission: "bash", pattern: "*", action: "allow" }]
const dangerousCommand = "mkfs.ext4 /dev/sda1"

test("hard bash policy denies a blocked command even when config explicitly allows all bash", () => {
  const rule = Permission.resolve("bash", dangerousCommand, allowAllBash)
  expect(rule.action).toBe("deny")
  expect((rule as { source?: string }).source).toBe("hard")
})

test("hard bash policy denies a blocked pattern even when it was saved as an always-allow override", () => {
  const askOnly: Permission.Ruleset = [{ permission: "bash", pattern: "*", action: "ask" }]
  const approved: Permission.Ruleset = [{ permission: "bash", pattern: dangerousCommand, action: "allow" }]
  expect(Permission.resolve("bash", dangerousCommand, askOnly, approved).action).toBe("deny")
})

test("hard bash policy leaves unrelated bash commands to normal config rules", () => {
  expect(Permission.resolve("bash", "npm install", allowAllBash).action).toBe("allow")
  const denyAllBash: Permission.Ruleset = [{ permission: "bash", pattern: "*", action: "deny" }]
  expect(Permission.resolve("bash", "npm install", denyAllBash).action).toBe("deny")
})

test("hard bash policy only applies to the bash permission", () => {
  const allowAllEdit: Permission.Ruleset = [{ permission: "edit", pattern: "*", action: "allow" }]
  expect(Permission.resolve("edit", dangerousCommand, allowAllEdit).action).toBe("allow")
})

test("hard bash policy matches each known-dangerous pattern", () => {
  const dangerous = ["mkfs.ext4 /dev/sda1", "mkfs.vfat /dev/sdb1", "dd if=/dev/zero of=/dev/sda", ":(){ :|:& };:"]
  for (const command of dangerous) {
    expect(Permission.resolve("bash", command, allowAllBash).action).toBe("deny")
  }
})

test("hard bash policy does not block rm -rf (kept out to avoid colliding with existing test fixtures)", () => {
  expect(Permission.resolve("bash", "rm -rf /", allowAllBash).action).toBe("allow")
})
