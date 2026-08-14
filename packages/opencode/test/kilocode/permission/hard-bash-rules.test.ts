// kilocode_change - new file
import { expect, test } from "bun:test"
import { Permission } from "../../../src/permission"

const denyAllBash: Permission.Ruleset = [{ permission: "bash", pattern: "*", action: "deny" }]
const allowAllBash: Permission.Ruleset = [{ permission: "bash", pattern: "*", action: "allow" }]
const askAllBash: Permission.Ruleset = [{ permission: "bash", pattern: "*", action: "ask" }]

function classify(command: string) {
  return Permission.resolve("bash", command, denyAllBash).action
}

test("hard bash policy allows read-only/text-processing commands even when config denies all bash", () => {
  const readOnly = [
    "ls",
    "ls -la",
    "cat package.json",
    "head -n 20 file.txt",
    "tail -f log.txt",
    "grep -r foo src/",
    "rg foo",
    "find . -name '*.ts'",
    "wc -l file.txt",
    "pwd",
    "echo hello",
    "which node",
    "diff a.txt b.txt",
    "jq '.name' package.json",
    "awk '{print $1}' file.txt",
    "sed 's/a/b/' file.txt",
    "git status",
    "git log --oneline",
    "git diff HEAD~1",
    "git show HEAD",
    "git branch -a",
    "npm list",
  ]
  for (const command of readOnly) {
    const rule = Permission.resolve("bash", command, denyAllBash)
    expect([command, rule.action]).toEqual([command, "allow"])
    expect((rule as { source?: string }).source).toBe("hard")
  }
})

test("hard bash policy asks for build/execution and VCS-write commands even when config allows all bash", () => {
  const buildOrWrite = [
    "npm run build",
    "npm install",
    "npm ci",
    "bun run build",
    "bun install",
    "yarn install",
    "pnpm install",
    "make",
    "cargo build",
    "go build ./...",
    "tsc --noEmit",
    "python3 script.py",
    "node index.js",
    "docker build .",
    "git commit -m 'msg'",
    "git push origin main",
    "git pull",
    "git merge feature",
    "git add .",
    "git checkout -b feature",
    "git clone https://example.com/repo.git",
  ]
  for (const command of buildOrWrite) {
    const rule = Permission.resolve("bash", command, allowAllBash)
    expect([command, rule.action]).toEqual([command, "ask"])
    expect((rule as { source?: string }).source).toBe("hard")
  }
})

test("hard bash policy denies everything else, even when config allows all bash", () => {
  const catchAll = [
    "rm -rf /",
    "curl http://example.com",
    "wget http://example.com",
    "ssh user@example.com",
    "mkfs.ext4 /dev/sda1",
    "dd if=/dev/zero of=/dev/sda",
    ":(){ :|:& };:",
    "chmod 777 /etc/passwd",
    "sudo reboot",
  ]
  for (const command of catchAll) {
    const rule = Permission.resolve("bash", command, allowAllBash)
    expect([command, rule.action]).toEqual([command, "deny"])
    expect((rule as { source?: string }).source).toBe("hard")
  }
})

test("hard bash policy ignores config entirely for bash (allow/ask/deny config rules all get overridden)", () => {
  for (const ruleset of [denyAllBash, allowAllBash, askAllBash]) {
    expect(Permission.resolve("bash", "ls", ruleset).action).toBe("allow")
    expect(Permission.resolve("bash", "npm install", ruleset).action).toBe("ask")
    expect(Permission.resolve("bash", "curl http://example.com", ruleset).action).toBe("deny")
  }
})

test("hard bash policy does not affect other permissions", () => {
  const allowAllEdit: Permission.Ruleset = [{ permission: "edit", pattern: "*", action: "allow" }]
  expect(Permission.resolve("edit", "curl http://example.com", allowAllEdit).action).toBe("allow")
})

test("hard bash policy classification reference (documents current tiering)", () => {
  expect(classify("ls")).toBe("allow")
  expect(classify("npm install")).toBe("ask")
  expect(classify("curl http://example.com")).toBe("deny")
})
