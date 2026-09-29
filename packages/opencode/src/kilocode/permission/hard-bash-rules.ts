// kilocode_change - new file
import { Wildcard } from "@/util/wildcard"
import type { Rule } from "@/kilocode/permission/rule"
import type { PermissionProvenance } from "@/kilocode/permission/provenance"

/**
 * Hard-coded, config-immune classification for every bash command.
 * Independent of kilo.jsonc, per-agent permission overrides, and saved
 * "always allow" approvals — none of them can change the outcome here.
 * Changing this policy requires editing and rebuilding the extension itself.
 *
 * Three tiers, in priority order:
 *   1. ALLOW  - read-only inspection / text-processing commands. Auto-run.
 *   2. ASK    - build/execution and VCS-write commands. Prompt every time.
 *   3. DENY   - everything else. Catch-all default; not an explicit list.
 *
 * Patterns use the same glob syntax as config permission rules (see
 * util/wildcard.ts) and are matched against the same per-command strings
 * `resolve()` already evaluates config rules against.
 *
 * IMPORTANT: this is glob matching on the literal command text, the same
 * mechanism config permission rules use. It is not a sandbox. It catches the
 * obvious/direct forms of a command but not obfuscation (quoting, variable
 * expansion, encoding) or equivalent behavior reached through another tool
 * (e.g. a Python one-liner opening a socket). Treat it as a floor under
 * config, not a substitute for real process isolation (see also
 * packages/kilo-docs/pages/getting-started/settings/sandboxing.md).
 *
 * `sed`/`awk` are in ALLOW for their common read/filter usage, even though
 * `sed -i` can edit files in place — the glob can't distinguish the two
 * forms. Treat ALLOW as "usually read-only," not "provably safe."
 */
const ALLOW_PATTERNS: readonly string[] = [
  "ls *",
  "find *",
  "rg *",
  "jq *",
  "grep *",
  "cat *",
  "head *",
  "glob *",
  "less *",
  "wc *",
  "diff *",
  "echo *",
  "sed *",
  "awk *",
  "vi *",
  "cut *",
  "sort *",
  "uniq *",
  "tr *",
  "ag *",
  "cp *",
  "mv *",
  "mkdir *",
  "touch *",
  "tail *",
  "chmod *",
  "pwd *",
  "env *",
  "whoami *",
  "ll *",
  "la *",
  "tree *",
  "ps *",
  "top *",
  "df -h *",
  "du *",
  "df *",
  "pgrep *",
  "lsof *",
  "stat *",
  "file *",
  "realpath *",
  "more *",
  "git status *",
  "git diff *",
  "git log *",
  "git show *",
  "git branch --show-current *",
  "git ls-files *",
  "svn status *",
  "svn diff *",
  "svn log *",
  "svn info *",
  "dd *",
  "dir *",
  "type *",
  "where *",
  "findstr *",
  "cd *",
  "set *",
  "cls *",
  "ver *",
  "hostname *",
  "tasklist *",
  "systeminfo *",
  "ipconfig *",
  "fc *",
  "comp *",
  "attrib *",
  "copy *",
  "move *",
  "ren *",
  "rename *",
  "md *",
  "Get-ChildItem *",
  "Get-Content *",
  "Get-Location *",
  "Set-Location *",
  "Get-Item *",
  "Select-String *",
  "Get-Process *",
  "Test-Path *",
  "Resolve-Path *",
  "Measure-Object *",
  "Sort-Object *",
  "Select-Object *",
  "Where-Object *",
  "ForEach-Object *",
  "Write-Output *",
  "Write-Host *",
  "Copy-Item *",
  "Move-Item *",
  "New-Item *",
  "Rename-Item *",
]

const ASK_PATTERNS: readonly string[] = [
  "rmdir *",
  "rm *",
  "curl *",
  "wget *",
  "mvn compile *",
  "mvn package *",
  "mvn test *",
  "mvn dependency:tree *",
  "gradle build *",
  "gradle test *",
  "javac *",
  "java -jar *",
  "java -cp *",
  "node *",
  "npm *",
  "yarn *",
  "pnpm *",
  "npx *",
  "bun *",
  "pip *",
  "uv *",
  "python *",
  "python3 *",
  "pytest *",
  "pyright-langserver *",
  "svn add *",
  "svn commit *",
  "svn update *",
  "kill *",
  "pkill *",
  "nohup *",
  "sh *",
  "bash *",
  "tail -f *",
  "zsh *",
  "tsc *",
  "eslint *",
  "prettier *",
  "vite *",
  "vitest *",
  "jest *",
  "storybook *",
  "webpack *",
  "rollup *",
  "parcel *",
  "turbo *",
  "nx *",
  "git add *",
  "git commit *",
  "git fetch *",
  "git pull *",
  "jdtls *",
  "eclipse.jdt.ls *",
  "rd *",
  "del *",
  "erase *",
  "taskkill *",
  "Remove-Item *",
]

function classify(pattern: string): "allow" | "ask" | "deny" {
  if (ALLOW_PATTERNS.some((entry) => Wildcard.match(pattern, entry))) return "allow"
  if (ASK_PATTERNS.some((entry) => Wildcard.match(pattern, entry))) return "ask"
  return "deny"
}

export namespace HardBashPolicy {
  /**
   * Forces every bash pattern into the ALLOW/ASK/DENY classification above,
   * overriding whatever the config-derived rule (from kilo.jsonc, agent
   * overrides, or a saved "always allow") would otherwise have produced.
   * Mirrors the shape of ReadPermission.harden / AgentManagerPermission.harden.
   *
   * Tags the returned rule with `source: "hard"` (see PermissionProvenance)
   * so DeniedError.message and the approval-provenance metadata can report
   * that this policy, not a kilo.jsonc/agent config rule, decided the call.
   */
  export function harden(permission: string, pattern: string, rule: Rule): PermissionProvenance.SourcedRule {
    if (permission !== "bash") return rule
    return { permission, pattern, action: classify(pattern), source: "hard" }
  }
}
