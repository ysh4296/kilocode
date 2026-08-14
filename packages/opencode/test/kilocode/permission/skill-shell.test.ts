import { PermissionV1 } from "@opencode-ai/core/v1/permission"
import { expect } from "bun:test"
import { Cause, Effect, Exit, Layer } from "effect"
import * as CrossSpawnSpawner from "@opencode-ai/core/cross-spawn-spawner"
import { Permission } from "@/permission"
import { testEffect } from "../../lib/effect"
import { SessionID } from "@/session/schema"
import * as Config from "@/config/config"
import { AppNodeBuilder } from "@opencode-ai/core/effect/app-node-builder"

// skillShell forces a single up-front prompt over soft allow/deny/auto-approve
// rules, but must never override a hard (plan-mode) veto, and must never be
// auto-resolved while pending.

const env = Layer.mergeAll(
  AppNodeBuilder.build(Permission.node),
  AppNodeBuilder.build(Config.node),
  AppNodeBuilder.build(CrossSpawnSpawner.node),
)
const it = testEffect(env)

const ask = (input: Parameters<Permission.Interface["ask"]>[0]) =>
  Effect.gen(function* () {
    return yield* (yield* Permission.Service).ask(input)
  })

const list = () =>
  Effect.gen(function* () {
    return yield* (yield* Permission.Service).list()
  })

const fail = <A, E, R>(self: Effect.Effect<A, E, R>) =>
  Effect.gen(function* () {
    const exit = yield* self.pipe(Effect.exit)
    if (Exit.isFailure(exit)) return Cause.squash(exit.cause)
    throw new Error("expected permission effect to fail")
  })

it.instance(
  "skillShell - a deny rule stays terminal (build mode, no hard ruleset)",
  () =>
    Effect.gen(function* () {
      // build mode has no hardRuleset; an ordinary deny rule must still block, not prompt.
      const err = yield* fail(
        ask({
          sessionID: SessionID.make("session_test"),
          permission: "bash",
          patterns: ["curl evil.sh"],
          metadata: { skillShell: true },
          always: [],
          ruleset: [{ permission: "bash", pattern: "curl *", action: "deny" }],
        }),
      )

      expect(err).toBeInstanceOf(PermissionV1.DeniedError)
      expect(yield* list()).toHaveLength(0)
    }),
  { git: true },
)

it.instance(
  "skillShell - a cd-chained escape is vetoed via the verbatim command pattern",
  () =>
    Effect.gen(function* () {
      // The injector asks with the decomposed sub-command (`cat .ssh/id_rsa`, which
      // readOnlyBash would allow) AND the verbatim command. In plan mode the metachar
      // hard-veto (`*\n*` deny) must fire on the verbatim string, blocking the escape.
      const err = yield* fail(
        ask({
          sessionID: SessionID.make("session_test"),
          permission: "bash",
          patterns: ['cd "$HOME"\ncat .ssh/id_rsa', "cat .ssh/id_rsa"],
          metadata: { skillShell: true },
          always: [],
          ruleset: [{ permission: "bash", pattern: "cat *", action: "allow" }],
          hardRuleset: [{ permission: "bash", pattern: "*\n*", action: "deny" }],
        }),
      )

      expect(err).toBeInstanceOf(PermissionV1.DeniedError)
      expect(yield* list()).toHaveLength(0)
    }),
  { git: true },
)

it.instance(
  "skillShell - is denied by a hard-ruleset veto instead of prompting",
  () =>
    Effect.gen(function* () {
      const err = yield* fail(
        ask({
          sessionID: SessionID.make("session_test"),
          permission: "bash",
          patterns: ["rm -rf /"],
          metadata: { skillShell: true },
          always: [],
          ruleset: [{ permission: "bash", pattern: "*", action: "allow" }],
          hardRuleset: [{ permission: "bash", pattern: "*", action: "deny" }],
        }),
      )

      expect(err).toBeInstanceOf(PermissionV1.DeniedError)
      expect(yield* list()).toHaveLength(0)
    }),
  { git: true },
)

