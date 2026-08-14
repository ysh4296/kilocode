// kilocode_change - new file
import { LayerNode } from "@opencode-ai/core/effect/layer-node"
import { SessionProjector } from "@opencode-ai/core/session/projector"
import { expect } from "bun:test"
import { Cause, Effect, Exit, Fiber } from "effect"
import { CrossSpawnSpawner } from "@opencode-ai/core/cross-spawn-spawner"
import { PermissionV1 } from "@opencode-ai/core/v1/permission"
import { Bus } from "../../../src/bus"
import * as Config from "../../../src/config/config"
import { Permission } from "../../../src/permission"
import { Session } from "../../../src/session/session"
import { testEffect } from "../../lib/effect"

const env = LayerNode.compile(
  LayerNode.group([Permission.node, Config.node, Session.node, SessionProjector.node, Bus.node, CrossSpawnSpawner.node]),
)
const it = testEffect(env)

it.instance(
  "denies a blocked command through Permission.Service.ask() even with an allow-all bash config",
  () =>
    Effect.gen(function* () {
      const permission = yield* Permission.Service
      const sessions = yield* Session.Service
      const session = yield* sessions.create({})

      const exit = yield* permission
        .ask({
          sessionID: session.id,
          permission: "bash",
          patterns: ["mkfs.ext4 /dev/sda1"],
          metadata: {},
          always: [],
          ruleset: [{ permission: "bash", pattern: "*", action: "allow" }],
        })
        .pipe(Effect.exit)

      expect(Exit.isFailure(exit)).toBe(true)
      if (Exit.isFailure(exit)) {
        const error = Cause.squash(exit.cause)
        expect(error).toBeInstanceOf(Permission.DeniedError)
        expect((error as Permission.DeniedError).message).toContain("AIP Platform 팀 내부 규정")
      }
    }),
  { git: true },
)

it.instance(
  "auto-approves read-only commands even under a deny-all config",
  () =>
    Effect.gen(function* () {
      const permission = yield* Permission.Service
      const sessions = yield* Session.Service
      const session = yield* sessions.create({})

      const outcome = yield* permission.ask({
        sessionID: session.id,
        permission: "bash",
        patterns: ["git status"],
        metadata: {},
        always: [],
        ruleset: [{ permission: "bash", pattern: "*", action: "deny" }],
      })

      expect(outcome.manual).toBe(false)
    }),
  { git: true },
)

it.instance(
  "still prompts for build/VCS-write commands even under an allow-all config",
  () =>
    Effect.gen(function* () {
      const permission = yield* Permission.Service
      const sessions = yield* Session.Service
      const session = yield* sessions.create({})

      const id = PermissionV1.ID.make("permission_hard_ask_tier")
      const pending = yield* permission
        .ask({
          id,
          sessionID: session.id,
          permission: "bash",
          patterns: ["npm install"],
          metadata: {},
          always: [],
          ruleset: [{ permission: "bash", pattern: "*", action: "allow" }],
        })
        .pipe(Effect.forkScoped)

      // give the ask() fiber a moment to register the pending request
      for (let i = 0; i < 100; i++) {
        const items = yield* permission.list()
        if (items.some((item) => item.id === id)) break
        yield* Effect.sleep("10 millis")
      }
      expect((yield* permission.list()).some((item) => item.id === id)).toBe(true)

      yield* permission.reply({ requestID: id, reply: "once" })
      const outcome = yield* Fiber.join(pending)
      expect(outcome.manual).toBe(true)
    }),
  { git: true },
)
