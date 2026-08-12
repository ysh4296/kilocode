// kilocode_change - new file
import { LayerNode } from "@opencode-ai/core/effect/layer-node"
import { SessionProjector } from "@opencode-ai/core/session/projector"
import { expect } from "bun:test"
import { Cause, Effect, Exit } from "effect"
import { CrossSpawnSpawner } from "@opencode-ai/core/cross-spawn-spawner"
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
        expect((error as Permission.DeniedError).message).toContain("built-in, non-configurable Kilo policy")
      }
    }),
  { git: true },
)

it.instance(
  "still auto-approves ordinary bash commands under the same allow-all config",
  () =>
    Effect.gen(function* () {
      const permission = yield* Permission.Service
      const sessions = yield* Session.Service
      const session = yield* sessions.create({})

      const outcome = yield* permission.ask({
        sessionID: session.id,
        permission: "bash",
        patterns: ["npm install"],
        metadata: {},
        always: [],
        ruleset: [{ permission: "bash", pattern: "*", action: "allow" }],
      })

      expect(outcome.manual).toBe(false)
    }),
  { git: true },
)
