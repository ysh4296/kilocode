import { AppNodeBuilder } from "@opencode-ai/core/effect/app-node-builder"
import { expect, describe, afterAll } from "bun:test"
import fs from "fs/promises"
import path from "path"
import { Cause, Effect, Exit, Fiber, Layer } from "effect"
import { Bus } from "../../../src/bus"
import { Permission } from "../../../src/permission"
import { PermissionV1 } from "@opencode-ai/core/v1/permission"
import { SessionID } from "../../../src/session/schema"
import * as Config from "../../../src/config/config"
import { InstanceRuntime } from "../../../src/project/instance-runtime"
import { Global } from "@opencode-ai/core/global"
import * as CrossSpawnSpawner from "@opencode-ai/core/cross-spawn-spawner"
import { provideTmpdirInstance } from "../../fixture/fixture"
import { testEffect } from "../../lib/effect"

const bus = Bus.layer
const env = Layer.mergeAll(
  AppNodeBuilder.build(Permission.node),
  AppNodeBuilder.build(Config.node),
  bus,
  AppNodeBuilder.build(CrossSpawnSpawner.node),
)
const it = testEffect(env)

afterAll(async () => {
  const dir = Global.Path.config
  for (const file of ["kilo.jsonc", "kilo.json", "config.json", "opencode.json", "opencode.jsonc"]) {
    await fs.rm(path.join(dir, file), { force: true }).catch(() => {})
  }
  await Effect.runPromise(
    Config.Service.use((svc) => svc.invalidate()).pipe(Effect.scoped, Effect.provide(AppNodeBuilder.build(Config.node))),
  )
  await InstanceRuntime.disposeAllInstances()
})

const ask = (input: Parameters<Permission.Interface["ask"]>[0]) =>
  Effect.gen(function* () {
    const permission = yield* Permission.Service
    return yield* permission.ask(input)
  })

const reply = (input: Parameters<Permission.Interface["reply"]>[0]) =>
  Effect.gen(function* () {
    const permission = yield* Permission.Service
    return yield* permission.reply(input)
  })

const saveAlwaysRules = (input: Parameters<Permission.Interface["saveAlwaysRules"]>[0]) =>
  Effect.gen(function* () {
    const permission = yield* Permission.Service
    return yield* permission.saveAlwaysRules(input)
  })

const list = () =>
  Effect.gen(function* () {
    const permission = yield* Permission.Service
    return yield* permission.list()
  })

const waitForPending = (count: number) =>
  Effect.gen(function* () {
    const permission = yield* Permission.Service
    for (let i = 0; i < 100; i++) {
      const items = yield* permission.list()
      if (items.length >= count) return items
      yield* Effect.sleep("10 millis")
    }
    return yield* Effect.fail(new Error(`timed out waiting for ${count} pending permission request(s)`))
  })

function withDir(options: { git?: boolean } | undefined, self: (dir: string) => Effect.Effect<any, any, any>) {
  return provideTmpdirInstance(self, options)
}

const expectFailure = <E>(exit: Exit.Exit<unknown, E>, ErrorClass: new (...args: any[]) => unknown) => {
  expect(Exit.isFailure(exit)).toBe(true)
  if (Exit.isFailure(exit)) {
    expect(Cause.squash(exit.cause)).toBeInstanceOf(ErrorClass)
  }
}

describe("saveAlwaysRules", () => {
  it.live("fails for unknown request ID", () =>
    withDir({ git: true }, () =>
      Effect.gen(function* () {
        const exit = yield* saveAlwaysRules({
          requestID: PermissionV1.ID.make("permission_nonexistent"),
          approvedAlways: ["npm install"],
        }).pipe(Effect.exit)
        expect(Exit.isFailure(exit)).toBe(true)
        if (Exit.isFailure(exit)) {
          expect(Cause.squash(exit.cause)).toMatchObject({
            _tag: "Permission.NotFoundError",
            requestID: "permission_nonexistent",
          })
        }
      }),
    ),
  )

  it.live("accepts patterns from always array (non-bash tools)", () =>
    withDir({ git: true }, () =>
      Effect.gen(function* () {
        const asking = yield* ask({
          id: PermissionV1.ID.make("permission_nonbash"),
          sessionID: SessionID.make("session_test"),
          permission: "read",
          patterns: ["src/main.ts"],
          metadata: {},
          always: ["*"],
          ruleset: [],
        }).pipe(Effect.forkScoped)

        yield* waitForPending(1)
        // "*" is in always — should be accepted even without metadata.rules
        yield* saveAlwaysRules({
          requestID: PermissionV1.ID.make("permission_nonbash"),
          approvedAlways: ["*"],
        })
        yield* reply({ requestID: PermissionV1.ID.make("permission_nonbash"), reply: "once" })
        yield* Fiber.join(asking)

        // "*" wildcard should auto-allow any read
        const result = yield* ask({
          sessionID: SessionID.make("session_test"),
          permission: "read",
          patterns: ["any/file.ts"],
          metadata: {},
          always: [],
          ruleset: [],
        })
        expect(result.manual).toBe(false)
      }),
    ),
  )

  it.live("explicit external directory allows are not shadowed by ask plan broad denies", () =>
    withDir({ git: true }, (dir) =>
      Effect.gen(function* () {
        const root = path.resolve(path.dirname(dir), "legacy")
        const glob = path.join(root, "*")
        const ruleset: Permission.Ruleset = [
          { permission: "external_directory", pattern: "*", action: "ask" },
          { permission: "external_directory", pattern: glob, action: "allow" },
          { permission: "*", pattern: "*", action: "deny" },
        ]

        const result = yield* ask({
          sessionID: SessionID.make("session_test"),
          permission: "external_directory",
          patterns: [glob],
          metadata: { filepath: path.join(root, "main.ts"), parentDir: root },
          always: [glob],
          ruleset,
          hardRuleset: ruleset,
        })
        expect(result.manual).toBe(false)
      }),
    ),
  )

  it.live("saved external directory approvals survive ask plan hard rules", () =>
    withDir({ git: true }, (dir) =>
      Effect.gen(function* () {
        const root = path.resolve(path.dirname(dir), "legacy")
        const glob = path.join(root, "*")
        const asking = yield* ask({
          id: PermissionV1.ID.make("permission_external_seed"),
          sessionID: SessionID.make("session_test"),
          permission: "external_directory",
          patterns: [glob],
          metadata: { filepath: path.join(root, "main.ts"), parentDir: root },
          always: [glob],
          ruleset: [{ permission: "external_directory", pattern: "*", action: "ask" }],
        }).pipe(Effect.forkScoped)

        yield* waitForPending(1)
        yield* reply({ requestID: PermissionV1.ID.make("permission_external_seed"), reply: "always" })
        yield* Fiber.join(asking)

        const result = yield* ask({
          sessionID: SessionID.make("session_test"),
          permission: "external_directory",
          patterns: [glob],
          metadata: { filepath: path.join(root, "main.ts"), parentDir: root },
          always: [glob],
          ruleset: [
            { permission: "external_directory", pattern: "*", action: "ask" },
            { permission: "*", pattern: "*", action: "deny" },
          ],
          hardRuleset: [{ permission: "*", pattern: "*", action: "deny" }],
        })
        expect(result.manual).toBe(false)
      }),
    ),
  )

  it.live("explicit external directory denies still win over ask plan exceptions", () =>
    withDir({ git: true }, (dir) =>
      Effect.gen(function* () {
        const root = path.resolve(path.dirname(dir), "legacy")
        const glob = path.join(root, "*")
        const exit = yield* ask({
          sessionID: SessionID.make("session_test"),
          permission: "external_directory",
          patterns: [glob],
          metadata: { filepath: path.join(root, "main.ts"), parentDir: root },
          always: [glob],
          ruleset: [
            { permission: "external_directory", pattern: glob, action: "allow" },
            { permission: "external_directory", pattern: glob, action: "deny" },
            { permission: "*", pattern: "*", action: "deny" },
          ],
          hardRuleset: [
            { permission: "*", pattern: "*", action: "deny" },
            { permission: "external_directory", pattern: glob, action: "deny" },
          ],
        }).pipe(Effect.exit)
        expectFailure(exit, Permission.DeniedError)
      }),
    ),
  )

  it.live("does not auto-resolve the request being replied to", () =>
    withDir({ git: true }, () =>
      Effect.gen(function* () {
        const fiberA = yield* ask({
          id: PermissionV1.ID.make("permission_a4"),
          sessionID: SessionID.make("session_a"),
          permission: "bash",
          patterns: ["npm install"],
          metadata: { rules: ["npm *"] },
          always: ["npm *"],
          ruleset: [],
        }).pipe(Effect.forkScoped)

        yield* waitForPending(1)
        // Save rules but don't reply yet — the request itself should not be auto-resolved
        yield* saveAlwaysRules({
          requestID: PermissionV1.ID.make("permission_a4"),
          approvedAlways: ["npm *"],
        })

        // The original request should still be pending (needs explicit reply)
        const pending = yield* list()
        expect(pending.some((p) => String(p.id) === "permission_a4")).toBe(true)

        yield* reply({ requestID: PermissionV1.ID.make("permission_a4"), reply: "once" })
        yield* Fiber.join(fiberA)
      }),
    ),
  )
})
