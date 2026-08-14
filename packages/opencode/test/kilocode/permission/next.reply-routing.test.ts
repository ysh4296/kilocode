import { AppNodeBuilder } from "@opencode-ai/core/effect/app-node-builder"
import { expect, describe, afterAll } from "bun:test"
import fs from "fs/promises"
import path from "path"
import { Cause, Effect, Exit, Layer } from "effect"
import { Bus } from "../../../src/bus"
import { Permission } from "../../../src/permission"
import { PermissionV1 } from "@opencode-ai/core/v1/permission"
import * as Config from "../../../src/config/config"
import { InstanceRuntime } from "../../../src/project/instance-runtime"
import { Global } from "@opencode-ai/core/global"
import * as CrossSpawnSpawner from "@opencode-ai/core/cross-spawn-spawner"
import { provideTmpdirInstance, testInstanceStoreLayer } from "../../fixture/fixture"
import { testEffect } from "../../lib/effect"

const bus = Bus.layer
const env = Layer.mergeAll(
  AppNodeBuilder.build(Permission.node),
  bus,
  AppNodeBuilder.build(CrossSpawnSpawner.node),
  testInstanceStoreLayer,
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

const reply = (input: Parameters<Permission.Interface["reply"]>[0]) =>
  Effect.gen(function* () {
    const permission = yield* Permission.Service
    return yield* permission.reply(input)
  })

const expectNotFound = (exit: Exit.Exit<void, Permission.NotFoundError>, requestID: PermissionV1.ID) => {
  expect(Exit.isFailure(exit)).toBe(true)
  if (Exit.isFailure(exit)) {
    expect(Cause.squash(exit.cause)).toMatchObject({
      _tag: "Permission.NotFoundError",
      requestID,
    })
  }
}

describe("reply routing", () => {
  it.live("fails when requestID is not pending", () =>
    provideTmpdirInstance(
      () =>
        Effect.gen(function* () {
          const requestID = PermissionV1.ID.make("permission_unknown")
          const exit = yield* reply({ requestID, reply: "once" }).pipe(Effect.exit)
          expectNotFound(exit, requestID)
        }),
      { git: true },
    ),
  )

  it.live("fails for a reject reply to an unknown id", () =>
    provideTmpdirInstance(
      () =>
        Effect.gen(function* () {
          const requestID = PermissionV1.ID.make("permission_unknown_reject")
          const exit = yield* reply({ requestID, reply: "reject" }).pipe(Effect.exit)
          expectNotFound(exit, requestID)
        }),
      { git: true },
    ),
  )
})
