export * as PermissionV1 from "./permission"

import { Schema } from "effect"
export * from "@opencode-ai/schema/permission-v1"
import { ID } from "@opencode-ai/schema/permission-v1"

export class RejectedError extends Schema.TaggedErrorClass<RejectedError>()("PermissionRejectedError", {}) {
  override get message() {
    return "The user rejected permission to use this specific tool call."
  }
}

export class CorrectedError extends Schema.TaggedErrorClass<CorrectedError>()("PermissionCorrectedError", {
  feedback: Schema.String,
}) {
  override get message() {
    return `The user rejected permission to use this specific tool call with the following feedback: ${this.feedback}`
  }
}

export class DeniedError extends Schema.TaggedErrorClass<DeniedError>()("PermissionDeniedError", {
  ruleset: Schema.Any,
}) {
  override get message() {
    // kilocode_change start - distinguish hard-coded, config-immune denials (e.g. HardBashPolicy)
    // from ordinary kilo.jsonc/agent-config denials, so it's clear which layer blocked the call.
    const rule = this.ruleset as { source?: string; permission?: string; pattern?: string } | undefined
    if (rule?.source === "hard") {
      return `This command is blocked by a built-in, non-configurable Kilo policy (matched "${rule.pattern}" for permission "${rule.permission}"). This is not a kilo.jsonc/agent-config rule, so kilo.jsonc edits, agent permission overrides, and "always allow" cannot re-enable it. Do not retry this command or attempt a workaround; explain the block to the user instead.`
    }
    // kilocode_change end
    return `The user has specified a rule which prevents you from using this specific tool call. Here are some of the relevant rules ${JSON.stringify(this.ruleset)}`
  }
}

export class NotFoundError extends Schema.TaggedErrorClass<NotFoundError>()("Permission.NotFoundError", {
  requestID: ID,
}) {}

export type Error = DeniedError | RejectedError | CorrectedError
