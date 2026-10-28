import { PermissionNext } from "@/permission/next"

/**
 * Return the effective permission for the required first step of captured-request
 * analysis. PermissionNext uses ordered rules (last matching rule wins), so checking
 * whether any "task" rule exists can incorrectly report a denied/approval-gated
 * analyzer as enabled.
 */
export function proxyAnalyzerTaskPermission(ruleset: PermissionNext.Ruleset): PermissionNext.Action {
  return PermissionNext.evaluate("task", "proxy-analyzer", ruleset).action
}
