import path from "node:path"

/**
 * ProjectTable reuses "global" for directories without Git metadata.
 * Include the resolved working directory for those projects so unrelated folders
 * cannot share target memory. Git-backed projects stay stable across worktrees.
 */
export function targetWorkspaceOwnerKey(projectID: string, projectRoot: string): string {
  if (projectID !== "global") return "project:" + projectID
  return "directory:" + path.resolve(projectRoot)
}
