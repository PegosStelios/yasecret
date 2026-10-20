import { invoke } from "@tauri-apps/api/core";

export type Project = { id: string; name: string; description: string | null };
export type Environment = { id: string; projectId: string; name: string; secretCount: number; inheritsFrom: string | null };
/** A variable an environment gets from a parent and doesn't override. */
export type InheritedVar = { key: string; value: string | null; isSecret: boolean; fromEnv: string; secretId: string };
export type Secret = { id: string; envId: string; key: string; expiresAt: number | null; isSecret: boolean; updatedAt: number };
export type ImportRow = { key: string; value: string; exists: boolean; suggestedSecret: boolean };
export type ImportItem = { key: string; value: string; isSecret: boolean };
export type ImportSummary = { added: number; updated: number; skipped: number };
export type Version = { id: string; value: string; changedAt: number; byMe: boolean; note: string | null };
export type Activity = { id: string; timestamp: number; action: string; targetLabel: string; byMe: boolean; fromSync: boolean };
export type DiffRow = {
  key: string;
  status: "same" | "different" | "only_left" | "only_right";
  leftValue: string | null;
  rightValue: string | null;
  leftIsSecret: boolean;
  rightIsSecret: boolean;
};
export type Member = { peerId: string; name: string; level: string; joinedAt: number; isMe: boolean; isRoot: boolean };
export type Relay = { code: string; name: string; addedAt: number; online: boolean };
export type SyncStatus = {
  shared: boolean;
  isOwner: boolean;
  isRoot: boolean;
  myLevel: string;
  peersOnline: number;
  lastSyncedAt: number | null;
  lastError: string | null;
};
export type VaultState = { firstRun: boolean; unlocked: boolean; hasRemembered: boolean; hello: boolean; devPassword: boolean };
export type ExportFormat = "dotenv" | "json" | "docker-compose" | "k8s-secret" | "k8s-configmap" | "example";

/** Thin typed wrappers over the Rust commands; errors arrive as readable strings. */
export const api = {
  vaultState: () => invoke<VaultState>("vault_state"),
  unlock: (password: string, confirm: string | null, remember: boolean) => invoke<void>("unlock", { password, confirm, remember }),
  unlockRemembered: () => invoke<void>("unlock_remembered"),
  changePassword: (old: string, next: string) => invoke<void>("change_password", { old, new: next }),
  createRecoveryKey: () => invoke<string>("create_recovery_key"),
  hasRecoveryKey: () => invoke<boolean>("has_recovery_key"),
  /** Save dialog + encrypted backup; resolves to the file name, or null when cancelled. */
  backupVault: () => invoke<string | null>("backup_vault"),
  recoverVault: (key: string, next: string) => invoke<void>("recover_vault", { key, new: next }),
  /** Open dialog for a backup; resolves to its file name, or null when cancelled. */
  pickBackup: () => invoke<string | null>("pick_backup"),
  restoreBackup: (password: string) => invoke<void>("restore_backup", { password }),
  devUnlock: () => invoke<void>("dev_unlock"),
  lock: () => invoke<void>("lock"),
  forgetPassword: () => invoke<void>("forget_password"),

  listProjects: () => invoke<Project[]>("list_projects"),
  sharedProjectIds: () => invoke<string[]>("shared_project_ids"),
  createProject: (name: string, withDefaults: boolean) => invoke<Project>("create_project", { name, withDefaults }),
  renameProject: (projectId: string, name: string) => invoke<void>("rename_project", { projectId, name }),
  deleteProject: (projectId: string) => invoke<void>("delete_project", { projectId }),

  listEnvironments: (projectId: string) => invoke<Environment[]>("list_environments", { projectId }),
  createEnvironment: (projectId: string, name: string) => invoke<Environment>("create_environment", { projectId, name }),
  renameEnvironment: (envId: string, name: string) => invoke<void>("rename_environment", { envId, name }),
  setEnvironmentParent: (envId: string, parentId: string | null) => invoke<void>("set_environment_parent", { envId, parentId }),
  listInherited: (envId: string) => invoke<InheritedVar[]>("list_inherited", { envId }),
  cloneEnvironment: (envId: string, name: string) => invoke<Environment>("clone_environment", { envId, name }),
  deleteEnvironment: (envId: string) => invoke<void>("delete_environment", { envId }),

  listSecrets: (envId: string) => invoke<Secret[]>("list_secrets", { envId }),
  createSecret: (a: { projectId: string; envId: string; key: string; value: string; isSecret: boolean; expiresAt: number | null }) =>
    invoke<Secret>("create_secret", a),
  editSecret: (a: {
    projectId: string;
    secretId: string;
    newKey: string | null;
    newValue: string | null;
    isSecret: boolean | null;
    expiryChanged: boolean;
    expiresAt: number | null;
  }) => invoke<void>("edit_secret", a),
  deleteSecrets: (secretIds: string[]) => invoke<void>("delete_secrets", { secretIds }),
  getValue: (projectId: string, secretId: string, reveal: boolean) => invoke<string>("get_value", { projectId, secretId, reveal }),
  looksSecret: (key: string) => invoke<boolean>("looks_secret", { key }),
  isValidKey: (key: string) => invoke<boolean>("is_valid_key", { key }),

  previewImport: (envId: string, content: string) => invoke<ImportRow[]>("preview_import", { envId, content }),
  applyImport: (projectId: string, envId: string, items: ImportItem[], overwrite: boolean) =>
    invoke<ImportSummary>("apply_import", { projectId, envId, items, overwrite }),
  exportVariables: (a: { projectId: string; envId: string; format: ExportFormat; keys: string[] | null; includeSecretValues: boolean; name: string }) =>
    invoke<string>("export_variables", a),
  /** Native open dialog; resolves to [file name, text], or null when cancelled. */
  openTextFile: () => invoke<[string, string] | null>("open_text_file"),
  /** Native save dialog; resolves to the saved file's name, or null when cancelled. */
  saveTextFile: (defaultName: string, contents: string) => invoke<string | null>("save_text_file", { defaultName, contents }),
  copyText: (text: string, sensitive: boolean) => invoke<void>("copy_text", { text, sensitive }),

  listVersions: (projectId: string, secretId: string) => invoke<Version[]>("list_versions", { projectId, secretId }),
  restoreVersion: (projectId: string, secretId: string, versionId: string) => invoke<void>("restore_version", { projectId, secretId, versionId }),
  listActivity: (projectId: string) => invoke<Activity[]>("list_activity", { projectId }),
  compareEnvironments: (projectId: string, left: string, right: string) => invoke<DiffRow[]>("compare_environments", { projectId, left, right }),

  deviceCode: () => invoke<string>("device_code"),
  createInvite: (projectId: string, deviceCode: string | null, level: "editor" | "viewer") =>
    invoke<string>("create_invite", { projectId, deviceCode, level }),
  joinProject: (link: string) => invoke<string>("join_project", { link }),
  listMembers: (projectId: string) => invoke<Member[]>("list_members", { projectId }),
  setMemberLevel: (projectId: string, peerId: string, level: string) => invoke<void>("set_member_level", { projectId, peerId, level }),
  addRelay: (projectId: string, code: string, name: string) => invoke<string>("add_relay", { projectId, code, name }),
  removeRelay: (projectId: string, code: string) => invoke<void>("remove_relay", { projectId, code }),
  listRelays: (projectId: string) => invoke<Relay[]>("list_relays", { projectId }),
  syncStatus: (projectId: string) => invoke<SyncStatus>("sync_status", { projectId }),
  syncRevision: () => invoke<number>("sync_revision"),
  expiringVariables: (days: number) => invoke<{ id: string; label: string; expired: boolean }[]>("expiring_variables", { days }),
  stopSharing: (projectId: string) => invoke<void>("stop_sharing", { projectId }),
};

export const errorText = (e: unknown) => (typeof e === "string" ? e : e instanceof Error ? e.message : String(e));

export const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

export function relativeTime(unixSeconds: number): string {
  const diff = Date.now() / 1000 - unixSeconds;
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (Math.abs(diff) < 60) return rtf.format(-Math.round(diff), "second");
  if (Math.abs(diff) < 3600) return rtf.format(-Math.round(diff / 60), "minute");
  if (Math.abs(diff) < 86400) return rtf.format(-Math.round(diff / 3600), "hour");
  return rtf.format(-Math.round(diff / 86400), "day");
}

export const formatDate = (unixSeconds: number) =>
  new Date(unixSeconds * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

export const levelLabel = (level: string) =>
  ({ owner: "Owner", editor: "Can edit", viewer: "Can view", pending: "Waiting for owner" } as Record<string, string>)[level] ?? level;
