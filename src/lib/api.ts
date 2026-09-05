import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { save } from "@tauri-apps/plugin-dialog";
import { openUrl } from "@tauri-apps/plugin-opener";

import type {
  AppInfo,
  Case,
  Entity,
  EntityType,
  Finding,
  Graph,
  Note,
  PluginList,
  RouteStatus,
  ScanDone,
  ScanHandle,
  ScanRequest,
  ScanRow,
  ScanStarted,
  SecretStatus,
  SiteSummary,
} from "./types";

export const api = {
  appInfo: () => invoke<AppInfo>("app_info"),
  listSites: () => invoke<SiteSummary>("list_sites"),

  startScan: (req: ScanRequest) => invoke<ScanHandle>("start_scan", { req }),
  cancelScan: (scanId: string) => invoke<boolean>("cancel_scan", { scanId }),
  listScans: (caseId: number | null, limit = 200) => invoke<ScanRow[]>("list_scans", { caseId, limit }),
  scanFindings: (scanId: string) => invoke<Finding[]>("scan_findings", { scanId }),
  deleteScan: (scanId: string) => invoke<void>("delete_scan", { scanId }),

  listCases: () => invoke<Case[]>("list_cases"),
  createCase: (name: string, description: string) => invoke<Case>("create_case", { name, description }),
  updateCase: (id: number, name: string, description: string) =>
    invoke<void>("update_case", { id, name, description }),
  deleteCase: (id: number) => invoke<void>("delete_case", { id }),

  listEntities: (caseId: number) => invoke<Entity[]>("list_entities", { caseId }),
  addEntity: (caseId: number, entityType: EntityType, value: string, label: string | null) =>
    invoke<number>("add_entity", { caseId, entityType, value, label }),
  deleteEntity: (id: number) => invoke<void>("delete_entity", { id }),
  setEntityLabel: (id: number, label: string | null) => invoke<void>("set_entity_label", { id, label }),
  setEntityTags: (entityId: number, tags: string[]) => invoke<void>("set_entity_tags", { entityId, tags }),
  entityHits: (entityId: number) => invoke<Finding[]>("entity_hits", { entityId }),
  caseHits: (caseId: number, limit = 5000) => invoke<Finding[]>("case_hits", { caseId, limit }),

  listNotes: (caseId: number, entityId: number | null) => invoke<Note[]>("list_notes", { caseId, entityId }),
  addNote: (caseId: number, entityId: number | null, body: string) =>
    invoke<Note>("add_note", { caseId, entityId, body }),
  updateNote: (id: number, body: string) => invoke<void>("update_note", { id, body }),
  deleteNote: (id: number) => invoke<void>("delete_note", { id }),

  caseGraph: (caseId: number) => invoke<Graph>("case_graph", { caseId }),

  writeTextFile: (path: string, contents: string) => invoke<void>("write_text_file", { path, contents }),
  openUrl: (url: string) => openUrl(url),

  secretStatus: () => invoke<SecretStatus[]>("secret_status"),
  setSecret: (name: string, value: string) => invoke<void>("set_secret", { name, value }),
  deleteSecret: (name: string) => invoke<void>("delete_secret", { name }),
  checkRoute: (proxy: string | null) => invoke<RouteStatus>("check_route", { proxy }),
  listPlugins: () => invoke<PluginList>("list_plugins"),
};

export interface ScanListeners {
  onStarted: (e: ScanStarted) => void;
  onFinding: (e: Finding) => void;
  onDone: (e: ScanDone) => void;
}

/** Subscribes to scan events. Returns a function that removes every listener. */
export async function listenToScans(l: ScanListeners): Promise<() => void> {
  const unlisteners: UnlistenFn[] = await Promise.all([
    listen<ScanStarted>("scan://started", (e) => l.onStarted(e.payload)),
    listen<Finding>("scan://finding", (e) => l.onFinding(e.payload)),
    listen<ScanDone>("scan://done", (e) => l.onDone(e.payload)),
  ]);
  return () => unlisteners.forEach((fn) => fn());
}

/** Opens a save dialog and writes the text. Returns the path, or null if cancelled. */
export async function saveTextAs(defaultName: string, extension: string, contents: string): Promise<string | null> {
  const path = await save({
    defaultPath: defaultName,
    filters: [{ name: extension.toUpperCase(), extensions: [extension] }],
  });
  if (!path) return null;
  await api.writeTextFile(path, contents);
  return path;
}

export function errorText(err: unknown): string {
  if (typeof err === "string") return err;
  if (err instanceof Error) return err.message;
  return JSON.stringify(err);
}
