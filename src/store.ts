import { create } from "zustand";

import { api, errorText } from "./lib/api";
import type { Case, Entity, Finding, ProbeKind, ScanDone, ScanOptions, ScanRow, ScanStarted, UpdateInfo } from "./lib/types";

export interface QueuedScan {
  probe: ProbeKind;
  input: string;
  patch?: Partial<ScanOptions>;
}

export type Skin = "phosphor" | "amber" | "paper";
export type View = "probes" | "cases" | "graph" | "history" | "toolbox" | "settings";
export type ResultsLayout = "cards" | "table";
export type StatusFilter = "hits" | "all" | "issues";

export interface Settings {
  skin: Skin;
  crt: boolean;
  concurrency: number;
  timeoutSecs: number;
  userAgent: string;
  proxy: string;
  includeNsfw: boolean;
  resultsLayout: ResultsLayout;
  activeCaseId: number;
  route: "direct" | "tor" | "custom";
  airgap: boolean;
  rotateUa: boolean;
  splash: boolean;
}

export const TOR_PROXY = "socks5h://127.0.0.1:9050";

/** Proxy string a scan should use for the current settings, or null for a direct route. */
export function effectiveProxy(settings: Settings): string | null {
  if (settings.route === "tor") return TOR_PROXY;
  if (settings.route === "custom") return settings.proxy.trim() || null;
  return null;
}

export type ScanStatus = "running" | "done" | "cancelled" | "error" | "interrupted";

export interface Scan {
  id: string;
  probe: ProbeKind;
  input: string;
  caseId: number;
  total: number;
  checked: number;
  found: number;
  status: ScanStatus;
  startedAt: number;
  elapsedMs: number | null;
  findings: Finding[];
  error?: string;
}

export interface LogLine {
  id: number;
  at: number;
  level: "info" | "ok" | "warn" | "bad";
  text: string;
}

export interface Selection {
  scanId: string;
  index: number;
}

const SETTINGS_KEY = "nazgul.settings.v2";

const defaultSettings: Settings = {
  skin: "phosphor",
  crt: false,
  concurrency: 40,
  timeoutSecs: 15,
  userAgent: "",
  proxy: "",
  includeNsfw: false,
  resultsLayout: "cards",
  activeCaseId: 0,
  route: "direct",
  airgap: false,
  rotateUa: false,
  splash: true,
};

function loadSettings(): Settings {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    if (!raw) return defaultSettings;
    return { ...defaultSettings, ...(JSON.parse(raw) as Partial<Settings>) };
  } catch {
    return defaultSettings;
  }
}

function persistSettings(settings: Settings) {
  try {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
  } catch {
    /* storage unavailable: settings live for this session only */
  }
}

const MAX_LOG = 300;
let logCounter = 0;

interface State {
  settings: Settings;
  setSettings: (patch: Partial<Settings>) => void;

  view: View;
  setView: (view: View) => void;
  probe: ProbeKind;
  setProbe: (probe: ProbeKind) => void;
  /** Text handed to the probe form by a pivot action. */
  pendingInput: string | null;
  requestProbe: (probe: ProbeKind, input: string) => void;
  consumePendingInput: () => void;

  cases: Case[];
  loadCases: () => Promise<void>;
  setActiveCase: (id: number) => void;
  entities: Entity[];
  loadEntities: () => Promise<void>;
  history: ScanRow[];
  loadHistory: (allCases: boolean) => Promise<void>;

  scans: Record<string, Scan>;
  scanOrder: string[];
  activeScanId: string | null;
  setActiveScan: (id: string) => void;
  beginScan: (id: string, probe: ProbeKind, input: string, caseId: number) => void;
  onScanStarted: (e: ScanStarted) => void;
  onFinding: (f: Finding) => void;
  onScanDone: (e: ScanDone) => void;
  markCancelling: (id: string) => void;
  openHistoricScan: (row: ScanRow) => Promise<void>;
  closeScan: (id: string) => void;

  selection: Selection | null;
  select: (sel: Selection | null) => void;

  queue: QueuedScan[];
  enqueue: (items: QueuedScan[]) => void;
  dequeue: () => QueuedScan | undefined;
  clearQueue: () => void;

  log: LogLine[];
  pushLog: (level: LogLine["level"], text: string) => void;

  update: UpdateInfo | null;
  setUpdate: (info: UpdateInfo | null) => void;
}

function emptyScan(id: string, probe: ProbeKind, input: string, caseId: number, total: number): Scan {
  return {
    id,
    probe,
    input,
    caseId,
    total,
    checked: 0,
    found: 0,
    status: "running",
    startedAt: Date.now(),
    elapsedMs: null,
    findings: [],
  };
}

export const useStore = create<State>((set, get) => ({
  settings: loadSettings(),
  setSettings: (patch) => {
    const settings = { ...get().settings, ...patch };
    persistSettings(settings);
    set({ settings });
  },

  view: "probes",
  setView: (view) => set({ view }),
  probe: "username",
  setProbe: (probe) => set({ probe }),
  pendingInput: null,
  requestProbe: (probe, input) => set({ probe, pendingInput: input, view: "probes" }),
  consumePendingInput: () => set({ pendingInput: null }),

  cases: [],
  loadCases: async () => {
    try {
      const cases = await api.listCases();
      const { settings } = get();
      const active = cases.find((c) => c.id === settings.activeCaseId) ?? cases[0];
      set({ cases });
      if (active && active.id !== settings.activeCaseId) get().setSettings({ activeCaseId: active.id });
    } catch (err) {
      get().pushLog("bad", `could not load cases: ${errorText(err)}`);
    }
  },
  setActiveCase: (id) => {
    get().setSettings({ activeCaseId: id });
    void get().loadEntities();
  },
  entities: [],
  loadEntities: async () => {
    const id = get().settings.activeCaseId;
    if (!id) return;
    try {
      set({ entities: await api.listEntities(id) });
    } catch (err) {
      get().pushLog("bad", `could not load entities: ${errorText(err)}`);
    }
  },
  history: [],
  loadHistory: async (allCases) => {
    try {
      const caseId = allCases ? null : get().settings.activeCaseId || null;
      set({ history: await api.listScans(caseId, 300) });
    } catch (err) {
      get().pushLog("bad", `could not load history: ${errorText(err)}`);
    }
  },

  scans: {},
  scanOrder: [],
  activeScanId: null,
  setActiveScan: (id) => set({ activeScanId: id, selection: null }),

  beginScan: (id, probe, input, caseId) =>
    set((s) => {
      if (s.scans[id]) return {};
      return {
        scans: { ...s.scans, [id]: emptyScan(id, probe, input, caseId, 0) },
        scanOrder: [id, ...s.scanOrder],
        activeScanId: id,
        selection: null,
      };
    }),

  onScanStarted: (e) =>
    set((s) => {
      const existing = s.scans[e.scanId];
      const scan = existing
        ? { ...existing, total: e.total, input: e.input }
        : emptyScan(e.scanId, e.probe, e.input, s.settings.activeCaseId, e.total);
      return {
        scans: { ...s.scans, [e.scanId]: scan },
        scanOrder: existing ? s.scanOrder : [e.scanId, ...s.scanOrder],
        activeScanId: s.activeScanId ?? e.scanId,
      };
    }),

  onFinding: (f) =>
    set((s) => {
      const scan = s.scans[f.scanId];
      if (!scan) return {};
      return {
        scans: {
          ...s.scans,
          [f.scanId]: {
            ...scan,
            checked: scan.checked + 1,
            found: scan.found + (f.status === "found" ? 1 : 0),
            findings: [...scan.findings, f],
          },
        },
      };
    }),

  onScanDone: (e) =>
    set((s) => {
      const scan = s.scans[e.scanId];
      if (!scan) return {};
      const status: ScanStatus = e.error ? "error" : e.cancelled ? "cancelled" : "done";
      return {
        scans: {
          ...s.scans,
          [e.scanId]: {
            ...scan,
            status,
            error: e.error ?? undefined,
            checked: Math.max(scan.checked, e.checked),
            found: e.found,
            elapsedMs: e.elapsedMs,
          },
        },
      };
    }),

  markCancelling: (id) =>
    set((s) => {
      const scan = s.scans[id];
      if (!scan || scan.status !== "running") return {};
      return { scans: { ...s.scans, [id]: { ...scan, status: "cancelled" } } };
    }),

  openHistoricScan: async (row) => {
    const existing = get().scans[row.id];
    if (existing) {
      set({ activeScanId: row.id, view: "probes", probe: row.probe, selection: null });
      return;
    }
    try {
      const findings = await api.scanFindings(row.id);
      const scan: Scan = {
        id: row.id,
        probe: row.probe,
        input: row.input,
        caseId: row.caseId,
        total: row.total,
        checked: row.checked || findings.length,
        found: row.found,
        status: (row.status as ScanStatus) ?? "done",
        startedAt: row.startedAt,
        elapsedMs: row.elapsedMs,
        findings,
        error: row.error ?? undefined,
      };
      set((s) => ({
        scans: { ...s.scans, [row.id]: scan },
        scanOrder: [row.id, ...s.scanOrder.filter((id) => id !== row.id)],
        activeScanId: row.id,
        view: "probes",
        probe: row.probe,
        selection: null,
      }));
    } catch (err) {
      get().pushLog("bad", `could not load scan: ${errorText(err)}`);
    }
  },

  closeScan: (id) =>
    set((s) => {
      const scans = { ...s.scans };
      delete scans[id];
      const scanOrder = s.scanOrder.filter((x) => x !== id);
      return {
        scans,
        scanOrder,
        activeScanId: s.activeScanId === id ? (scanOrder[0] ?? null) : s.activeScanId,
        selection: s.selection?.scanId === id ? null : s.selection,
      };
    }),

  selection: null,
  select: (selection) => set({ selection }),

  queue: [],
  enqueue: (items) => set((s) => ({ queue: [...s.queue, ...items] })),
  dequeue: () => {
    const [next, ...rest] = get().queue;
    if (next) set({ queue: rest });
    return next;
  },
  clearQueue: () => set({ queue: [] }),

  update: null,
  setUpdate: (update) => set({ update }),

  log: [{ id: ++logCounter, at: Date.now(), level: "info", text: "nazgul ready" }],
  pushLog: (level, text) =>
    set((s) => {
      const line: LogLine = { id: ++logCounter, at: Date.now(), level, text };
      const log = s.log.length >= MAX_LOG ? [...s.log.slice(-MAX_LOG + 1), line] : [...s.log, line];
      return { log };
    }),
}));

export const selectActiveScan = (s: State): Scan | null =>
  s.activeScanId ? (s.scans[s.activeScanId] ?? null) : null;

export const selectRunningCount = (s: State): number =>
  Object.values(s.scans).filter((scan) => scan.status === "running").length;

export const selectActiveCase = (s: State): Case | null =>
  s.cases.find((c) => c.id === s.settings.activeCaseId) ?? null;

export const selectSelectedFinding = (s: State): Finding | null => {
  if (!s.selection) return null;
  const scan = s.scans[s.selection.scanId];
  return scan?.findings[s.selection.index] ?? null;
};
