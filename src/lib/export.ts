import type { Finding } from "./types";
import type { Scan } from "../store";

function csvCell(value: unknown): string {
  const text = value === null || value === undefined ? "" : String(value);
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function findingsToCsv(findings: Finding[]): string {
  const header = ["source", "kind", "title", "status", "url", "summary", "category", "httpStatus", "elapsedMs", "detail"];
  const rows = findings.map((f) =>
    [f.source, f.kind, f.title, f.status, f.url, f.summary, f.category, f.httpStatus, f.elapsedMs, f.detail]
      .map(csvCell)
      .join(","),
  );
  return [header.join(","), ...rows].join("\n");
}

export function scanToJson(scan: Scan): string {
  return JSON.stringify(
    {
      tool: "nazgul",
      probe: scan.probe,
      input: scan.input,
      startedAt: new Date(scan.startedAt).toISOString(),
      status: scan.status,
      total: scan.total,
      checked: scan.checked,
      found: scan.found,
      elapsedMs: scan.elapsedMs,
      findings: scan.findings,
    },
    null,
    2,
  );
}

export function safeFileStem(text: string): string {
  return text.replace(/[^a-z0-9._-]+/gi, "_").slice(0, 60) || "scan";
}
