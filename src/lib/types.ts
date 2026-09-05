export type ProbeKind = "username" | "email" | "phone" | "domain" | "ip" | "image" | "crypto" | "plugin" | "person";

export type EntityType =
  | "username"
  | "email"
  | "phone"
  | "domain"
  | "ip"
  | "image"
  | "wallet"
  | "person"
  | "org"
  | "url";

export type FindingStatus = "found" | "notFound" | "ambiguous" | "error" | "info";

export interface EntityRef {
  type: EntityType;
  value: string;
  label: string | null;
}

export interface Finding {
  scanId: string;
  probe: ProbeKind;
  source: string;
  kind: string;
  title: string;
  url: string | null;
  status: FindingStatus;
  summary: string | null;
  category: string;
  httpStatus: number | null;
  elapsedMs: number;
  detail: string | null;
  data: unknown;
  discovered: EntityRef[];
}

export interface ScanStarted {
  scanId: string;
  probe: ProbeKind;
  input: string;
  total: number;
}

export interface ScanDone {
  scanId: string;
  cancelled: boolean;
  total: number;
  checked: number;
  found: number;
  elapsedMs: number;
  error: string | null;
}

export interface ScanOptions {
  categories: string[];
  includeNsfw: boolean;
  concurrency: number;
  timeoutSecs: number;
  userAgent: string | null;
  proxy: string | null;
  airgap?: boolean;
  rotateUserAgent?: boolean;
  extra?: unknown;
}

export interface SecretStatus {
  name: string;
  label: string;
  description: string;
  set: boolean;
}

export interface RouteStatus {
  ok: boolean;
  ip: string | null;
  isTor: boolean;
  error: string | null;
}

export interface PluginManifest {
  name: string;
  description: string;
  inputTypes: EntityType[];
  command: string;
  args: string[];
  parse: string;
  foundMarker: string | null;
  timeoutSecs: number;
  path: string | null;
}

export interface PluginList {
  plugins: PluginManifest[];
  dirs: string[];
}

export interface ScanRequest {
  probe: ProbeKind;
  input: string;
  caseId: number;
  options: ScanOptions;
}

export interface ScanHandle {
  scanId: string;
  probe: ProbeKind;
  input: string;
  caseId: number;
  entityId: number;
}

export interface CategoryCount {
  name: string;
  count: number;
}

export interface SiteSummary {
  total: number;
  categories: CategoryCount[];
  license: string;
  authors: string[];
}

export interface AppInfo {
  name: string;
  version: string;
  siteCount: number;
  dataDir: string;
}

export interface Case {
  id: number;
  name: string;
  description: string;
  createdAt: number;
  updatedAt: number;
  entityCount: number;
  scanCount: number;
  findingCount: number;
}

export interface Entity {
  id: number;
  caseId: number;
  type: EntityType;
  value: string;
  label: string | null;
  createdAt: number;
  scanCount: number;
  foundCount: number;
  tags: string[];
}

export interface ScanRow {
  id: string;
  caseId: number;
  caseName: string;
  entityId: number | null;
  probe: ProbeKind;
  input: string;
  status: string;
  total: number;
  checked: number;
  found: number;
  startedAt: number;
  finishedAt: number | null;
  elapsedMs: number | null;
  error: string | null;
}

export interface Note {
  id: number;
  caseId: number;
  entityId: number | null;
  body: string;
  createdAt: number;
  updatedAt: number;
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  value: string;
  url: string | null;
  entityId: number | null;
  weight: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relation: string;
}

export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export const NSFW_CATEGORY = "xx NSFW xx";

export interface ProbeMeta {
  kind: ProbeKind;
  label: string;
  entity: EntityType;
  placeholder: string;
  available: boolean;
  blurb: string;
}

export const PROBES: ProbeMeta[] = [
  {
    kind: "username",
    label: "Username",
    entity: "username",
    placeholder: "handle to search, e.g. jdoe_dev",
    available: true,
    blurb: "Checks a handle across hundreds of sites in parallel.",
  },
  {
    kind: "email",
    label: "Email",
    entity: "email",
    placeholder: "address, e.g. jdoe@example.com",
    available: true,
    blurb: "Mail posture, disposable check, Gravatar, registration checks.",
  },
  {
    kind: "phone",
    label: "Phone",
    entity: "phone",
    placeholder: "+1 555 0100",
    available: true,
    blurb: "Country, carrier type, formats, messaging presence, dorks.",
  },
  {
    kind: "person",
    label: "Name",
    entity: "person",
    placeholder: "full name, e.g. John Doe",
    available: true,
    blurb: "Handle candidates checked on Venmo, PayPal.Me and Revolut, plus people-search, social and dork launchers.",
  },
  {
    kind: "domain",
    label: "Domain",
    entity: "domain",
    placeholder: "example.com",
    available: true,
    blurb: "RDAP, DNS, subdomains, tech fingerprint, archives.",
  },
  {
    kind: "ip",
    label: "IP",
    entity: "ip",
    placeholder: "203.0.113.7",
    available: true,
    blurb: "Geo, ASN, reverse DNS, open ports, Tor and abuse checks.",
  },
  {
    kind: "image",
    label: "Image",
    entity: "image",
    placeholder: "path to an image, or pick a file",
    available: true,
    blurb: "EXIF metadata, GPS, hashes, reverse-image launchers.",
  },
  {
    kind: "crypto",
    label: "Crypto",
    entity: "wallet",
    placeholder: "BTC / ETH / LTC address",
    available: true,
    blurb: "Validate an address, pull balance and activity.",
  },
  {
    kind: "plugin",
    label: "Plugins",
    entity: "url",
    placeholder: "input for the selected tool",
    available: true,
    blurb: "Run external tools from manifests: Sherlock, holehe, Maigret, theHarvester and your own.",
  },
];

export const probeMeta = (kind: ProbeKind): ProbeMeta => PROBES.find((p) => p.kind === kind) ?? PROBES[0];

export const ENTITY_PROBE: Partial<Record<EntityType, ProbeKind>> = {
  username: "username",
  email: "email",
  phone: "phone",
  domain: "domain",
  ip: "ip",
  image: "image",
  wallet: "crypto",
  person: "person",
};
