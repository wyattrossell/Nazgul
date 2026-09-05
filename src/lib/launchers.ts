import type { EntityType, Launcher } from "./types";

export type Vars = Record<string, string>;

/** Fills `{var}` placeholders; returns null when a placeholder has no value. */
export function render(template: string, vars: Vars): string | null {
  let missing = false;
  const out = template.replace(/\{(\w+)\}/g, (_, key: string) => {
    if (vars[key] === undefined) {
      missing = true;
      return "";
    }
    return vars[key];
  });
  return missing ? null : out;
}

function cap(s: string): string {
  return s ? s[0].toUpperCase() + s.slice(1) : s;
}

/** Builds template variables for an identifier, mirroring the Rust side. */
export function varsFor(type: EntityType, raw: string): Vars {
  const value = raw.trim();
  const v: Vars = { raw: value, q: encodeURIComponent(value) };
  switch (type) {
    case "username":
      v.handle = value;
      break;
    case "domain":
      v.domain = value.toLowerCase();
      break;
    case "ip":
      v.ip = value;
      break;
    case "person": {
      const tokens = value
        .split(/\s+/)
        .map((t) => t.replace(/[^\p{L}\p{N}]/gu, "").toLowerCase())
        .filter(Boolean);
      if (tokens.length >= 2) {
        v.first = tokens[0];
        v.last = tokens[tokens.length - 1];
        v.First = cap(v.first);
        v.Last = cap(v.last);
      }
      break;
    }
    case "phone": {
      const digits = value.replace(/\D/g, "");
      v.digits = digits;
      // Assume a leading 1 is the US/Canada country code when 11 digits are present.
      const national = digits.length === 11 && digits.startsWith("1") ? digits.slice(1) : digits;
      v.national = national;
      if (national.length === 10) v.nd = `${national.slice(0, 3)}-${national.slice(3, 6)}-${national.slice(6)}`;
      break;
    }
    case "location": {
      const m = value.match(/^\s*(-?\d{1,2}(?:\.\d+)?)\s*([NnSs])?\s*[,;/ ]\s*(-?\d{1,3}(?:\.\d+)?)\s*([EeWw])?\s*$/);
      if (m) {
        let lat = parseFloat(m[1]);
        let lon = parseFloat(m[3]);
        if (m[2]?.toUpperCase() === "S") lat = -Math.abs(lat);
        if (m[4]?.toUpperCase() === "W") lon = -Math.abs(lon);
        v.lat = lat.toFixed(6);
        v.lon = lon.toFixed(6);
        v.latabs = Math.abs(lat).toFixed(6);
        v.lonabs = Math.abs(lon).toFixed(6);
        v.ns = lat < 0 ? "S" : "N";
        v.ew = lon < 0 ? "W" : "E";
      }
      break;
    }
    default:
      break;
  }
  return v;
}

export interface Planned {
  launcher: Launcher;
  url: string;
}

export function plan(catalog: Launcher[], type: EntityType, raw: string): Planned[] {
  const vars = varsFor(type, raw);
  return catalog
    .filter((l) => l.types.includes(type))
    .map((launcher) => ({ launcher, url: render(launcher.url, vars) }))
    .filter((p): p is Planned => p.url !== null);
}

// ---------------------------------------------------------------------------
// Dork builder
// ---------------------------------------------------------------------------

export interface DorkSpec {
  exact: string;
  anyOf: string;
  exclude: string;
  site: string;
  tld: string;
  filetype: string;
  inurl: string;
  intitle: string;
  rangeFrom: string;
  rangeTo: string;
  social: "" | "@" | "#";
}

export const EMPTY_DORK: DorkSpec = {
  exact: "",
  anyOf: "",
  exclude: "",
  site: "",
  tld: "",
  filetype: "",
  inurl: "",
  intitle: "",
  rangeFrom: "",
  rangeTo: "",
  social: "",
};

const splitTerms = (s: string) => s.split(/,|\n/).map((t) => t.trim()).filter(Boolean);

export function buildDork(d: DorkSpec): string {
  const parts: string[] = [];
  const exact = d.exact.trim();
  if (exact) parts.push(d.social ? `${d.social}${exact.replace(/^[@#]/, "")}` : `"${exact}"`);
  const any = splitTerms(d.anyOf).map((t) => (t.includes(" ") ? `"${t}"` : t));
  if (any.length === 1) parts.push(any[0]);
  else if (any.length > 1) parts.push(`(${any.join(" OR ")})`);
  for (const t of splitTerms(d.exclude)) parts.push(`-${t.includes(" ") ? `"${t}"` : t}`);
  const site = d.site.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  const tld = d.tld.trim().replace(/^\./, "");
  if (site) parts.push(`site:${site}`);
  else if (tld) parts.push(`site:.${tld}`);
  for (const ft of splitTerms(d.filetype)) parts.push(`filetype:${ft.replace(/^\./, "")}`);
  if (d.inurl.trim()) parts.push(`inurl:${d.inurl.trim()}`);
  if (d.intitle.trim()) parts.push(`intitle:${d.intitle.trim()}`);
  if (d.rangeFrom.trim() && d.rangeTo.trim()) parts.push(`${d.rangeFrom.trim()}..${d.rangeTo.trim()}`);
  return parts.join(" ");
}

export const ENGINES: { name: string; url: (q: string) => string }[] = [
  { name: "Google", url: (q) => `https://www.google.com/search?q=${encodeURIComponent(q)}` },
  { name: "Bing", url: (q) => `https://www.bing.com/search?q=${encodeURIComponent(q)}` },
  { name: "DuckDuckGo", url: (q) => `https://duckduckgo.com/?q=${encodeURIComponent(q)}` },
  { name: "Yandex", url: (q) => `https://yandex.com/search/?text=${encodeURIComponent(q)}` },
  { name: "Carrot2", url: (q) => `https://search.carrot2.org/#/search/web/${encodeURIComponent(q)}` },
  { name: "Google Images", url: (q) => `https://www.google.com/search?tbm=isch&q=${encodeURIComponent(q)}` },
];

export const OPERATOR_SHEET: [string, string][] = [
  ['"exact phrase"', "Only pages containing the phrase exactly as typed. Works around every operator below."],
  ["term term", "A space is an AND: every term must appear."],
  ["a OR b  ·  a | b", "Either term. Group with parentheses: (a OR b) c"],
  ["*", "Wildcard for an unknown word inside a phrase: \"john * doe\""],
  ["2001..2026", "Any number in the range, useful for years, prices, IDs."],
  ["-term", "Exclude pages containing the term: -citigroup"],
  ["@handle", "Social identifier search."],
  ["#tag", "Social trend or hashtag search."],
  ["site:facebook.com", "Only that site. site:.ca limits to a country code; site:de.linkedin.com limits to a country subdomain."],
  ["filetype:pdf", "Only that file type: pdf, xlsx, docx, jpg, txt..."],
  ["inurl:fullz  ·  intitle:index of", "String must appear in the URL or the page title."],
];
