import { useEffect, useState } from "react";

import { api, errorText } from "../../lib/api";
import type { AppInfo, PluginList, RouteStatus, SecretStatus, SiteSummary } from "../../lib/types";
import { effectiveProxy, useStore, type Skin } from "../../store";

const skins: { id: Skin; label: string }[] = [
  { id: "phosphor", label: "Phosphor" },
  { id: "amber", label: "Amber" },
  { id: "paper", label: "Paper" },
];

export function SettingsPage() {
  const settings = useStore((s) => s.settings);
  const setSettings = useStore((s) => s.setSettings);
  const pushLog = useStore((s) => s.pushLog);
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [sites, setSites] = useState<SiteSummary | null>(null);
  const [secrets, setSecrets] = useState<SecretStatus[]>([]);
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [route, setRoute] = useState<RouteStatus | null>(null);
  const [checking, setChecking] = useState(false);
  const [plugins, setPlugins] = useState<PluginList | null>(null);

  const refreshSecrets = () => api.secretStatus().then(setSecrets).catch((e) => pushLog("bad", errorText(e)));

  useEffect(() => {
    api.appInfo().then(setInfo).catch(() => {});
    api.listSites().then(setSites).catch(() => {});
    api.listPlugins().then(setPlugins).catch(() => {});
    void refreshSecrets();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const saveSecret = async (name: string) => {
    const value = drafts[name] ?? "";
    try {
      await api.setSecret(name, value);
      setDrafts((d) => ({ ...d, [name]: "" }));
      await refreshSecrets();
      pushLog("ok", value.trim() ? `${name} key saved to the keychain` : `${name} key removed`);
    } catch (e) {
      pushLog("bad", errorText(e));
    }
  };

  const clearSecret = async (name: string) => {
    try {
      await api.deleteSecret(name);
      await refreshSecrets();
      pushLog("warn", `${name} key removed`);
    } catch (e) {
      pushLog("bad", errorText(e));
    }
  };

  const checkRoute = async () => {
    setChecking(true);
    setRoute(null);
    try {
      setRoute(await api.checkRoute(effectiveProxy(settings)));
    } catch (e) {
      setRoute({ ok: false, ip: null, isTor: false, error: errorText(e) });
    } finally {
      setChecking(false);
    }
  };

  return (
    <section className="page">
      <h1>settings</h1>

      <h2>Display</h2>
      <div className="field">
        <span className="label">theme</span>
        <div className="swatches">
          {skins.map((s) => (
            <button
              key={s.id}
              type="button"
              className={`swatch ${s.id}`}
              aria-pressed={settings.skin === s.id}
              onClick={() => setSettings({ skin: s.id })}
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>
      <div className="field">
        <span className="label">crt effects</span>
        <label className="toggle">
          <input type="checkbox" checked={settings.crt} onChange={(e) => setSettings({ crt: e.target.checked })} />
          scanlines and glow (dark themes only)
        </label>
      </div>
      <div className="field">
        <span className="label">boot splash</span>
        <label className="toggle">
          <input type="checkbox" checked={settings.splash} onChange={(e) => setSettings({ splash: e.target.checked })} />
          short boot sequence on launch (click to skip)
        </label>
      </div>

      <h2>Route</h2>
      <div className="field">
        <span className="label">traffic</span>
        <div className="row">
          <div className="seg" role="group" aria-label="Route">
            {(["direct", "tor", "custom"] as const).map((r) => (
              <button key={r} type="button" aria-pressed={settings.route === r} onClick={() => setSettings({ route: r })}>
                {r}
              </button>
            ))}
          </div>
          <button type="button" className="btn sm" onClick={checkRoute} disabled={checking || settings.airgap}>
            {checking ? "Checking…" : "Check route"}
          </button>
          {route && (
            <span className={`status ${route.ok ? (route.isTor ? "found" : "info") : "error"}`}>
              {route.ok ? `${route.isTor ? "Tor exit" : "direct"} · ${route.ip}` : route.error}
            </span>
          )}
        </div>
        <span className="help">
          tor uses socks5h://127.0.0.1:9050, the default port for Tor Browser or the tor service. Applies to new scans.
        </span>
      </div>
      {settings.route === "custom" && (
        <div className="field">
          <span className="label">proxy url</span>
          <input
            className="input"
            value={settings.proxy}
            onChange={(e) => setSettings({ proxy: e.target.value })}
            placeholder="socks5h://127.0.0.1:1080   or   http://127.0.0.1:8080"
            spellCheck={false}
          />
          <span className="help">socks5h resolves DNS through the proxy; plain socks5 leaks DNS to your resolver.</span>
        </div>
      )}
      <div className="field">
        <span className="label">airgap</span>
        <label className="toggle">
          <input type="checkbox" checked={settings.airgap} onChange={(e) => setSettings({ airgap: e.target.checked })} />
          refuse all network probes; phone and image parsing still work
        </label>
      </div>
      <div className="field">
        <span className="label">user agent</span>
        <label className="toggle">
          <input type="checkbox" checked={settings.rotateUa} onChange={(e) => setSettings({ rotateUa: e.target.checked })} />
          rotate: pick a random desktop browser string per scan
        </label>
        <input
          className="input"
          style={{ gridColumn: 2 }}
          value={settings.userAgent}
          onChange={(e) => setSettings({ userAgent: e.target.value })}
          placeholder="or pin a specific user agent string (overrides rotation)"
          spellCheck={false}
        />
      </div>

      <h2>Scanning</h2>
      <div className="field">
        <span className="label">concurrency</span>
        <div className="row">
          <input
            type="range"
            min={5}
            max={100}
            step={5}
            value={settings.concurrency}
            onChange={(e) => setSettings({ concurrency: Number(e.target.value) })}
          />
          <span className="range-val">{settings.concurrency}</span>
        </div>
        <span className="help">parallel requests for the username probe. Lower it if you see many timeouts. Tor likes 10 to 20.</span>
      </div>
      <div className="field">
        <span className="label">timeout</span>
        <div className="row">
          <input
            type="range"
            min={3}
            max={60}
            step={1}
            value={settings.timeoutSecs}
            onChange={(e) => setSettings({ timeoutSecs: Number(e.target.value) })}
          />
          <span className="range-val">{settings.timeoutSecs}s</span>
        </div>
      </div>
      <div className="field">
        <span className="label">adult sites</span>
        <label className="toggle">
          <input type="checkbox" checked={settings.includeNsfw} onChange={(e) => setSettings({ includeNsfw: e.target.checked })} />
          include the NSFW category in username scans
        </label>
      </div>

      <h2>API keys</h2>
      <p className="muted">
        Stored in Windows Credential Manager, never in a file. A probe uses a key only when one is present; without it the
        probe still runs and offers a launcher link instead. Every service below has a free tier except where marked paid.
        Click <b>Get a key</b> to open the sign-up or token page.
      </p>
      <p className="muted">
        {secrets.filter((s) => s.set).length} of {secrets.length} keys saved.
      </p>
      {secrets.map((s) => (
        <div key={s.name} className="field">
          <span className="label">
            {s.label}
            {s.set && <span className="status found"> · saved</span>}
            <br />
            <button type="button" className="linkish-btn" onClick={() => api.openUrl(s.url)} title={s.url}>
              Get a key ↗
            </button>
            <span className={`chip static ${s.free.toLowerCase().startsWith("paid") ? "paid" : "free"}`}>{s.free}</span>
          </span>
          <div className="row">
            <input
              className="input"
              type="password"
              style={{ flex: 1 }}
              value={drafts[s.name] ?? ""}
              onChange={(e) => setDrafts((d) => ({ ...d, [s.name]: e.target.value }))}
              placeholder={s.set ? "saved · paste a new key to replace" : "paste key"}
              autoComplete="off"
              spellCheck={false}
            />
            <button type="button" className="btn sm" disabled={!(drafts[s.name] ?? "").trim()} onClick={() => saveSecret(s.name)}>
              Save
            </button>
            {s.set && (
              <button type="button" className="btn sm" onClick={() => clearSecret(s.name)}>
                Clear
              </button>
            )}
          </div>
          <span className="help">{s.description}</span>
        </div>
      ))}

      <h2>Plugins</h2>
      <p className="muted">
        External tools described by JSON manifests. {plugins?.plugins.length ?? 0} found. Folders searched:{" "}
        <span className="mono">{plugins?.dirs.join(" · ")}</span>
      </p>
      {plugins?.plugins.map((p) => (
        <div key={p.name} className="field">
          <span className="label">{p.name}</span>
          <div>
            <div>{p.description}</div>
            <span className="help">
              {p.command} {p.args.join(" ")} · accepts {p.inputTypes.join(", ") || "any"} · {p.parse} mode
            </span>
          </div>
        </div>
      ))}

      <h2>Data sources</h2>
      <p>
        Username site definitions come from the <b>WhatsMyName</b> project
        {sites ? ` (${sites.total} sites)` : ""}, maintained by {sites?.authors.join(", ") ?? "Micah Hoffman and contributors"}.
      </p>
      <p className="muted">{sites?.license ?? "Creative Commons Attribution-ShareAlike 4.0 International."}</p>
      <p className="muted">
        Disposable-domain list from the disposable-email-domains project. Phone metadata from libphonenumber. Geolocation
        from ip-api.com, ports from Shodan InternetDB, archives from the Wayback Machine, certificates from crt.sh.
      </p>

      <h2>About</h2>
      <p className="muted">
        {info ? `${info.name} v${info.version}` : "Nazgul"} · data folder {info?.dataDir} · public-data reconnaissance
        only. No CAPTCHA solving, no login bypass, no scraping behind authentication.
      </p>
    </section>
  );
}
