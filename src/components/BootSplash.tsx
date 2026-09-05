import { useEffect, useState } from "react";

import { api } from "../lib/api";

const LINES = [
  "NAZGUL // desktop osint workbench",
  "loading site catalog ............ {sites} sites",
  "opening case database ........... ok",
  "probes online: username email phone domain ip image crypto plugin",
  "route: {route}",
  "ready.",
];

interface Props {
  route: string;
  onDone: () => void;
}

/** Short terminal-style boot sequence. Click or press any key to skip. */
export function BootSplash({ route, onDone }: Props) {
  const [shown, setShown] = useState(0);
  const [sites, setSites] = useState<number | null>(null);
  const [leaving, setLeaving] = useState(false);

  useEffect(() => {
    api.appInfo().then((i) => setSites(i.siteCount)).catch(() => setSites(0));
  }, []);

  useEffect(() => {
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setShown(LINES.length);
      const t = window.setTimeout(onDone, 500);
      return () => window.clearTimeout(t);
    }
    const step = 190;
    const timers: number[] = [];
    LINES.forEach((_, i) => timers.push(window.setTimeout(() => setShown(i + 1), step * (i + 1))));
    timers.push(window.setTimeout(() => setLeaving(true), step * (LINES.length + 1) + 250));
    timers.push(window.setTimeout(onDone, step * (LINES.length + 1) + 600));
    return () => timers.forEach((t) => window.clearTimeout(t));
  }, [onDone]);

  useEffect(() => {
    const skip = () => onDone();
    window.addEventListener("keydown", skip);
    return () => window.removeEventListener("keydown", skip);
  }, [onDone]);

  return (
    <div className={`splash${leaving ? " leaving" : ""}`} onClick={onDone} role="presentation">
      <pre className="splash-lines">
        {LINES.slice(0, shown).map((l, i) => (
          <div key={i} className={i === 0 ? "brand" : undefined}>
            {"> "}
            {l.replace("{sites}", sites === null ? "…" : String(sites)).replace("{route}", route)}
          </div>
        ))}
        {shown < LINES.length && <span className="cursor" aria-hidden="true" />}
      </pre>
      <div className="splash-hint">click or press any key to skip</div>
    </div>
  );
}
