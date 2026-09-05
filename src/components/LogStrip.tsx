import { useEffect, useRef } from "react";

import { useStore } from "../store";

function stamp(at: number): string {
  return new Date(at).toLocaleTimeString([], { hour12: false });
}

export function LogStrip() {
  const log = useStore((s) => s.log);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [log.length]);

  return (
    <div className="logstrip" ref={ref} role="log" aria-live="polite">
      {log.map((line) => (
        <div key={line.id} className={`line ${line.level}`}>
          <span className="t">{stamp(line.at)}</span>
          {line.text}
        </div>
      ))}
    </div>
  );
}
