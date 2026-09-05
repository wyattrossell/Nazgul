import { useEffect, useRef, useState } from "react";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";

import { api, errorText } from "../../lib/api";
import { ENTITY_PROBE, probeMeta, type EntityType, type Graph, type GraphNode } from "../../lib/types";
import { selectActiveCase, useStore } from "../../store";

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

const TYPE_SHAPE: Record<string, cytoscape.Css.NodeShape> = {
  username: "round-rectangle",
  email: "diamond",
  phone: "hexagon",
  domain: "ellipse",
  ip: "rectangle",
  image: "triangle",
  wallet: "octagon",
  person: "star",
  org: "pentagon",
  url: "vee",
  profile: "ellipse",
};

export function GraphPage() {
  const activeCase = useStore(selectActiveCase);
  const skin = useStore((s) => s.settings.skin);
  const requestProbe = useStore((s) => s.requestProbe);
  const pushLog = useStore((s) => s.pushLog);
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [layout, setLayout] = useState<"cose" | "concentric" | "breadthfirst" | "circle">("cose");
  const [hideProfiles, setHideProfiles] = useState(false);

  const caseId = activeCase?.id ?? 0;

  useEffect(() => {
    if (!caseId) return;
    api
      .caseGraph(caseId)
      .then(setGraph)
      .catch((err) => pushLog("bad", `graph: ${errorText(err)}`));
  }, [caseId, pushLog]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container || !graph) return;

    const accent = cssVar("--accent");
    const ink = cssVar("--ink");
    const ink2 = cssVar("--ink-2");
    const line = cssVar("--line-strong");
    const panel = cssVar("--panel-2");
    const bg = cssVar("--bg");

    const nodes = graph.nodes.filter((n) => !hideProfiles || n.type !== "profile");
    const ids = new Set(nodes.map((n) => n.id));
    const edges = graph.edges.filter((e) => ids.has(e.source) && ids.has(e.target));

    const elements: ElementDefinition[] = [
      ...nodes.map((n) => ({
        data: { ...n, weight: Math.min(6, n.weight) },
        classes: n.type,
      })),
      ...edges.map((e) => ({ data: { id: e.id, source: e.source, target: e.target, relation: e.relation } })),
    ];

    cyRef.current?.destroy();
    const cy = cytoscape({
      container,
      elements,
      minZoom: 0.2,
      maxZoom: 3,
      wheelSensitivity: 0.2,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            color: ink,
            "font-family": "IBM Plex Mono, Consolas, monospace",
            "font-size": 10,
            "text-wrap": "ellipsis",
            "text-max-width": "140",
            "text-valign": "bottom",
            "text-margin-y": 4,
            "background-color": panel,
            "border-color": accent,
            "border-width": 1.5,
            width: "mapData(weight, 1, 6, 18, 42)",
            height: "mapData(weight, 1, 6, 18, 42)",
            shape: "ellipse",
          },
        },
        ...Object.entries(TYPE_SHAPE).map(([type, shape]) => ({
          selector: `node.${type}`,
          style: { shape },
        })),
        {
          selector: "node.profile",
          style: {
            "background-color": bg,
            "border-color": ink2,
            "border-width": 1,
            width: 12,
            height: 12,
            "font-size": 8,
            color: ink2,
          },
        },
        {
          selector: "node:selected",
          style: { "border-width": 3, "border-color": accent, "background-color": accent, color: accent },
        },
        {
          selector: "edge",
          style: {
            width: 1,
            "line-color": line,
            "target-arrow-color": line,
            "target-arrow-shape": "triangle",
            "arrow-scale": 0.7,
            "curve-style": "bezier",
            label: "data(relation)",
            "font-size": 7,
            color: ink2,
            "text-rotation": "autorotate",
            "text-background-color": bg,
            "text-background-opacity": 0.8,
            "text-background-padding": "1",
          },
        },
        { selector: "edge:selected", style: { "line-color": accent, "target-arrow-color": accent, width: 2 } },
      ],
      layout: {
        name: layout,
        animate: false,
        ...(layout === "cose" ? { nodeRepulsion: () => 8000, idealEdgeLength: () => 80, padding: 30 } : { padding: 30 }),
      } as cytoscape.LayoutOptions,
    });

    cy.on("tap", "node", (e) => setSelected(e.target.data() as GraphNode));
    cy.on("tap", (e) => {
      if (e.target === cy) setSelected(null);
    });
    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [graph, skin, layout, hideProfiles]);

  const pivot = (node: GraphNode) => {
    const probe = ENTITY_PROBE[node.type as EntityType];
    if (probe && probeMeta(probe).available) requestProbe(probe, node.value);
  };

  const counts = graph
    ? graph.nodes.reduce<Record<string, number>>((acc, n) => {
        acc[n.type] = (acc[n.type] ?? 0) + 1;
        return acc;
      }, {})
    : {};

  return (
    <div className="graph-page">
      <div className="results-bar">
        <span className="summary">
          {activeCase?.name ?? "…"} · <b>{graph?.nodes.length ?? 0} nodes</b> · {graph?.edges.length ?? 0} links
          {Object.entries(counts).map(([t, n]) => (
            <span key={t}>
              {" "}
              · {n} {t}
            </span>
          ))}
        </span>
        <div className="seg" role="group" aria-label="Layout">
          {(["cose", "concentric", "breadthfirst", "circle"] as const).map((l) => (
            <button key={l} type="button" aria-pressed={layout === l} onClick={() => setLayout(l)}>
              {l}
            </button>
          ))}
        </div>
        <button type="button" className="btn sm" aria-pressed={hideProfiles} onClick={() => setHideProfiles((v) => !v)}>
          {hideProfiles ? "show profiles" : "hide profiles"}
        </button>
        <button type="button" className="btn sm" onClick={() => cyRef.current?.fit(undefined, 30)}>
          Fit
        </button>
        <button
          type="button"
          className="btn sm"
          onClick={() => caseId && api.caseGraph(caseId).then(setGraph).catch((err) => pushLog("bad", errorText(err)))}
        >
          Refresh
        </button>
      </div>

      <div className="graph-body">
        <div className="graph-canvas" ref={containerRef} />
        {graph && graph.nodes.length === 0 && (
          <div className="empty graph-empty">
            <div className="big">EMPTY GRAPH</div>
            Run a probe in this case. Every input and everything it discovers becomes a node here.
          </div>
        )}
        {selected && (
          <div className="graph-side">
            <span className="chip static">{selected.type}</span>
            <div className="site-name">{selected.label}</div>
            {selected.value !== selected.label && <div className="muted mono">{selected.value}</div>}
            <div className="actions">
              {selected.url && (
                <button type="button" className="btn sm primary" onClick={() => api.openUrl(selected.url!)}>
                  Open
                </button>
              )}
              {ENTITY_PROBE[selected.type as EntityType] && (
                <button type="button" className="btn sm" onClick={() => pivot(selected)}>
                  Probe this
                </button>
              )}
              <button
                type="button"
                className="btn sm"
                onClick={() => navigator.clipboard.writeText(selected.value).catch(() => pushLog("warn", "clipboard unavailable"))}
              >
                Copy
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
