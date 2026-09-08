import type { CaseGraph, GraphNode } from "../types/case";

const WIDTH = 560;
const HEIGHT = 340;
const CENTER = { x: WIDTH / 2, y: HEIGHT / 2 };
const INNER_RADIUS = 100;
const OUTER_RADIUS = 155;

const NODE_COLOR: Record<string, string> = {
  case: "#22d3ee", // cyan-400
  domain: "#fbbf24", // amber-400
  ip: "#fb923c", // orange-400
};

interface PositionedNode extends GraphNode {
  x: number;
  y: number;
}

function layout(graph: CaseGraph, rootId: string): PositionedNode[] {
  const indicatorNodes = graph.nodes.filter((n) => n.type !== "case" || n.id === rootId);
  const otherCaseNodes = graph.nodes.filter((n) => n.type === "case" && n.id !== rootId);

  const positioned = new Map<string, PositionedNode>();
  positioned.set(rootId, { ...graph.nodes.find((n) => n.id === rootId)!, x: CENTER.x, y: CENTER.y });

  const indicators = indicatorNodes.filter((n) => n.id !== rootId);
  indicators.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / Math.max(indicators.length, 1) - Math.PI / 2;
    positioned.set(node.id, {
      ...node,
      x: CENTER.x + INNER_RADIUS * Math.cos(angle),
      y: CENTER.y + INNER_RADIUS * Math.sin(angle),
    });
  });

  otherCaseNodes.forEach((node) => {
    // place near whichever indicator connects to it
    const connectingEdge = graph.edges.find(
      (e) => (e.source === node.id || e.target === node.id) && e.relationship === "potential_correlation"
    );
    const indicatorId = connectingEdge ? (connectingEdge.source === node.id ? connectingEdge.target : connectingEdge.source) : null;
    const indicatorPos = indicatorId ? positioned.get(indicatorId) : null;
    if (indicatorPos) {
      const angle = Math.atan2(indicatorPos.y - CENTER.y, indicatorPos.x - CENTER.x);
      positioned.set(node.id, {
        ...node,
        x: CENTER.x + OUTER_RADIUS * Math.cos(angle),
        y: CENTER.y + OUTER_RADIUS * Math.sin(angle),
      });
    } else {
      positioned.set(node.id, { ...node, x: CENTER.x, y: CENTER.y });
    }
  });

  return Array.from(positioned.values());
}

export function CorrelationGraph({ graph, rootId }: { graph: CaseGraph; rootId: string }) {
  if (graph.nodes.length <= 1) {
    return (
      <div className="flex h-40 items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900/40 text-sm text-zinc-500">
        No infrastructure indicators observed for this case yet.
      </div>
    );
  }

  const nodes = layout(graph, rootId);
  const positionOf = (id: string) => nodes.find((n) => n.id === id);

  return (
    <div className="overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-900/40 p-2">
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="mx-auto" style={{ minWidth: 480, maxWidth: 640 }}>
        {graph.edges.map((edge, i) => {
          const source = positionOf(edge.source);
          const target = positionOf(edge.target);
          if (!source || !target) return null;
          const isCorrelation = edge.relationship === "potential_correlation";
          return (
            <line
              key={i}
              x1={source.x}
              y1={source.y}
              x2={target.x}
              y2={target.y}
              stroke={isCorrelation ? "#f87171" : "#52525b"}
              strokeWidth={isCorrelation ? 1.5 : 1}
              strokeDasharray={isCorrelation ? "4 3" : undefined}
            />
          );
        })}
        {nodes.map((node) => (
          <g key={node.id}>
            <circle
              cx={node.x}
              cy={node.y}
              r={node.id === rootId ? 26 : 20}
              fill="#18181b"
              stroke={NODE_COLOR[node.type] ?? "#a1a1aa"}
              strokeWidth={2}
            />
            <text x={node.x} y={node.y + 34} textAnchor="middle" fontSize={10} fill="#a1a1aa">
              {node.type}
            </text>
            <text x={node.x} y={node.y + 46} textAnchor="middle" fontSize={10} fill="#e4e4e7" fontFamily="monospace">
              {node.label.length > 18 ? `${node.label.slice(0, 16)}…` : node.label}
            </text>
          </g>
        ))}
      </svg>
      <div className="mt-1 flex justify-center gap-4 text-[11px] text-zinc-500">
        <span className="flex items-center gap-1">
          <span className="inline-block h-0.5 w-4 bg-zinc-600" /> observed in this case
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-0.5 w-4 border-t border-dashed border-red-400" /> potential correlation
        </span>
      </div>
    </div>
  );
}
