import type { Signal } from "../types/case";
import { severityStyle, titleCase } from "../utils/severityColors";

const CATEGORY_LABELS: Record<string, string> = {
  authentication: "Authentication",
  identity: "Identity",
  content: "Content",
  infrastructure: "Infrastructure",
  reputation: "Reputation",
  url: "URL",
};

export function SignalCard({ signal }: { signal: Signal }) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3">
      <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-zinc-100">{titleCase(signal.name)}</span>
          <span className="rounded border border-zinc-700 px-1.5 py-0.5 text-[10px] font-medium text-zinc-400 uppercase">
            {CATEGORY_LABELS[signal.category] ?? signal.category}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold ${severityStyle(signal.severity)}`}>
            {signal.severity}
          </span>
          <span className="font-mono text-sm font-semibold text-zinc-300">+{signal.score}</span>
        </div>
      </div>
      <p className="text-xs text-zinc-400">{signal.explanation}</p>
      {signal.evidence && (
        <p className="mt-1.5 truncate font-mono text-[11px] text-zinc-500" title={signal.evidence}>
          {signal.evidence}
        </p>
      )}
    </div>
  );
}
