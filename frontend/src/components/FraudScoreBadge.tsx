import { classificationStyle } from "../utils/severityColors";

export function FraudScoreBadge({ label, score }: { label: string; score: number }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-semibold tracking-wide uppercase ${classificationStyle(label)}`}
    >
      <span>{label}</span>
      <span className="opacity-50">·</span>
      <span className="font-mono">{score}/100</span>
    </span>
  );
}
