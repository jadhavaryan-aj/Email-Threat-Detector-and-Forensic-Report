import { useQuery } from "@tanstack/react-query";
import { getCaseAttribution } from "../api/cases";
import type { AttributionScenario } from "../types/case";

const SCENARIO_STYLES: Record<AttributionScenario, string> = {
  insufficient_data: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
  spoofed_domain: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  compromised_account: "bg-red-500/10 text-red-400 border-red-500/30",
  anonymized_infrastructure: "bg-purple-500/10 text-purple-400 border-purple-500/30",
  direct_actor: "bg-amber-500/10 text-amber-400 border-amber-500/30",
};

const SCENARIO_LABELS: Record<AttributionScenario, string> = {
  insufficient_data: "Insufficient Data",
  spoofed_domain: "Spoofed Domain",
  compromised_account: "Compromised Account",
  anonymized_infrastructure: "Anonymized Infrastructure",
  direct_actor: "Direct Actor",
};

export function AttributionPanel({ caseId }: { caseId: number }) {
  const { data, isLoading } = useQuery({
    queryKey: ["case-attribution", caseId],
    queryFn: () => getCaseAttribution(caseId),
  });

  if (isLoading || !data) {
    return <p className="text-sm text-zinc-500">Assessing attribution scenario…</p>;
  }

  if (data.scenario === "insufficient_data") {
    return (
      <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3 text-sm text-zinc-500">
        Risk score too low to support an attribution assessment.
      </div>
    );
  }

  const style = SCENARIO_STYLES[data.scenario] ?? SCENARIO_STYLES.insufficient_data;

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
      <div className="flex items-center justify-between gap-3">
        <span className={`rounded-md border px-2 py-1 text-xs font-semibold ${style}`}>
          {SCENARIO_LABELS[data.scenario]}
        </span>
        <span className="font-mono text-xs text-zinc-500">{Math.round(data.confidence * 100)}% confidence</span>
      </div>
      <p className="mt-2 text-sm text-zinc-300">{data.reasoning}</p>
      <p className="mt-2 text-[11px] text-zinc-600 italic">
        A rule-based hypothesis derived from signals already computed for this case — not a confirmed identity or
        location.
      </p>
    </div>
  );
}
