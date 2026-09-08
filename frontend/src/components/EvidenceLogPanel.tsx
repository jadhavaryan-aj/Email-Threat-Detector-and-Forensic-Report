import { useQuery } from "@tanstack/react-query";
import { getCaseEvidenceLog } from "../api/cases";
import { formatTimestamp } from "../utils/format";
import { titleCase } from "../utils/severityColors";

function truncateHash(hash: string): string {
  return hash === "genesis" ? "genesis" : `${hash.slice(0, 10)}…${hash.slice(-6)}`;
}

export function EvidenceLogPanel({ caseId }: { caseId: number }) {
  const { data, isLoading } = useQuery({
    queryKey: ["case-evidence-log", caseId],
    queryFn: () => getCaseEvidenceLog(caseId),
  });

  if (isLoading || !data) {
    return <p className="text-sm text-zinc-500">Verifying evidence chain…</p>;
  }

  return (
    <div>
      <div
        className={`mb-4 flex items-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium ${
          data.valid
            ? "border-emerald-600/40 bg-emerald-500/5 text-emerald-400"
            : "border-red-600/40 bg-red-500/5 text-red-400"
        }`}
      >
        <span className={`h-2 w-2 rounded-full ${data.valid ? "bg-emerald-500" : "animate-pulse bg-red-500"}`} />
        {data.valid
          ? "Chain of custody verified — no tampering detected"
          : `Chain of custody BROKEN at entry #${(data.first_broken_index ?? 0) + 1} — evidence may have been tampered with`}
      </div>

      {data.entries.length === 0 ? (
        <p className="text-sm text-zinc-500">No evidence log entries yet.</p>
      ) : (
        <ol className="relative ml-2 space-y-4 border-l border-zinc-800 pl-5">
          {data.entries.map((entry, index) => {
            const broken = data.first_broken_index !== null && index >= data.first_broken_index;
            return (
              <li key={entry.id} className="relative">
                <span
                  className={`absolute top-1 -left-[25px] h-2.5 w-2.5 rounded-full border-2 border-zinc-950 ${
                    broken ? "bg-red-500" : "bg-emerald-500"
                  }`}
                />
                <p className="text-sm font-medium text-zinc-200">{titleCase(entry.action)}</p>
                <p className="text-[11px] text-zinc-600">{formatTimestamp(entry.created_at)}</p>
                <p className="mt-1 font-mono text-[11px] text-zinc-500">
                  hash: {truncateHash(entry.entry_hash)} <span className="text-zinc-700">←</span>{" "}
                  {truncateHash(entry.prev_entry_hash)}
                </p>
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
}
