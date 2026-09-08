import { Link } from "react-router-dom";
import type { CaseSummary } from "../types/case";
import { EmptyState, InboxIcon } from "./EmptyState";
import { formatTimestamp } from "../utils/format";
import { caseStatusStyle, titleCase } from "../utils/severityColors";
import { FraudScoreBadge } from "./FraudScoreBadge";

export function CaseTable({ cases }: { cases: CaseSummary[] }) {
  if (cases.length === 0) {
    return (
      <EmptyState
        icon={<InboxIcon />}
        title="No cases yet"
        description={
          <>
            Upload an <code>.eml</code> file from the{" "}
            <Link to="/" className="text-cyan-400 hover:underline">
              Upload page
            </Link>{" "}
            to get started.
          </>
        }
      />
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-zinc-800">
      <table className="min-w-full divide-y divide-zinc-800 text-sm">
        <thead className="bg-zinc-900">
          <tr>
            <th className="px-4 py-2 text-left font-medium text-zinc-400">Subject</th>
            <th className="px-4 py-2 text-left font-medium text-zinc-400">From</th>
            <th className="px-4 py-2 text-left font-medium text-zinc-400">Category</th>
            <th className="px-4 py-2 text-left font-medium text-zinc-400">Risk</th>
            <th className="px-4 py-2 text-left font-medium text-zinc-400">Status</th>
            <th className="px-4 py-2 text-left font-medium text-zinc-400">Received</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800 bg-zinc-950">
          {cases.map((c) => (
            <tr key={c.case_id} className="transition hover:bg-zinc-900/60">
              <td className="px-4 py-2">
                <Link to={`/cases/${c.case_id}`} className="font-medium text-cyan-400 hover:underline">
                  {c.subject || "(no subject)"}
                </Link>
              </td>
              <td className="px-4 py-2 font-mono text-xs text-zinc-400">{c.from_address}</td>
              <td className="px-4 py-2 text-zinc-300">{titleCase(c.threat_category)}</td>
              <td className="px-4 py-2">
                <FraudScoreBadge label={c.classification_label} score={c.fraud_score} />
              </td>
              <td className="px-4 py-2">
                <span className={`rounded border px-2 py-0.5 text-xs font-medium ${caseStatusStyle(c.status)}`}>
                  {titleCase(c.status)}
                </span>
              </td>
              <td className="px-4 py-2 text-zinc-500">{formatTimestamp(c.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
