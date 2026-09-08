import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getDashboardStats, listCases } from "../api/cases";
import { DashboardSkeleton, TableRowSkeleton } from "../components/Skeleton";
import { EmptyState, InboxIcon, ShieldIcon } from "../components/EmptyState";
import { StatTile } from "../components/StatTile";
import { formatTimestamp } from "../utils/format";
import { classificationStyle, titleCase } from "../utils/severityColors";

const CRITICAL_THREAT_MIN_SCORE = 90;

function CriticalThreatsSection() {
  const navigate = useNavigate();
  const { data: criticalCases, isLoading } = useQuery({
    queryKey: ["cases", { min_score: CRITICAL_THREAT_MIN_SCORE }],
    queryFn: () => listCases(CRITICAL_THREAT_MIN_SCORE),
  });

  function openMail(caseId: number, sourceUrl: string) {
    if (sourceUrl) {
      window.open(sourceUrl, "_blank", "noopener");
    } else {
      navigate(`/cases/${caseId}`);
    }
  }

  return (
    <section className="mb-8 rounded-lg border border-red-600/30 bg-red-950/10 p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-red-400">
          <span className="h-2 w-2 animate-pulse rounded-full bg-red-500" />
          Critical Threats (≥{CRITICAL_THREAT_MIN_SCORE}% risk)
        </h2>
        {criticalCases && <span className="text-xs text-zinc-500">{criticalCases.length} email(s)</span>}
      </div>

      {isLoading && (
        <div className="space-y-2">
          <TableRowSkeleton />
          <TableRowSkeleton />
        </div>
      )}

      {criticalCases && criticalCases.length === 0 && (
        <EmptyState
          icon={<ShieldIcon />}
          title="No critical threats right now"
          description={`Emails scoring ${CRITICAL_THREAT_MIN_SCORE}% or higher will show up here as soon as they're scanned.`}
        />
      )}

      <div className="space-y-2">
        {criticalCases?.map((c) => (
          <button
            key={c.case_id}
            type="button"
            onClick={() => openMail(c.case_id, c.source_url)}
            className="flex w-full items-center justify-between gap-3 rounded-md border border-red-600/20 bg-zinc-950/40 px-3 py-2 text-left text-sm transition hover:border-red-500/50 hover:bg-zinc-900"
          >
            <div className="min-w-0">
              <p className="truncate text-zinc-100">{c.subject || "(no subject)"}</p>
              <p className="truncate font-mono text-xs text-zinc-500">{c.from_address}</p>
            </div>
            <div className="flex shrink-0 items-center gap-3">
              <span className="rounded border border-red-600/40 bg-red-600/10 px-2 py-0.5 text-xs font-semibold text-red-400">
                {c.fraud_score}/100
              </span>
              <span className="text-xs text-cyan-400">{c.source_url ? "Open in mailbox →" : "View analysis →"}</span>
            </div>
          </button>
        ))}
      </div>
    </section>
  );
}

export function DashboardPage() {
  const { data, isLoading, error } = useQuery({ queryKey: ["dashboard-stats"], queryFn: getDashboardStats });

  if (isLoading) return <DashboardSkeleton />;
  if (error || !data) return <p className="text-sm text-red-400">Failed to load dashboard.</p>;

  return (
    <div>
      <h1 className="mb-1 text-xl font-semibold text-zinc-100">Investigation Dashboard</h1>
      <p className="mb-6 text-sm text-zinc-500">Aggregate view across all analyzed cases.</p>

      <CriticalThreatsSection />

      <div className="mb-8 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <StatTile label="Total Cases" value={data.total_cases} />
        <StatTile label="High Risk" value={data.high_risk_count} accent="text-orange-400" />
        <StatTile label="Critical" value={data.critical_count} accent="text-red-400" />
        <StatTile label="Potential Campaigns" value={data.potential_campaigns} accent="text-amber-400" />
        <StatTile label="Investigations Today" value={data.investigations_today} accent="text-cyan-400" />
      </div>

      <div className="mb-8 grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-4">
          <h2 className="mb-3 text-sm font-semibold text-zinc-300">Risk Distribution</h2>
          <div className="space-y-2">
            {Object.entries(data.classification_breakdown).map(([label, count]) => (
              <div key={label} className="flex items-center gap-3">
                <span className={`w-24 shrink-0 rounded border px-2 py-0.5 text-center text-xs font-medium ${classificationStyle(label)}`}>
                  {label}
                </span>
                <div className="h-2 flex-1 rounded-full bg-zinc-800">
                  <div
                    className="h-2 rounded-full bg-cyan-500"
                    style={{ width: `${(count / Math.max(data.total_cases, 1)) * 100}%` }}
                  />
                </div>
                <span className="w-6 text-right text-xs text-zinc-400">{count}</span>
              </div>
            ))}
            {Object.keys(data.classification_breakdown).length === 0 && (
              <p className="text-sm text-zinc-500">No cases analyzed yet.</p>
            )}
          </div>
        </div>

        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-4">
          <h2 className="mb-3 text-sm font-semibold text-zinc-300">Threat Categories</h2>
          <div className="space-y-2">
            {Object.entries(data.threat_category_breakdown).map(([label, count]) => (
              <div key={label} className="flex items-center justify-between rounded bg-zinc-950/50 px-3 py-1.5 text-sm">
                <span className="text-zinc-300">{titleCase(label)}</span>
                <span className="font-mono text-zinc-400">{count}</span>
              </div>
            ))}
            {Object.keys(data.threat_category_breakdown).length === 0 && (
              <p className="text-sm text-zinc-500">No cases analyzed yet.</p>
            )}
          </div>
        </div>
      </div>

      <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-4">
        <h2 className="mb-3 text-sm font-semibold text-zinc-300">Recent Investigations</h2>
        {data.recent_cases.length === 0 ? (
          <EmptyState
            icon={<InboxIcon />}
            title="No investigations yet"
            description="Upload an .eml file or scan your inbox with the Chrome extension to get started."
          />
        ) : (
          <div className="space-y-2">
            {data.recent_cases.map((c) => (
              <Link
                key={c.id}
                to={`/cases/${c.id}`}
                className="flex items-center justify-between rounded-md border border-zinc-800 px-3 py-2 text-sm transition hover:border-zinc-700 hover:bg-zinc-900"
              >
                <span className="text-zinc-200">{c.title || "(no subject)"}</span>
                <span className="flex items-center gap-3">
                  <span className={`rounded border px-2 py-0.5 text-xs ${classificationStyle(c.overall_risk_level)}`}>
                    {c.overall_risk_level}
                  </span>
                  <span className="text-xs text-zinc-500">{formatTimestamp(c.created_at)}</span>
                </span>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
