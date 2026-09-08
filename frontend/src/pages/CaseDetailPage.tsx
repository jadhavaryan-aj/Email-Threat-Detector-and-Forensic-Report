import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  getCase,
  getCaseGraph,
  getCaseIndicators,
  getCaseReportUrl,
  getCaseTimeline,
  updateCaseStatus,
} from "../api/cases";
import { CaseNotesPanel } from "../components/CaseNotesPanel";
import { CorrelationGraph } from "../components/CorrelationGraph";
import { EvidenceLogPanel } from "../components/EvidenceLogPanel";
import { FraudScoreBadge } from "../components/FraudScoreBadge";
import { HeaderTraceTable } from "../components/HeaderTraceTable";
import { DomainIntelCard, IpIntelCard } from "../components/IntelligenceCard";
import { IdentityPanel } from "../components/IdentityPanel";
import { SectionHeading } from "../components/SectionHeading";
import { Skeleton } from "../components/Skeleton";
import { SignalCard } from "../components/SignalCard";
import { TimelineView } from "../components/TimelineView";
import type { DetectionResult, EmailAnalysisDetail, Signal } from "../types/case";
import { caseStatusStyle, titleCase } from "../utils/severityColors";

const STATUS_OPTIONS = ["new", "investigating", "escalated", "resolved", "false_positive"];

function buildExecutiveSummary(detection: DetectionResult | null, signals: Signal[]): string {
  if (!detection) return "No detection result available for this email.";
  if (detection.classification_label === "legitimate") {
    return (
      "This email shows no significant risk indicators: authentication checks passed and no " +
      "suspicious identity, content, or infrastructure patterns were detected."
    );
  }

  const topSignals = [...signals].sort((a, b) => b.score - a.score).slice(0, 3);
  const signalPhrase = topSignals.map((s) => titleCase(s.name).toLowerCase()).join(", ");
  const secondary = detection.secondary_indicators.length
    ? ` Secondary indicators suggest possible ${detection.secondary_indicators.map(titleCase).join(" / ")}.`
    : "";

  return (
    `This email was classified as ${titleCase(detection.threat_category)} with a risk score of ` +
    `${detection.fraud_score}/100. The strongest contributing evidence: ${signalPhrase || "multiple risk signals"}.` +
    secondary
  );
}

function AuthTile({ label, result, detail }: { label: string; result: string; detail: string }) {
  const isPass = result === "pass";
  const isFail = result === "fail";
  return (
    <div
      className={`rounded-lg border px-3 py-2 ${
        isPass ? "border-emerald-600/40 bg-emerald-500/5" : isFail ? "border-red-600/40 bg-red-500/5" : "border-zinc-800 bg-zinc-900/40"
      }`}
    >
      <p className="text-[10px] font-medium tracking-wide text-zinc-500 uppercase">{label}</p>
      <p className={`font-semibold uppercase ${isPass ? "text-emerald-400" : isFail ? "text-red-400" : "text-zinc-400"}`}>
        {result}
      </p>
      <p className="truncate text-xs text-zinc-500" title={detail}>
        {detail}
      </p>
    </div>
  );
}

function EmailBlock({ email, caseId }: { email: EmailAnalysisDetail; caseId: number }) {
  const detection = email.detection_result;
  const header = email.header_auth_result;
  const sortedSignals = [...email.signals].sort((a, b) => b.score - a.score);

  return (
    <div className="mb-8 rounded-xl border border-zinc-800 bg-zinc-900/40 p-5">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-medium text-zinc-100">{email.subject || "(no subject)"}</p>
          <p className="text-sm text-zinc-500">
            From {email.from_display_name ? `${email.from_display_name} <${email.from_address}>` : email.from_address}
          </p>
        </div>
        {detection && <FraudScoreBadge label={detection.classification_label} score={detection.fraud_score} />}
      </div>

      <section className="mb-5 rounded-lg border border-cyan-900/40 bg-cyan-950/20 p-3">
        <h2 className="mb-1 text-xs font-semibold tracking-wide text-cyan-400 uppercase">Executive Summary</h2>
        <p className="text-sm text-zinc-200">{buildExecutiveSummary(detection, email.signals)}</p>
      </section>

      <section className="mb-6">
        <SectionHeading count={sortedSignals.length}>Risk Breakdown</SectionHeading>
        {sortedSignals.length > 0 ? (
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
            {sortedSignals.map((s) => (
              <SignalCard key={s.id} signal={s} />
            ))}
          </div>
        ) : (
          <p className="text-sm text-zinc-500">No risk signals were raised for this email.</p>
        )}
      </section>

      <section className="mb-6">
        <SectionHeading>Email Identity</SectionHeading>
        <IdentityPanel email={email} />
      </section>

      {header && (
        <>
          <section className="mb-6">
            <SectionHeading>Authentication (SPF / DKIM / DMARC)</SectionHeading>
            <div className="grid grid-cols-3 gap-3">
              <AuthTile label="SPF" result={header.spf_result} detail={header.spf_domain} />
              <AuthTile label="DKIM" result={header.dkim_result} detail={header.dkim_domain || "no signature"} />
              <AuthTile label="DMARC" result={header.dmarc_result} detail={`policy: ${header.dmarc_policy || "none"}`} />
            </div>
            {header.routing_anomaly_flags.length > 0 && (
              <ul className="mt-3 space-y-1 text-sm text-orange-400">
                {header.routing_anomaly_flags.map((flag) => (
                  <li key={flag}>⚠ {titleCase(flag)}</li>
                ))}
              </ul>
            )}
          </section>

          <section className="mb-6">
            <SectionHeading>Received Chain (Header Trace)</SectionHeading>
            <HeaderTraceTable hops={header.received_chain} />
          </section>
        </>
      )}

      {detection && detection.fraud_score >= 90 && email.ip_intelligence[0]?.available && (
        <section className="mb-5 rounded-lg border border-red-600/40 bg-red-950/20 p-4">
          <h2 className="mb-1 flex items-center gap-2 text-xs font-semibold tracking-wide text-red-400 uppercase">
            <span className="h-2 w-2 animate-pulse rounded-full bg-red-500" />
            Critical Risk — Origin Traced
          </h2>
          <p className="text-lg font-semibold text-zinc-100">
            {[email.ip_intelligence[0].city, email.ip_intelligence[0].region, email.ip_intelligence[0].country]
              .filter(Boolean)
              .join(", ") || "Location unavailable"}
          </p>
          <p className="mt-0.5 font-mono text-xs text-zinc-400">
            {email.ip_intelligence[0].ip}
            {email.ip_intelligence[0].asn_org ? ` · ${email.ip_intelligence[0].asn_org}` : ""}
          </p>
          <p className="mt-2 text-[11px] text-zinc-500 italic">{email.ip_intelligence[0].disclaimer}</p>
        </section>
      )}

      {(email.ip_intelligence.length > 0 || email.domain_intelligence.length > 0) && (
        <section className="mb-6">
          <SectionHeading>Infrastructure Intelligence</SectionHeading>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            {email.ip_intelligence.map((ip) => (
              <IpIntelCard key={ip.ip} intel={ip} />
            ))}
            {email.domain_intelligence.map((d) => (
              <DomainIntelCard key={d.domain} intel={d} />
            ))}
          </div>
        </section>
      )}

      {email.extracted_urls.length > 0 && (
        <section className="mb-6">
          <SectionHeading count={email.extracted_urls.length}>URL Analysis</SectionHeading>
          <div className="overflow-x-auto rounded-lg border border-zinc-800">
            <table className="min-w-full divide-y divide-zinc-800 text-sm">
              <thead className="bg-zinc-900">
                <tr>
                  <th className="px-3 py-2 text-left font-medium text-zinc-400">URL</th>
                  <th className="px-3 py-2 text-left font-medium text-zinc-400">Risk</th>
                  <th className="px-3 py-2 text-left font-medium text-zinc-400">Flags</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800 bg-zinc-950">
                {email.extracted_urls.map((u) => (
                  <tr key={u.raw_url}>
                    <td className="max-w-xs truncate px-3 py-2 font-mono text-xs text-zinc-300" title={u.raw_url}>
                      {u.raw_url}
                    </td>
                    <td className="px-3 py-2 text-zinc-300">{u.lexical_risk_score}</td>
                    <td className="px-3 py-2 text-xs text-orange-400">
                      {[
                        u.is_ip_based && "IP-based",
                        u.has_punycode && "punycode",
                        u.is_shortener && "shortener",
                        u.display_text_mismatch && "display-mismatch",
                        u.lookalike_of_brand && `lookalike:${u.lookalike_of_brand}`,
                      ]
                        .filter(Boolean)
                        .join(", ") || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <section className="mb-6">
        <SectionHeading>Evidence</SectionHeading>
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3 text-sm">
          <p className="text-zinc-500">
            Original filename: <span className="font-mono text-zinc-300">{email.original_filename || "unknown"}</span>
          </p>
          <p className="mt-1 text-zinc-500">
            SHA-256: <span className="font-mono text-zinc-300">{email.raw_eml_sha256}</span>
          </p>
        </div>
      </section>

      <section>
        <SectionHeading>Body</SectionHeading>
        <pre className="max-h-64 overflow-auto rounded-lg border border-zinc-800 bg-zinc-950 p-3 text-xs whitespace-pre-wrap text-zinc-400">
          {email.body_text || "(no plain-text body)"}
        </pre>
      </section>

      <p className="mt-3 text-[11px] text-zinc-600">Case #{caseId} · Email analysis #{email.id}</p>
    </div>
  );
}

function CaseDetailSkeleton() {
  return (
    <div>
      <Skeleton className="h-4 w-28" />
      <div className="mt-2 mb-6 flex items-center justify-between">
        <Skeleton className="h-7 w-72" />
        <Skeleton className="h-8 w-40" />
      </div>
      <div className="mb-8 rounded-xl border border-zinc-800 bg-zinc-900/40 p-5">
        <Skeleton className="mb-4 h-5 w-96" />
        <Skeleton className="mb-5 h-16 w-full" />
        <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-20 w-full" />
          ))}
        </div>
      </div>
    </div>
  );
}

export function CaseDetailPage() {
  const { caseId: caseIdParam } = useParams<{ caseId: string }>();
  const caseId = Number(caseIdParam);
  const queryClient = useQueryClient();
  const [statusDraft, setStatusDraft] = useState<string | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ["case", caseId],
    queryFn: () => getCase(caseId),
    enabled: !!caseId,
  });
  const { data: graph } = useQuery({ queryKey: ["case-graph", caseId], queryFn: () => getCaseGraph(caseId), enabled: !!caseId });
  const { data: indicators } = useQuery({
    queryKey: ["case-indicators", caseId],
    queryFn: () => getCaseIndicators(caseId),
    enabled: !!caseId,
  });
  const { data: timeline } = useQuery({
    queryKey: ["case-timeline", caseId],
    queryFn: () => getCaseTimeline(caseId),
    enabled: !!caseId,
  });

  const statusMutation = useMutation({
    mutationFn: (status: string) => updateCaseStatus(caseId, status),
    onSuccess: (_data, status) => {
      setStatusDraft(status);
      queryClient.invalidateQueries({ queryKey: ["case", caseId] });
      queryClient.invalidateQueries({ queryKey: ["case-timeline", caseId] });
      queryClient.invalidateQueries({ queryKey: ["cases"] });
    },
  });

  if (isLoading) return <CaseDetailSkeleton />;
  if (error || !data) return <p className="text-sm text-red-400">Case not found.</p>;

  const currentStatus = statusDraft ?? data.status;
  const primaryDetection = data.email_analyses[0]?.detection_result;

  return (
    <div>
      <Link to="/cases" className="text-sm text-cyan-400 hover:underline">
        &larr; Back to cases
      </Link>

      <div className="mt-2 mb-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100">
            CASE-{String(data.id).padStart(4, "0")}
            <span className="ml-2 text-zinc-500">— {data.title}</span>
          </h1>
          {primaryDetection && (
            <p className="mt-1 text-sm text-zinc-400">{titleCase(primaryDetection.threat_category)}</p>
          )}
        </div>
        <div className="flex items-center gap-3">
          {primaryDetection && <FraudScoreBadge label={primaryDetection.classification_label} score={primaryDetection.fraud_score} />}
          <select
            value={currentStatus}
            onChange={(e) => statusMutation.mutate(e.target.value)}
            className={`rounded-md border bg-zinc-950 px-2 py-1.5 text-xs font-medium ${caseStatusStyle(currentStatus)}`}
          >
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s} className="bg-zinc-900 text-zinc-100">
                {titleCase(s)}
              </option>
            ))}
          </select>
          <a
            href={getCaseReportUrl(data.id)}
            target="_blank"
            rel="noreferrer"
            className="rounded-md bg-zinc-100 px-3 py-1.5 text-xs font-semibold text-zinc-900 transition hover:bg-white"
          >
            Export Report
          </a>
        </div>
      </div>

      {data.email_analyses.map((email) => (
        <EmailBlock key={email.id} email={email} caseId={data.id} />
      ))}

      <section className="mb-8 rounded-xl border border-zinc-800 bg-zinc-900/40 p-5">
        <SectionHeading>Threat Correlation</SectionHeading>
        {graph && <CorrelationGraph graph={graph} rootId={`case:${data.id}`} />}
        {indicators && indicators.shared_infrastructure.length > 0 && (
          <div className="mt-3 space-y-1.5">
            {indicators.shared_infrastructure.map((item) => (
              <p key={`${item.indicator_type}:${item.indicator_value}`} className="text-sm text-amber-400">
                ⚠ Potential shared infrastructure: <span className="font-mono">{item.indicator_value}</span> also
                observed in case(s) {item.other_case_ids.join(", ")}. {item.note}
              </p>
            ))}
          </div>
        )}
      </section>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <section className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5">
          <SectionHeading>Investigation Timeline</SectionHeading>
          <TimelineView events={timeline ?? []} />
        </section>
        <section className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5">
          <SectionHeading>Analyst Notes</SectionHeading>
          <CaseNotesPanel caseId={data.id} />
        </section>
      </div>

      <section className="mt-6 rounded-xl border border-zinc-800 bg-zinc-900/40 p-5">
        <SectionHeading>Evidence Log</SectionHeading>
        <EvidenceLogPanel caseId={data.id} />
      </section>
    </div>
  );
}
