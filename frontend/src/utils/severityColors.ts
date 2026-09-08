export const CLASSIFICATION_STYLES: Record<string, string> = {
  legitimate: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
  suspicious: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  impersonated: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  phishing: "bg-red-500/10 text-red-400 border-red-500/30",
  fraud: "bg-red-600/15 text-red-400 border-red-600/40",
};

export const SEVERITY_STYLES: Record<string, string> = {
  LOW: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
  MEDIUM: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  HIGH: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  CRITICAL: "bg-red-600/15 text-red-400 border-red-600/40",
};

export const CASE_STATUS_STYLES: Record<string, string> = {
  new: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
  investigating: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  escalated: "bg-red-500/10 text-red-400 border-red-500/30",
  resolved: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
  false_positive: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
};

export function classificationStyle(label: string): string {
  return CLASSIFICATION_STYLES[label] ?? "bg-zinc-500/10 text-zinc-400 border-zinc-500/30";
}

export function severityStyle(severity: string): string {
  return SEVERITY_STYLES[severity] ?? "bg-zinc-500/10 text-zinc-400 border-zinc-500/30";
}

export function caseStatusStyle(status: string): string {
  return CASE_STATUS_STYLES[status] ?? "bg-zinc-500/10 text-zinc-400 border-zinc-500/30";
}

export function titleCase(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
