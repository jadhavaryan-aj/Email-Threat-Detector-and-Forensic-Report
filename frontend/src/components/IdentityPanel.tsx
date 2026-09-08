import type { EmailAnalysisDetail } from "../types/case";

function domainOf(address: string): string {
  return address.includes("@") ? address.split("@")[1] : "";
}

function IdentityRow({
  label,
  value,
  mismatchWith,
}: {
  label: string;
  value: string;
  mismatchWith?: string;
}) {
  const mismatched = Boolean(mismatchWith && value && domainOf(value) !== domainOf(mismatchWith));
  return (
    <div className={`rounded-md border px-3 py-2 ${mismatched ? "border-orange-500/40 bg-orange-500/5" : "border-zinc-800 bg-zinc-900/40"}`}>
      <p className="text-[10px] font-medium tracking-wide text-zinc-500 uppercase">{label}</p>
      <p className={`font-mono text-sm ${mismatched ? "text-orange-300" : "text-zinc-200"}`}>{value || "(not set)"}</p>
      {mismatched && <p className="mt-0.5 text-[11px] text-orange-400">⚠ domain differs from From:</p>}
    </div>
  );
}

export function IdentityPanel({ email }: { email: EmailAnalysisDetail }) {
  const fromLine = email.from_display_name
    ? `${email.from_display_name} <${email.from_address}>`
    : email.from_address;

  return (
    <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
      <IdentityRow label="From" value={fromLine} />
      <IdentityRow label="Reply-To" value={email.reply_to} mismatchWith={email.from_address} />
      <IdentityRow label="Return-Path" value={email.return_path} mismatchWith={email.from_address} />
    </div>
  );
}
