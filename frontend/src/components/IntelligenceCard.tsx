import type { DomainIntelligence, IpIntelligence } from "../types/case";

export function IpIntelCard({ intel }: { intel: IpIntelligence }) {
  if (!intel.available) {
    return (
      <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
        <p className="font-mono text-sm text-zinc-300">{intel.ip}</p>
        <p className="mt-1 text-xs text-zinc-500">Unavailable — {intel.unavailable_reason || "lookup failed"}</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
      <div className="mb-2 flex items-center justify-between">
        <p className="font-mono text-sm font-medium text-zinc-100">{intel.ip}</p>
        {intel.dnsbl_listed && (
          <span className="rounded border border-red-600/40 bg-red-600/10 px-1.5 py-0.5 text-[10px] font-semibold text-red-400 uppercase">
            Listed (Spamhaus)
          </span>
        )}
      </div>
      <dl className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
        <dt className="text-zinc-500">ASN</dt>
        <dd className="text-zinc-300">{intel.asn ?? "unavailable"}</dd>
        <dt className="text-zinc-500">Organization</dt>
        <dd className="text-zinc-300">{intel.asn_org ?? intel.isp_org ?? "unavailable"}</dd>
        <dt className="text-zinc-500">Country</dt>
        <dd className="text-zinc-300">{intel.country ?? "unavailable"}</dd>
        <dt className="text-zinc-500">Region / City</dt>
        <dd className="text-zinc-300">{[intel.region, intel.city].filter(Boolean).join(", ") || "unavailable"}</dd>
        {intel.is_vpn_or_proxy_or_tor !== null && (
          <>
            <dt className="text-zinc-500">Proxy/VPN</dt>
            <dd className="text-zinc-300">{intel.is_vpn_or_proxy_or_tor ? "yes" : "no"}</dd>
          </>
        )}
      </dl>
      <p className="mt-2 border-t border-zinc-800 pt-2 text-[11px] text-zinc-500 italic">{intel.disclaimer}</p>
    </div>
  );
}

export function DomainIntelCard({ intel }: { intel: DomainIntelligence }) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
      <div className="mb-2 flex items-center justify-between">
        <p className="font-mono text-sm font-medium text-zinc-100">{intel.domain}</p>
        {intel.dnsbl_listed && (
          <span className="rounded border border-red-600/40 bg-red-600/10 px-1.5 py-0.5 text-[10px] font-semibold text-red-400 uppercase">
            Listed (DBL)
          </span>
        )}
      </div>
      <dl className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
        <dt className="text-zinc-500">Registrar</dt>
        <dd className="text-zinc-300">{intel.registrar ?? "unavailable"}</dd>
        <dt className="text-zinc-500">Created</dt>
        <dd className="text-zinc-300">{intel.created_date ?? "unavailable"}</dd>
        <dt className="text-zinc-500">Age</dt>
        <dd className="text-zinc-300">{intel.age_days !== null ? `${intel.age_days} days` : "unavailable"}</dd>
        <dt className="text-zinc-500">MX records</dt>
        <dd className="truncate text-zinc-300" title={intel.mx_records.join(", ")}>
          {intel.mx_records.length ? intel.mx_records.join(", ") : "none"}
        </dd>
      </dl>
      {!intel.available && intel.unavailable_reason && (
        <p className="mt-2 text-[11px] text-zinc-500">Partial data — {intel.unavailable_reason}</p>
      )}
    </div>
  );
}
