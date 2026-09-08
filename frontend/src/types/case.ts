export type ClassificationLabel = "legitimate" | "suspicious" | "impersonated" | "phishing" | "fraud";

export type ThreatCategory =
  | "legitimate"
  | "spam"
  | "phishing"
  | "spear_phishing"
  | "business_email_compromise"
  | "spoofing"
  | "credential_theft"
  | "malware_delivery"
  | "suspicious_unknown";

export type CaseStatus = "new" | "investigating" | "escalated" | "resolved" | "false_positive";

export type SignalSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface CaseSummary {
  case_id: number;
  email_analysis_id: number;
  subject: string;
  from_address: string;
  fraud_score: number;
  classification_label: ClassificationLabel;
  threat_category: ThreatCategory;
  status: CaseStatus;
  source_url: string;
  created_at: string;
}

export interface ReceivedHop {
  hop_index: number;
  raw: string;
  from_host: string | null;
  by_host: string | null;
  ip: string | null;
  timestamp: string | null;
}

export interface AuthCrossCheckEntry {
  upstream: string | null;
  ours: string;
  agreement: "match" | "mismatch" | "no_upstream_data";
}

export interface HeaderAuthResult {
  spf_result: string;
  spf_domain: string;
  dkim_result: string;
  dkim_domain: string;
  dmarc_result: string;
  dmarc_policy: string;
  spf_aligned: boolean;
  dkim_aligned: boolean;
  routing_anomaly_flags: string[];
  received_chain: ReceivedHop[];
  auth_cross_check: Record<string, AuthCrossCheckEntry>;
}

export interface DetectionResult {
  classification_label: ClassificationLabel;
  fraud_score: number;
  threat_category: ThreatCategory;
  secondary_indicators: string[];
}

export interface Signal {
  id: number;
  name: string;
  category: "authentication" | "identity" | "content" | "infrastructure" | "reputation" | "url";
  severity: SignalSeverity;
  score: number;
  explanation: string;
  evidence: string;
}

export interface ExtractedUrl {
  raw_url: string;
  anchor_text: string | null;
  normalized_url: string;
  hostname: string;
  registered_domain: string;
  scheme: string;
  is_ip_based: boolean;
  subdomain_count: number;
  has_punycode: boolean;
  is_shortener: boolean;
  display_text_mismatch: boolean;
  lookalike_of_brand: string | null;
  lexical_risk_score: number;
}

export interface DomainIntelligence {
  domain: string;
  registered_domain: string;
  mx_records: string[];
  nameservers: string[];
  registrar: string | null;
  created_date: string | null;
  age_days: number | null;
  dnsbl_listed: boolean;
  source: string;
  available: boolean;
  unavailable_reason: string | null;
}

export interface IpIntelligence {
  ip: string;
  ip_version: number;
  is_public: boolean;
  asn: string | null;
  asn_org: string | null;
  country: string | null;
  region: string | null;
  city: string | null;
  isp_org: string | null;
  is_vpn_or_proxy_or_tor: boolean | null;
  dnsbl_listed: boolean;
  source: string;
  available: boolean;
  unavailable_reason: string | null;
  disclaimer: string;
}

export interface ThreatIntelResult {
  provider: string;
  indicator_type: string;
  indicator_value: string;
  available: boolean;
  verdict: string | null;
}

export interface Attachment {
  filename: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
}

export interface EmailAnalysisDetail {
  id: number;
  original_filename: string;
  source_url: string;
  subject: string;
  from_display_name: string;
  from_address: string;
  reply_to: string;
  return_path: string;
  to_addresses: string[];
  cc_addresses: string[];
  date_header: string;
  message_id: string;
  authentication_results: { raw: string[]; parsed_tokens: Record<string, string> };
  mime_structure: string[];
  body_text: string;
  attachments: Attachment[];
  raw_eml_sha256: string;
  created_at: string;
  header_auth_result: HeaderAuthResult | null;
  detection_result: DetectionResult | null;
  signals: Signal[];
  extracted_urls: ExtractedUrl[];
  domain_intelligence: DomainIntelligence[];
  ip_intelligence: IpIntelligence[];
  threat_intel_results: ThreatIntelResult[];
}

export interface CaseDetail {
  id: number;
  title: string;
  status: CaseStatus;
  overall_risk_level: ClassificationLabel | "unknown";
  created_at: string;
  email_analyses: EmailAnalysisDetail[];
}

export interface UploadResponse {
  case_id: number;
  email_analysis_id: number;
  status: string;
}

export interface TimelineEvent {
  id: number;
  case_id: number;
  email_analysis_id: number | null;
  event_type: string;
  description: string;
  occurred_at: string;
}

export interface CaseNote {
  id: number;
  case_id: number;
  author: string;
  note_text: string;
  created_at: string;
}

export interface EvidenceLogEntry {
  id: number;
  case_id: number;
  email_analysis_id: number | null;
  action: string;
  payload: Record<string, unknown>;
  prev_entry_hash: string;
  entry_hash: string;
  created_at: string;
}

export interface EvidenceLog {
  valid: boolean;
  first_broken_index: number | null;
  entries: EvidenceLogEntry[];
}

export interface GraphNode {
  id: string;
  type: "case" | "ip" | "domain";
  label: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  relationship: "observed_in" | "potential_correlation";
}

export interface CaseGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface SharedIndicator {
  indicator_type: string;
  indicator_value: string;
  other_case_ids: number[];
  note: string;
}

export interface DashboardStats {
  total_cases: number;
  high_risk_count: number;
  critical_count: number;
  potential_campaigns: number;
  investigations_today: number;
  classification_breakdown: Record<string, number>;
  threat_category_breakdown: Record<string, number>;
  recent_cases: {
    id: number;
    title: string;
    overall_risk_level: string;
    status: CaseStatus;
    created_at: string;
  }[];
}
