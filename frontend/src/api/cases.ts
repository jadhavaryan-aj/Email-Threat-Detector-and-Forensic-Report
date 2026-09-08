import { apiClient } from "./client";
import type {
  CaseDetail,
  CaseGraph,
  CaseNote,
  CaseSummary,
  DashboardStats,
  EvidenceLog,
  SharedIndicator,
  TimelineEvent,
  UploadResponse,
} from "../types/case";

export async function uploadEmail(file: File): Promise<UploadResponse> {
  const formData = new FormData();
  formData.append("file", file);
  const { data } = await apiClient.post<UploadResponse>("/cases/upload", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}

export async function listCases(minScore?: number): Promise<CaseSummary[]> {
  const { data } = await apiClient.get<CaseSummary[]>("/cases", {
    params: minScore !== undefined ? { min_score: minScore } : undefined,
  });
  return data;
}

export async function getCase(caseId: number): Promise<CaseDetail> {
  const { data } = await apiClient.get<CaseDetail>(`/cases/${caseId}`);
  return data;
}

export async function getDashboardStats(): Promise<DashboardStats> {
  const { data } = await apiClient.get<DashboardStats>("/dashboard/stats");
  return data;
}

export async function getCaseGraph(caseId: number): Promise<CaseGraph> {
  const { data } = await apiClient.get<CaseGraph>(`/cases/${caseId}/graph`);
  return data;
}

export async function getCaseIndicators(caseId: number): Promise<{ shared_infrastructure: SharedIndicator[] }> {
  const { data } = await apiClient.get(`/cases/${caseId}/indicators`);
  return data;
}

export async function getCaseTimeline(caseId: number): Promise<TimelineEvent[]> {
  const { data } = await apiClient.get<TimelineEvent[]>(`/cases/${caseId}/timeline`);
  return data;
}

export async function getCaseNotes(caseId: number): Promise<CaseNote[]> {
  const { data } = await apiClient.get<CaseNote[]>(`/cases/${caseId}/notes`);
  return data;
}

export async function addCaseNote(caseId: number, noteText: string, author = "analyst"): Promise<CaseNote> {
  const { data } = await apiClient.post<CaseNote>(`/cases/${caseId}/notes`, { note_text: noteText, author });
  return data;
}

export async function updateCaseStatus(caseId: number, status: string): Promise<void> {
  await apiClient.patch(`/cases/${caseId}/status`, { status });
}

export function getCaseReportUrl(caseId: number): string {
  return `/api/cases/${caseId}/report`;
}

export async function getCaseEvidenceLog(caseId: number): Promise<EvidenceLog> {
  const { data } = await apiClient.get<EvidenceLog>(`/cases/${caseId}/evidence-log`);
  return data;
}
