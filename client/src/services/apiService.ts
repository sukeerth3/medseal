/**
 * API client for the MedSeal gateway.
 */

import type {
  EncryptedPayload,
  ProcessResponse,
  JobStatus,
  HealthStatus,
} from "../types";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8080";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const headers = new Headers(options?.headers);
  headers.set("Content-Type", "application/json");

  const token = authToken();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: "Request failed" }));
    throw new Error(error.error || `HTTP ${response.status}`);
  }

  return response.json();
}

function authToken(): string | undefined {
  const envToken = import.meta.env.VITE_MEDSEAL_TOKEN;
  if (envToken) {
    return envToken;
  }

  try {
    return window.localStorage.getItem("medsealToken") || undefined;
  } catch {
    return undefined;
  }
}

export async function submitForProcessing(
  payload: EncryptedPayload
): Promise<ProcessResponse> {
  return request<ProcessResponse>("/api/v1/process", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function getJobStatus(jobId: string): Promise<JobStatus> {
  return request<JobStatus>(`/api/v1/jobs/${jobId}`);
}

export async function getRecentJobs(limit = 10): Promise<JobStatus[]> {
  return request<JobStatus[]>(`/api/v1/jobs?limit=${limit}`);
}

export async function getHealth(): Promise<HealthStatus> {
  return request<HealthStatus>("/api/v1/health");
}
