import { useEffect, useState } from "react";
import { Activity, CheckCircle2, Clock, ServerCrash, ShieldCheck } from "lucide-react";
import { getHealth, getRecentJobs } from "../services/apiService";
import type { HealthStatus, JobStatus } from "../types";

type ServiceTile = {
  label: string;
  value: "UP" | "DOWN";
};

export function OperationsDashboard({ refreshKey }: { refreshKey: number }) {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [jobs, setJobs] = useState<JobStatus[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function refresh() {
      try {
        const [nextHealth, nextJobs] = await Promise.all([
          getHealth(),
          getRecentJobs(8),
        ]);
        if (!cancelled) {
          setHealth(nextHealth);
          setJobs(nextJobs);
          setError(null);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Dashboard refresh failed");
        }
      }
    }

    refresh();
    const interval = window.setInterval(refresh, 10000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [refreshKey]);

  const services: ServiceTile[] = [
    { label: "Gateway", value: health?.gateway ?? "DOWN" },
    { label: "Enclave", value: health?.enclave ?? "DOWN" },
    { label: "NSM", value: health?.nsm ?? "DOWN" },
    { label: "KMS", value: health?.kms ?? "DOWN" },
    { label: "spaCy", value: health?.spacy ?? "DOWN" },
  ];

  return (
    <section style={{ marginBottom: 24 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(132px, 1fr))", gap: 8 }}>
        {services.map((service) => (
          <div
            key={service.label}
            style={{
              border: "1px solid #e5e7eb",
              borderRadius: 8,
              padding: "10px 12px",
              background: "white",
              minHeight: 58,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 6, color: "#6b7280", fontSize: 12 }}>
              {service.value === "UP" ? (
                <CheckCircle2 size={14} color="#16a34a" />
              ) : (
                <ServerCrash size={14} color="#dc2626" />
              )}
              {service.label}
            </div>
            <div style={{ marginTop: 6, fontSize: 18, fontWeight: 600, color: service.value === "UP" ? "#166534" : "#991b1b" }}>
              {service.value}
            </div>
          </div>
        ))}
      </div>

      <div style={{ marginTop: 12, border: "1px solid #e5e7eb", borderRadius: 8, overflow: "hidden", background: "white" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 12px", borderBottom: "1px solid #e5e7eb" }}>
          <Activity size={16} color="#2563eb" />
          <h2 style={{ fontSize: 14, margin: 0 }}>Recent Requests</h2>
          {error && <span style={{ marginLeft: "auto", color: "#991b1b", fontSize: 12 }}>{error}</span>}
        </div>

        {jobs.length === 0 ? (
          <div style={{ padding: "14px 12px", color: "#6b7280", fontSize: 13 }}>No jobs for this principal yet.</div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
            <thead>
              <tr style={{ textAlign: "left", background: "#f9fafb", color: "#4b5563" }}>
                <th style={{ padding: "8px 12px", fontWeight: 500 }}>Job</th>
                <th style={{ padding: "8px 12px", fontWeight: 500 }}>Status</th>
                <th style={{ padding: "8px 12px", fontWeight: 500 }}>Updated</th>
                <th style={{ padding: "8px 12px", fontWeight: 500 }}>Runtime</th>
                <th style={{ padding: "8px 12px", fontWeight: 500 }}>Attestation</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={job.jobId} style={{ borderTop: "1px solid #f3f4f6" }}>
                  <td style={{ padding: "8px 12px", fontFamily: "monospace" }}>{job.jobId.slice(0, 8)}</td>
                  <td style={{ padding: "8px 12px" }}>{statusPill(job.status)}</td>
                  <td style={{ padding: "8px 12px", color: "#6b7280" }}>{formatTime(job.updatedAt)}</td>
                  <td style={{ padding: "8px 12px", color: "#6b7280" }}>
                    {job.processingTimeMs == null ? "-" : `${job.processingTimeMs} ms`}
                  </td>
                  <td style={{ padding: "8px 12px", color: "#6b7280" }}>
                    {job.attestationHash ? (
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                        <ShieldCheck size={13} color="#059669" />
                        {job.attestationHash.slice(0, 10)}
                      </span>
                    ) : (
                      "-"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}

function statusPill(status: JobStatus["status"]) {
  const color = status === "COMPLETED" ? "#166534" : status === "FAILED" ? "#991b1b" : "#92400e";
  const background = status === "COMPLETED" ? "#dcfce7" : status === "FAILED" ? "#fee2e2" : "#fef3c7";
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 8px", borderRadius: 999, background, color }}>
      <Clock size={12} />
      {status}
    </span>
  );
}

function formatTime(value: string) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return "-";
  }
  return parsed.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
