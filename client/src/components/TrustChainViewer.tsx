import { CheckCircle, Lock, Cpu, KeyRound } from "lucide-react";

interface Props {
  attestationHash: string;
  processingTimeMs: number;
  jobId: string;
}

export function TrustChainViewer({ attestationHash, processingTimeMs, jobId }: Props) {
  const steps = [
    { icon: Lock, label: "Client Encrypted", detail: "AES-256-GCM envelope encryption", color: "#2563eb" },
    { icon: Cpu, label: "Enclave Attested", detail: `Hash: ${attestationHash?.slice(0, 16)}...`, color: "#7c3aed" },
    { icon: KeyRound, label: "KMS Key Released", detail: "PCR-verified attestation", color: "#059669" },
    { icon: CheckCircle, label: "Processed & Re-encrypted", detail: `${processingTimeMs}ms inside enclave`, color: "#16a34a" },
  ];

  return (
    <div style={{ background: "#f9fafb", borderRadius: 8, padding: 16, marginBottom: 16 }}>
      <h3 style={{ fontSize: 14, fontWeight: 600, margin: "0 0 12px" }}>
        Trust Chain: Job {jobId.slice(0, 8)}...
      </h3>

      <div style={{ display: "flex", gap: 4, alignItems: "center", flexWrap: "wrap" }}>
        {steps.map((step, i) => {
          const Icon = step.icon;
          return (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <div style={{
                display: "flex", alignItems: "center", gap: 6,
                padding: "6px 10px", borderRadius: 6,
                background: "white", border: "1px solid #e5e7eb",
                fontSize: 12,
              }}>
                <Icon size={14} color={step.color} />
                <div>
                  <div style={{ fontWeight: 500 }}>{step.label}</div>
                  <div style={{ color: "#999", fontSize: 11 }}>{step.detail}</div>
                </div>
              </div>
              {i < steps.length - 1 && (
                <span style={{ color: "#d1d5db", fontSize: 16 }}>→</span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
