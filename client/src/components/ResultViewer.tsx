import { ShieldCheck, AlertTriangle } from "lucide-react";
import type { ProcessingOutput } from "../types";

interface Props {
  result: ProcessingOutput;
}

export function ResultViewer({ result }: Props) {
  const { deidentification, classification } = result;

  return (
    <div style={{ marginTop: 24 }}>
      {/* De-identified text */}
      <div style={{ background: "#f9fafb", borderRadius: 8, padding: 16, marginBottom: 16 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, margin: "0 0 8px", display: "flex", alignItems: "center", gap: 6 }}>
          <ShieldCheck size={16} color="#16a34a" />
          De-identified Record
        </h3>
        <pre style={{
          fontSize: 13, lineHeight: 1.6, whiteSpace: "pre-wrap",
          fontFamily: "monospace", margin: 0, color: "#333"
        }}>
          {deidentification.deidentified_text}
        </pre>
        <div style={{ marginTop: 12, fontSize: 12, color: "#666" }}>
          {deidentification.entity_count} PHI entities removed
          (avg confidence: {(deidentification.confidence_score * 100).toFixed(0)}%)
        </div>
      </div>

      {/* PHI entities found */}
      {deidentification.entities_found.length > 0 && (
        <div style={{ background: "#fffbeb", borderRadius: 8, padding: 16, marginBottom: 16 }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, margin: "0 0 8px", display: "flex", alignItems: "center", gap: 6 }}>
            <AlertTriangle size={16} color="#d97706" />
            PHI Entities Detected & Redacted
          </h3>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {deidentification.entities_found.map((entity, i) => (
              <span
                key={i}
                style={{
                  fontSize: 12, padding: "3px 8px", borderRadius: 4,
                  background: "#fef3c7", border: "1px solid #fcd34d",
                }}
              >
                {entity.type} ({entity.source}, {(entity.confidence * 100).toFixed(0)}%)
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ICD-10 codes */}
      <div style={{ background: "#f0fdf4", borderRadius: 8, padding: 16, marginBottom: 16 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, margin: "0 0 12px" }}>
          ICD-10 Classification
        </h3>
        {classification.icd_codes.length === 0 ? (
          <p style={{ fontSize: 13, color: "#666", margin: 0 }}>No conditions identified.</p>
        ) : (
          <table style={{ width: "100%", fontSize: 13, borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ textAlign: "left", borderBottom: "1px solid #e5e7eb" }}>
                <th style={{ padding: "6px 8px", fontWeight: 500 }}>Code</th>
                <th style={{ padding: "6px 8px", fontWeight: 500 }}>Description</th>
                <th style={{ padding: "6px 8px", fontWeight: 500 }}>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {classification.icd_codes.map((code, i) => (
                <tr key={i} style={{ borderBottom: "1px solid #f3f4f6" }}>
                  <td style={{ padding: "6px 8px", fontFamily: "monospace" }}>{code.code}</td>
                  <td style={{ padding: "6px 8px" }}>{code.description}</td>
                  <td style={{ padding: "6px 8px" }}>{(code.confidence * 100).toFixed(0)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {/* Risk score */}
        <div style={{ marginTop: 16, display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ fontSize: 13, fontWeight: 500 }}>Risk Score:</span>
          <div style={{
            flex: 1, height: 8, background: "#e5e7eb", borderRadius: 4, overflow: "hidden"
          }}>
            <div style={{
              height: "100%", borderRadius: 4,
              width: `${classification.risk_score * 100}%`,
              background: classification.risk_score > 0.7 ? "#dc2626"
                : classification.risk_score > 0.4 ? "#f59e0b" : "#16a34a",
              transition: "width 0.5s ease",
            }} />
          </div>
          <span style={{ fontSize: 13, fontWeight: 600, minWidth: 40 }}>
            {(classification.risk_score * 100).toFixed(0)}%
          </span>
        </div>

        {classification.risk_factors.length > 0 && (
          <div style={{ marginTop: 8, fontSize: 12, color: "#666" }}>
            Risk factors: {classification.risk_factors.join(", ")}
          </div>
        )}
      </div>
    </div>
  );
}
