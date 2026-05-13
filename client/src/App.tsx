import { useState } from "react";
import { UploadForm } from "./components/UploadForm";
import { ResultViewer } from "./components/ResultViewer";
import { TrustChainViewer } from "./components/TrustChainViewer";
import { OperationsDashboard } from "./components/OperationsDashboard";
import { encryptFile, decryptResult } from "./services/encryptionService";
import { submitForProcessing } from "./services/apiService";
import type { ProcessingOutput, ProcessResponse } from "./types";
import {
  Shield,
  Lock,
  FileCheck,
  Activity,
} from "lucide-react";

type AppState = "idle" | "encrypting" | "processing" | "decrypting" | "done" | "error";

export default function App() {
  const [state, setState] = useState<AppState>("idle");
  const [result, setResult] = useState<ProcessingOutput | null>(null);
  const [response, setResponse] = useState<ProcessResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState("");
  const [dashboardRefresh, setDashboardRefresh] = useState(0);
  const kmsKeyId = import.meta.env.VITE_MEDSEAL_KMS_KEY_ID || "alias/medseal-master";

  const handleFileSubmit = async (file: File) => {
    try {
      setError(null);
      setResult(null);
      setResponse(null);

      const content = await file.arrayBuffer();

      setState("encrypting");
      setStatusMessage("Encrypting data locally with AES-256-GCM...");
      const encrypted = await encryptFile(
        content,
        kmsKeyId
      );

      setState("processing");
      setStatusMessage("Processing inside Nitro Enclave (attestation → decrypt → NLP → re-encrypt)...");
      const processResponse = await submitForProcessing(encrypted);
      setResponse(processResponse);

      if (processResponse.status !== "COMPLETED") {
        throw new Error("Processing failed in enclave");
      }

      setState("decrypting");
      setStatusMessage("Decrypting results locally...");
      const decrypted = await decryptResult(
        processResponse.encryptedResultB64,
        processResponse.encryptedDataKeyB64,
        processResponse.ivB64,
        processResponse.authTagB64,
        kmsKeyId,
        processResponse.encryptionContext || encrypted.encryptionContext
      );

      const output: ProcessingOutput = JSON.parse(decrypted);
      setResult(output);
      setState("done");
      setStatusMessage("");
      setDashboardRefresh((value) => value + 1);

    } catch (err) {
      setState("error");
      setError(err instanceof Error ? err.message : "Unknown error");
      setStatusMessage("");
    }
  };

  return (
    <div style={{ maxWidth: 960, margin: "0 auto", padding: "2rem 1.5rem" }}>
      <header style={{ marginBottom: "2rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
          <Shield size={28} />
          <h1 style={{ fontSize: 24, fontWeight: 600, margin: 0 }}>MedSeal</h1>
        </div>
        <p style={{ color: "#666", margin: 0, fontSize: 14 }}>
          Confidential medical data processing powered by AWS Nitro Enclaves
        </p>
      </header>

      <OperationsDashboard refreshKey={dashboardRefresh} />

      {state !== "idle" && state !== "done" && state !== "error" && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 12,
            padding: "12px 16px",
            background: "#f0f7ff",
            borderRadius: 8,
            marginBottom: 16,
            fontSize: 14,
          }}
        >
          {state === "encrypting" && <Lock size={16} color="#2563eb" />}
          {state === "processing" && <Activity size={16} color="#2563eb" />}
          {state === "decrypting" && <FileCheck size={16} color="#2563eb" />}
          <span>{statusMessage}</span>
        </div>
      )}

      {error && (
        <div
          style={{
            padding: "12px 16px",
            background: "#fef2f2",
            color: "#991b1b",
            borderRadius: 8,
            marginBottom: 16,
            fontSize: 14,
          }}
        >
          Error: {error}
        </div>
      )}

      {(state === "idle" || state === "error") && (
        <UploadForm onSubmit={handleFileSubmit} />
      )}

      {result && response && (
        <>
          <TrustChainViewer
            attestationHash={response.attestationHash}
            processingTimeMs={response.processingTimeMs}
            jobId={response.jobId}
          />
          <ResultViewer result={result} />

          <button
            onClick={() => {
              setState("idle");
              setResult(null);
              setResponse(null);
            }}
            style={{
              marginTop: 16,
              padding: "10px 20px",
              background: "#f5f5f5",
              border: "1px solid #ddd",
              borderRadius: 6,
              cursor: "pointer",
              fontSize: 14,
            }}
          >
            Process another record
          </button>
        </>
      )}
    </div>
  );
}
