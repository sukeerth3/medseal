import { useState, useRef } from "react";
import { Upload, FileText } from "lucide-react";

interface Props {
  onSubmit: (file: File) => void;
}

export function UploadForm({ onSubmit }: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile) setFile(droppedFile);
  };

  return (
    <div>
      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        style={{
          border: `2px dashed ${dragOver ? "#2563eb" : "#d1d5db"}`,
          borderRadius: 12,
          padding: "3rem 2rem",
          textAlign: "center",
          cursor: "pointer",
          background: dragOver ? "#f0f7ff" : "#fafafa",
          transition: "all 0.2s",
        }}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".txt,.pdf,.doc,.docx"
          onChange={(e) => e.target.files?.[0] && setFile(e.target.files[0])}
          style={{ display: "none" }}
        />

        {file ? (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
            <FileText size={20} />
            <span style={{ fontSize: 14 }}>{file.name} ({(file.size / 1024).toFixed(1)} KB)</span>
          </div>
        ) : (
          <>
            <Upload size={32} color="#9ca3af" />
            <p style={{ margin: "12px 0 4px", fontSize: 14, color: "#666" }}>
              Drop a medical record file here, or click to browse
            </p>
            <p style={{ margin: 0, fontSize: 12, color: "#999" }}>
              .txt files up to 5 MB
            </p>
          </>
        )}
      </div>

      {file && (
        <button
          onClick={() => onSubmit(file)}
          style={{
            marginTop: 16,
            width: "100%",
            padding: "12px 0",
            background: "#2563eb",
            color: "white",
            border: "none",
            borderRadius: 8,
            fontSize: 14,
            fontWeight: 500,
            cursor: "pointer",
          }}
        >
          Encrypt & Process Securely
        </button>
      )}
    </div>
  );
}
