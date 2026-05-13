export interface EncryptedPayload {
  ciphertextB64: string;
  encryptedDataKeyB64: string;
  ivB64: string;
  authTagB64: string;
  kmsKeyId: string;
  jobId: string;
  principal: string;
  encryptionContext: EncryptionContext;
}

export type EncryptionContext = {
  jobId: string;
  principal: string;
};

export interface ProcessResponse {
  jobId: string;
  status: "COMPLETED" | "FAILED";
  encryptedResultB64: string;
  encryptedDataKeyB64: string;
  ivB64: string;
  authTagB64: string;
  attestationHash: string;
  processingTimeMs: number;
  encryptionContext?: EncryptionContext;
}

export interface JobStatus {
  jobId: string;
  status: "SUBMITTED" | "PROCESSING" | "COMPLETED" | "FAILED";
  createdAt: string;
  updatedAt: string;
  attestationHash?: string;
  processingTimeMs?: number;
  errorMessage?: string;
  ownerPrincipal?: string;
}

export interface DeidentificationResult {
  deidentified_text: string;
  entities_found: PhiEntity[];
  entity_count: number;
  confidence_score: number;
}

export interface PhiEntity {
  type: string;
  start: number;
  end: number;
  original_length: number;
  replacement: string;
  confidence: number;
  source: string;
}

export interface ClassificationResult {
  icd_codes: IcdCode[];
  risk_score: number;
  risk_factors: string[];
}

export interface IcdCode {
  code: string;
  description: string;
  confidence: number;
  matched_terms: string[];
}

export interface ProcessingOutput {
  job_id: string;
  deidentification: DeidentificationResult;
  classification: ClassificationResult;
  processed_at: string;
}

export interface HealthStatus {
  status: "UP" | "DOWN";
  gateway: "UP" | "DOWN";
  enclave: "UP" | "DOWN";
  nsm: "UP" | "DOWN";
  kms: "UP" | "DOWN";
  spacy: "UP" | "DOWN";
}
