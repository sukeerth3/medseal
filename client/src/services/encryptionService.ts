/**
 * Client-side envelope encryption with Web Crypto and direct AWS KMS calls.
 */

import { DecryptCommand, GenerateDataKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import type { EncryptedPayload, EncryptionContext } from "../types";

const GCM_IV_SIZE = 12;
const GCM_TAG_SIZE_BITS = 128;

/**
 * Encrypt file contents and return the envelope fields expected by the gateway.
 */
export async function encryptFile(
  fileContent: ArrayBuffer,
  kmsKeyId: string
): Promise<EncryptedPayload> {
  const iv = crypto.getRandomValues(new Uint8Array(GCM_IV_SIZE));
  const encryptionContext = buildEncryptionContext();
  const aad = canonicalEncryptionContext(encryptionContext);
  const dataKeyResponse = await generateDataKey(kmsKeyId, encryptionContext);
  const encryptedDataKey = requireBytes(dataKeyResponse.CiphertextBlob, "KMS ciphertext blob");
  let dataKey: Uint8Array | null = requireBytes(dataKeyResponse.Plaintext, "KMS plaintext data key");

  if (dataKey.byteLength !== 32) {
    dataKey.fill(0);
    throw new Error("KMS returned an invalid AES-256 data key");
  }

  const rawKey = new ArrayBuffer(dataKey.byteLength);
  const rawKeyBytes = new Uint8Array(rawKey);
  rawKeyBytes.set(dataKey);

  try {
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );

    const ciphertextWithTag = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad, tagLength: GCM_TAG_SIZE_BITS },
      cryptoKey,
      fileContent
    );

    const fullCiphertext = new Uint8Array(ciphertextWithTag);
    const tagSizeBytes = GCM_TAG_SIZE_BITS / 8;
    const ciphertext = fullCiphertext.slice(0, fullCiphertext.length - tagSizeBytes);
    const authTag = fullCiphertext.slice(fullCiphertext.length - tagSizeBytes);

    return {
      ciphertextB64: arrayBufferToBase64(ciphertext),
      encryptedDataKeyB64: arrayBufferToBase64(encryptedDataKey),
      ivB64: arrayBufferToBase64(iv),
      authTagB64: arrayBufferToBase64(authTag),
      kmsKeyId,
      jobId: encryptionContext.jobId,
      principal: encryptionContext.principal,
      encryptionContext,
    };
  } finally {
    rawKeyBytes.fill(0);
    if (dataKey) {
      dataKey.fill(0);
      dataKey = null;
    }
  }
}

/**
 * Decrypt an encrypted result from the enclave using direct KMS.
 */
export async function decryptResult(
  encryptedResultB64: string,
  encryptedDataKeyB64: string,
  ivB64: string,
  authTagB64: string,
  kmsKeyId: string,
  encryptionContext: EncryptionContext
): Promise<string> {
  const ciphertext = base64ToBytes(encryptedResultB64);
  const iv = base64ToBytes(ivB64);
  const authTag = base64ToBytes(authTagB64);
  const encryptedDataKey = base64ToBytes(encryptedDataKeyB64);
  const aad = canonicalEncryptionContext(encryptionContext);
  let dataKey: Uint8Array | null = null;

  try {
    const response = await kmsClient().send(new DecryptCommand({
      CiphertextBlob: encryptedDataKey,
      KeyId: kmsKeyId,
      EncryptionContext: encryptionContext,
    }));
    dataKey = requireBytes(response.Plaintext, "KMS decrypted data key");
    if (dataKey.byteLength !== 32) {
      dataKey.fill(0);
      throw new Error("KMS returned an invalid AES-256 data key");
    }

    const rawKey = new ArrayBuffer(dataKey.byteLength);
    const rawKeyBytes = new Uint8Array(rawKey);
    rawKeyBytes.set(dataKey);
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    rawKeyBytes.fill(0);

    const combined = new Uint8Array(ciphertext.byteLength + authTag.byteLength);
    combined.set(ciphertext, 0);
    combined.set(authTag, ciphertext.byteLength);

    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: toArrayBuffer(iv), additionalData: aad, tagLength: GCM_TAG_SIZE_BITS },
      cryptoKey,
      toArrayBuffer(combined)
    );

    return new TextDecoder().decode(plaintext);
  } finally {
    if (dataKey) {
      dataKey.fill(0);
      dataKey = null;
    }
  }
}

function arrayBufferToBase64(buffer: Uint8Array | ArrayBuffer): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

async function generateDataKey(kmsKeyId: string, encryptionContext: EncryptionContext) {
  return kmsClient().send(new GenerateDataKeyCommand({
    KeyId: kmsKeyId,
    KeySpec: "AES_256",
    EncryptionContext: encryptionContext,
  }));
}

function requireBytes(value: Uint8Array | undefined, label: string): Uint8Array {
  if (!value) {
    throw new Error(`${label} was missing from the KMS response`);
  }
  return value;
}

function buildEncryptionContext(): EncryptionContext {
  return {
    jobId: crypto.randomUUID(),
    principal: clientPrincipal(),
  };
}

function canonicalEncryptionContext(context: EncryptionContext): ArrayBuffer {
  const sorted = Object.keys(context)
    .sort()
    .reduce<Record<string, string>>((acc, key) => {
      acc[key] = context[key as keyof EncryptionContext];
      return acc;
    }, {});
  return toArrayBuffer(new TextEncoder().encode(JSON.stringify(sorted)));
}

function clientPrincipal(): string {
  const configured = import.meta.env.VITE_MEDSEAL_PRINCIPAL;
  if (configured) {
    return configured;
  }

  const claimPrincipal = principalFromAuthToken();
  if (claimPrincipal) {
    return claimPrincipal;
  }

  // Browser direct-KMS cannot call STS without extra credentials wiring; deployments
  // should set VITE_MEDSEAL_PRINCIPAL to the auth identity or KMS session role.
  return "browser-direct-kms";
}

function principalFromAuthToken(): string | undefined {
  let token = import.meta.env.VITE_MEDSEAL_TOKEN;
  if (!token) {
    try {
      token = window.localStorage.getItem("medsealToken") || undefined;
    } catch {
      token = undefined;
    }
  }
  if (!token) {
    return undefined;
  }

  try {
    const payload = JSON.parse(atob(token.split(".")[1]));
    return payload.arn || payload.sub || payload.email;
  } catch {
    return undefined;
  }
}

function kmsClient(): KMSClient {
  const region = import.meta.env.VITE_AWS_REGION || "us-east-1";
  const accessKeyId = import.meta.env.VITE_AWS_ACCESS_KEY_ID;
  const secretAccessKey = import.meta.env.VITE_AWS_SECRET_ACCESS_KEY;
  const sessionToken = import.meta.env.VITE_AWS_SESSION_TOKEN;

  if (!accessKeyId || !secretAccessKey) {
    throw new Error(
      "Browser direct-KMS mode requires temporary AWS credentials in VITE_AWS_ACCESS_KEY_ID and VITE_AWS_SECRET_ACCESS_KEY"
    );
  }

  return new KMSClient({
    region,
    credentials: {
      accessKeyId,
      secretAccessKey,
      sessionToken: sessionToken || undefined,
    },
  });
}
