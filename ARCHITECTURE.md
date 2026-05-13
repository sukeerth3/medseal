# MedSeal Architecture

## Design Principles

MedSeal keeps the trust boundary narrow. The gateway handles authentication,
request validation, job metadata, audit logs, and encrypted result storage. The
enclave handles attestation, key release, plaintext processing, and
re-encryption.

The main extension points are explicit:

- PHI detection can be extended through additional `PhiDetector`
  implementations.
- ICD-10 classification can be replaced with a maintained coding source or a
  clinical NLP model behind the same pipeline contract.
- KMS and attestation providers have mock implementations for local tests, while
  production startup rejects those mocks.
- Gateway dependencies are separated by role: enclave communication, job state,
  encrypted storage, and audit logging.

## Trust Boundary

The most important architectural decision is the trust boundary. Everything outside the Nitro Enclave is untrusted:

```
UNTRUSTED                          TRUSTED
---------------------------------  -------------------
Client browser/CLI                 Nitro Enclave
Internet/network                     - Attestation
EC2 host OS                          - Decryption
Spring Boot gateway                  - NLP processing
S3 / DynamoDB                        - Re-encryption
CloudWatch logs
```

The gateway is intentionally outside the trusted computing base. It can route
requests, validate envelope shape, record job metadata, and store encrypted
results, but it must not hold plaintext PHI or plaintext data keys.

## Envelope Encryption Flow

```
Client:
  plaintext_data_key <- KMS.GenerateDataKey()
  encrypted_data_key <- returned alongside
  ciphertext <- AES-256-GCM(plaintext, plaintext_data_key)
  DELETE plaintext_data_key
  SEND { ciphertext, encrypted_data_key, iv, auth_tag }

Enclave:
  attestation_doc <- NSM.GetAttestationDocument()
  plaintext_data_key <- KMS.Decrypt(encrypted_data_key, attestation=attestation_doc)
  plaintext <- AES-256-GCM.Decrypt(ciphertext, plaintext_data_key)
  result <- Pipeline.Process(plaintext)
  DELETE plaintext, plaintext_data_key
  new_data_key <- KMS.GenerateDataKey()
  encrypted_result <- AES-256-GCM(result, new_data_key)
  RETURN { encrypted_result, encrypted_new_data_key, iv, auth_tag }
```

## Why Python for the Enclave

1. **Nitro NSM**: a small ctypes binding over `/dev/nsm` (`enclave/src/attestation/nsm_binding.py`) handles attestation; CBOR/COSE parsing is pure Python.
2. **spaCy**: Medical NER runs natively in Python and fits inside the 4 GB enclave memory budget.
3. **kmstool-enclave-cli**: KMS calls from inside the enclave are not made by `boto3`. The enclave has no NIC, so plain `boto3` cannot complete a TLS handshake to KMS even with `vsock-proxy` running on the host. Instead, the enclave shells out to AWS's `kmstool-enclave-cli` (from `aws-nitro-enclaves-sdk-c`), which uses `libnsm` plus a vsock-aware C SDK and returns plaintext key material directly to the enclave process. See `scripts/build-kmstool.sh` and `enclave/Dockerfile`.
4. **Memory**: Python has a smaller startup footprint than the JVM, which matters in a constrained 4 GB enclave.

## Why Java for the Gateway

1. **Spring Boot**: REST framework with validation, exception handling, and dependency injection.
2. **Type safety**: Java records keep the API contract explicit.
3. **Operational fit**: The gateway integrates cleanly with AWS SDK clients, structured logging, and systemd deployment.
