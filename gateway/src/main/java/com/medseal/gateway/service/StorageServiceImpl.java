package com.medseal.gateway.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.ServerSideEncryption;

/**
 * S3-backed encrypted result storage.
 * <p>
 * Stores encrypted results with SSE-KMS (server-side encryption
 * using KMS). This is defense-in-depth: the results are already
 * envelope-encrypted by the enclave, and S3 adds another layer.
 */
@Service
public class StorageServiceImpl implements StorageService {

    private static final Logger log = LoggerFactory.getLogger(StorageServiceImpl.class);

    private final S3Client s3;
    private final String bucketName;
    private final String kmsKeyId;

    public StorageServiceImpl(
            S3Client s3,
            @Value("${medseal.s3.bucket-name:medseal-results}") String bucketName,
            @Value("${medseal.s3.kms-key-id:alias/medseal-master}") String kmsKeyId) {
        this.s3 = s3;
        this.bucketName = bucketName;
        this.kmsKeyId = kmsKeyId;
    }

    @Override
    public String store(String jobId, byte[] encryptedResult) {
        String key = "results/" + jobId + "/result.enc";

        s3.putObject(
                PutObjectRequest.builder()
                        .bucket(bucketName)
                        .key(key)
                        .serverSideEncryption(ServerSideEncryption.AWS_KMS)
                        .ssekmsKeyId(kmsKeyId)
                        .build(),
                RequestBody.fromBytes(encryptedResult)
        );

        log.info("Stored encrypted result for job {} ({} bytes)", jobId, encryptedResult.length);
        return key;
    }

    @Override
    public byte[] retrieve(String jobId) {
        String key = "results/" + jobId + "/result.enc";

        byte[] data = s3.getObjectAsBytes(
                GetObjectRequest.builder()
                        .bucket(bucketName)
                        .key(key)
                        .build()
        ).asByteArray();

        log.info("Retrieved encrypted result for job {} ({} bytes)", jobId, data.length);
        return data;
    }
}
