package com.medseal.gateway.service;

import com.medseal.gateway.model.JobStatus;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;

import java.time.Instant;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * DynamoDB-backed job tracking.
 * <p>
 * Stores job metadata (status, timestamps, attestation hash).
 * Never stores payload data, only metadata.
 */
@Service
@ConditionalOnProperty(prefix = "medseal.dynamodb", name = "in-memory", havingValue = "false", matchIfMissing = true)
public class JobServiceImpl implements JobService {

    private static final Logger log = LoggerFactory.getLogger(JobServiceImpl.class);
    private static final String OWNER_UPDATED_AT_INDEX = "ownerPrincipal-updatedAt-index";

    private final DynamoDbClient dynamoDb;
    private final String tableName;

    public JobServiceImpl(
            DynamoDbClient dynamoDb,
            @Value("${medseal.dynamodb.table-name:medseal-jobs}") String tableName) {
        this.dynamoDb = dynamoDb;
        this.tableName = tableName;
    }

    @Override
    public JobStatus createJob(String jobId, String ownerPrincipal) {
        JobStatus job = JobStatus.submitted(jobId, ownerPrincipal);

        Map<String, AttributeValue> item = new HashMap<>();
        item.put("jobId", AttributeValue.fromS(job.jobId()));
        item.put("status", AttributeValue.fromS(job.status()));
        item.put("createdAt", AttributeValue.fromS(job.createdAt().toString()));
        item.put("updatedAt", AttributeValue.fromS(job.updatedAt().toString()));
        if (job.ownerPrincipal() != null) {
            item.put("ownerPrincipal", AttributeValue.fromS(job.ownerPrincipal()));
        }

        dynamoDb.putItem(PutItemRequest.builder()
                .tableName(tableName)
                .item(item)
                .conditionExpression("attribute_not_exists(jobId)")
                .build());

        log.info("Created job {}", jobId);
        return job;
    }

    @Override
    public Optional<JobStatus> getJob(String jobId) {
        GetItemResponse response = dynamoDb.getItem(GetItemRequest.builder()
                .tableName(tableName)
                .key(Map.of("jobId", AttributeValue.fromS(jobId)))
                .build());

        if (!response.hasItem() || response.item().isEmpty()) {
            return Optional.empty();
        }

        return Optional.of(fromItem(response.item()));
    }

    @Override
    public void updateJob(JobStatus jobStatus) {
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("jobId", AttributeValue.fromS(jobStatus.jobId()));
        item.put("status", AttributeValue.fromS(jobStatus.status()));
        item.put("createdAt", AttributeValue.fromS(jobStatus.createdAt().toString()));
        item.put("updatedAt", AttributeValue.fromS(jobStatus.updatedAt().toString()));

        if (jobStatus.attestationHash() != null) {
            item.put("attestationHash", AttributeValue.fromS(jobStatus.attestationHash()));
        }
        if (jobStatus.processingTimeMs() != null) {
            item.put("processingTimeMs", AttributeValue.fromN(jobStatus.processingTimeMs().toString()));
        }
        if (jobStatus.errorMessage() != null) {
            item.put("errorMessage", AttributeValue.fromS(jobStatus.errorMessage()));
        }
        if (jobStatus.ownerPrincipal() != null) {
            item.put("ownerPrincipal", AttributeValue.fromS(jobStatus.ownerPrincipal()));
        }

        dynamoDb.putItem(PutItemRequest.builder()
                .tableName(tableName)
                .item(item)
                .build());

        log.info("Updated job {} -> {}", jobStatus.jobId(), jobStatus.status());
    }

    @Override
    public List<JobStatus> listRecentJobs(String ownerPrincipal, int limit) {
        if (ownerPrincipal == null || ownerPrincipal.isBlank()) {
            return List.of();
        }

        QueryResponse response = dynamoDb.query(QueryRequest.builder()
                .tableName(tableName)
                .indexName(OWNER_UPDATED_AT_INDEX)
                .keyConditionExpression("ownerPrincipal = :owner")
                .expressionAttributeValues(Map.of(":owner", AttributeValue.fromS(ownerPrincipal)))
                .scanIndexForward(false)
                .limit(Math.max(1, Math.min(limit, 50)))
                .build());

        return response.items().stream()
                .map(this::fromItem)
                .toList();
    }

    private JobStatus fromItem(Map<String, AttributeValue> item) {
        return new JobStatus(
                item.get("jobId").s(),
                item.get("status").s(),
                Instant.parse(item.get("createdAt").s()),
                Instant.parse(item.get("updatedAt").s()),
                item.containsKey("attestationHash") ? item.get("attestationHash").s() : null,
                item.containsKey("processingTimeMs") ? Integer.parseInt(item.get("processingTimeMs").n()) : null,
                item.containsKey("errorMessage") ? item.get("errorMessage").s() : null,
                item.containsKey("ownerPrincipal") ? item.get("ownerPrincipal").s() : null
        );
    }
}
