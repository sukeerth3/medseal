package com.medseal.gateway.service;

import com.medseal.gateway.model.JobStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Dev/demo job tracking fallback used when DynamoDB is unavailable.
 */
@Service
@ConditionalOnProperty(prefix = "medseal.dynamodb", name = "in-memory", havingValue = "true")
public class InMemoryJobService implements JobService {

    private static final Logger log = LoggerFactory.getLogger(InMemoryJobService.class);

    private final Map<String, JobStatus> jobs = new ConcurrentHashMap<>();

    @Override
    public JobStatus createJob(String jobId, String ownerPrincipal) {
        JobStatus job = JobStatus.submitted(jobId, ownerPrincipal);
        JobStatus existing = jobs.putIfAbsent(jobId, job);
        if (existing != null) {
            throw new IllegalStateException("Job already exists: " + jobId);
        }
        log.warn("Created in-memory demo job {}; job status will not survive gateway restart", jobId);
        return job;
    }

    @Override
    public Optional<JobStatus> getJob(String jobId) {
        return Optional.ofNullable(jobs.get(jobId));
    }

    @Override
    public void updateJob(JobStatus jobStatus) {
        jobs.put(jobStatus.jobId(), jobStatus);
        log.info("Updated in-memory demo job {} -> {}", jobStatus.jobId(), jobStatus.status());
    }

    @Override
    public List<JobStatus> listRecentJobs(String ownerPrincipal, int limit) {
        return jobs.values().stream()
                .filter(job -> ownerPrincipal == null || ownerPrincipal.equals(job.ownerPrincipal()))
                .sorted(Comparator.comparing(JobStatus::updatedAt).reversed())
                .limit(Math.max(1, Math.min(limit, 50)))
                .toList();
    }
}
