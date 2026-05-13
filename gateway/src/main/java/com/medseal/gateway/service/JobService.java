package com.medseal.gateway.service;

import com.medseal.gateway.model.JobStatus;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Job lifecycle storage contract. */
public interface JobService {

    /** Create a new job record. */
    default JobStatus createJob(String ownerPrincipal) {
        return createJob(UUID.randomUUID().toString(), ownerPrincipal);
    }

    /** Create a new job record with a caller-provided ID. */
    JobStatus createJob(String jobId, String ownerPrincipal);

    /** Create a new job record without an owner. */
    default JobStatus createJob() {
        return createJob(null);
    }

    /** Get job status by ID. */
    Optional<JobStatus> getJob(String jobId);

    /** Update job status. */
    void updateJob(JobStatus jobStatus);

    /** List recent jobs for the authenticated owner. */
    List<JobStatus> listRecentJobs(String ownerPrincipal, int limit);
}
