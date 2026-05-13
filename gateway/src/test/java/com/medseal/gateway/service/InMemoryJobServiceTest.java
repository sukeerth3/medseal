package com.medseal.gateway.service;

import com.medseal.gateway.model.JobStatus;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class InMemoryJobServiceTest {

    @Test
    void listsRecentJobsForOwnerOnly() {
        InMemoryJobService service = new InMemoryJobService();

        JobStatus ownerJob = service.createJob("doctor-a");
        JobStatus otherJob = service.createJob("doctor-b");

        service.updateJob(ownerJob.completed("attestation", 123));
        service.updateJob(otherJob.failed("boom"));

        List<JobStatus> jobs = service.listRecentJobs("doctor-a", 20);

        assertEquals(1, jobs.size());
        assertEquals(ownerJob.jobId(), jobs.get(0).jobId());
        assertEquals(JobStatus.Status.COMPLETED.name(), jobs.get(0).status());
    }

    @Test
    void clampsListLimit() {
        InMemoryJobService service = new InMemoryJobService();

        service.createJob("doctor-a");
        service.createJob("doctor-a");

        List<JobStatus> jobs = service.listRecentJobs("doctor-a", 1);

        assertEquals(1, jobs.size());
    }
}
