package com.medseal.gateway.service;

/** Storage contract for encrypted processing results. */
public interface StorageService {

    /** Store encrypted result bytes. Returns the storage key. */
    String store(String jobId, byte[] encryptedResult);

    /** Retrieve encrypted result bytes by job ID. */
    byte[] retrieve(String jobId);
}
