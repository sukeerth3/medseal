package com.medseal.gateway.exception;

public class EnclaveException extends RuntimeException {
    public EnclaveException(String message, Throwable cause) {
        super(message, cause);
    }
}
