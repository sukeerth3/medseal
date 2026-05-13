package com.medseal.gateway.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.medseal.gateway.exception.EnclaveException;
import com.medseal.gateway.model.HealthResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * Production enclave communication via vsock.
 * <p>
 * Uses a vsock client to communicate with the Nitro Enclave.
 * Message framing: [4-byte big-endian length][JSON payload]
 * <p>
 * On non-Linux systems (development), falls back to a local
 * TCP socket for testing with a mock enclave server.
 */
@Service
public class EnclaveServiceImpl implements EnclaveService {

    private static final Logger log = LoggerFactory.getLogger(EnclaveServiceImpl.class);
    private static final int HEADER_SIZE = 4;
    private static final int MAX_MESSAGE_SIZE = 10 * 1024 * 1024; // 10 MB

    private final ObjectMapper objectMapper;

    @Value("${medseal.enclave.cid:16}")
    private int enclaveCid;

    @Value("${medseal.enclave.port:5000}")
    private int enclavePort;

    @Value("${medseal.enclave.timeout-seconds:60}")
    private int timeoutSeconds;

    @Value("${medseal.enclave.use-tcp-fallback:false}")
    private boolean useTcpFallback;

    @Value("${medseal.enclave.tcp-host:localhost}")
    private String tcpHost;

    @Value("${medseal.enclave.client-path:/opt/medseal/enclave}")
    private String enclaveClientPath;

    public EnclaveServiceImpl(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public String process(String jobId, String jsonPayload) {
        log.info("[{}] Sending payload to enclave ({} bytes)", jobId, jsonPayload.length());

        try {
            String response;
            if (useTcpFallback) {
                response = sendViaTcp(jsonPayload);
            } else {
                response = sendViaVsock(jsonPayload);
            }

            log.info("[{}] Received response from enclave ({} bytes)", jobId, response.length());
            return response;

        } catch (Exception e) {
            log.error("[{}] Enclave communication failed: {}", jobId, e.getMessage());
            throw new EnclaveException("Failed to communicate with enclave: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean isHealthy() {
        return health().isOk();
    }

    @Override
    public HealthResponse health() {
        try {
            String response = process("health-check", "{\"type\":\"health\"}");
            return objectMapper.readValue(response, HealthResponse.class);
        } catch (Exception e) {
            log.warn("Enclave health check failed: {}", e.getMessage());
            return HealthResponse.down();
        }
    }

    /** Send to the enclave through the Python AF_VSOCK client. */
    private String sendViaVsock(String payload) throws IOException, InterruptedException {
        // Keep AF_VSOCK handling in the Python client to avoid JNI glue here.
        ProcessBuilder pb = new ProcessBuilder(
                "python3", "-c",
                String.format(
                        "import os, sys; sys.path.insert(0, os.environ['MEDSEAL_ENCLAVE_CLIENT_PATH']); "
                                + "from src.transport.vsock import VsockClient; "
                                + "client = VsockClient(%d, %d); "
                                + "print(client.send(sys.stdin.read(), timeout=%d))",
                        enclaveCid, enclavePort, timeoutSeconds
                )
        );
        pb.environment().put("MEDSEAL_ENCLAVE_CLIENT_PATH", enclaveClientPath);
        pb.redirectErrorStream(false);
        Process process = pb.start();

        try (OutputStream os = process.getOutputStream()) {
            os.write(payload.getBytes(StandardCharsets.UTF_8));
            os.flush();
        }

        String response;
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            response = reader.lines().reduce("", (a, b) -> a + b);
        }

        String errors;
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
            errors = reader.lines().reduce("", (a, b) -> a + "\n" + b).trim();
        }

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new IOException("vsock client failed (exit " + exitCode + "): " + errors);
        }

        return response;
    }

    /**
     * Send via TCP (development fallback).
     * <p>
     * For local testing with a mock enclave running as a TCP server.
     */
    private String sendViaTcp(String payload) throws IOException {
        try (Socket socket = new Socket(tcpHost, enclavePort)) {
            socket.setSoTimeout(timeoutSeconds * 1000);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            byte[] data = payload.getBytes(StandardCharsets.UTF_8);
            ByteBuffer header = ByteBuffer.allocate(HEADER_SIZE).order(ByteOrder.BIG_ENDIAN);
            header.putInt(data.length);
            out.write(header.array());
            out.write(data);
            out.flush();

            byte[] respHeader = in.readNBytes(HEADER_SIZE);
            if (respHeader.length != HEADER_SIZE) {
                throw new IOException("Incomplete response header");
            }
            int respLen = ByteBuffer.wrap(respHeader).order(ByteOrder.BIG_ENDIAN).getInt();

            if (respLen < 0 || respLen > MAX_MESSAGE_SIZE) {
                throw new IOException("Response too large: " + respLen);
            }

            byte[] respBody = in.readNBytes(respLen);
            if (respBody.length != respLen) {
                throw new IOException("Incomplete response body");
            }
            return new String(respBody, StandardCharsets.UTF_8);
        }
    }
}
