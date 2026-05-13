package com.medseal.gateway.exception;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import static org.assertj.core.api.Assertions.assertThat;

class GlobalExceptionHandlerTest {

    @Test
    void noResourceFoundReturnsNotFoundInsteadOfInternalServerError() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();

        var response = handler.handleNoResourceFound(
                new NoResourceFoundException(HttpMethod.POST, "api/v1/datakey"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(response.getBody()).containsEntry("error", "Not found");
    }
}
