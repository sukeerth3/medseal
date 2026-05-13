package com.medseal.gateway.model.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = ProcessRequestValidator.class)
public @interface ValidProcessRequest {

    String message() default "Invalid process request";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
