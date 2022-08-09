package com.example.sociallogin.constants;

import java.util.Optional;
import java.util.function.Predicate;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    // ok case
    OK(200, ErrorCategory.NORMAL, "Ok"),

    // 4xx error case
    BAD_REQUEST(400, ErrorCategory.CLIENT_SIDE, "Bad request"),
    VALIDATION_ERROR(400, ErrorCategory.CLIENT_SIDE, "Validation error"),
    NOT_FOUND(400, ErrorCategory.CLIENT_SIDE, "Requested resource is not found"),
    TOKEN_INVALID(400, ErrorCategory.CLIENT_SIDE, "Invalid token"),
    DUPLICATED_USER(400, ErrorCategory.CLIENT_SIDE, "Duplicated user"),
    DUPLICATED_FREDIT_USER(400, ErrorCategory.CLIENT_SIDE, "Duplicated fredit user"),
    NOT_MINE(400, ErrorCategory.CLIENT_SIDE, "Not my resource"),
    BLOCK_USER(400, ErrorCategory.CLIENT_SIDE, "Block user"),
    ACCESS_DENIED(400, ErrorCategory.CLIENT_SIDE, "Access denied"),

    // 5xx error case
    INTERNAL_ERROR(500, ErrorCategory.SERVER_SIDE, "Internal error"),
    DATA_ACCESS_ERROR(500, ErrorCategory.SERVER_SIDE, "Data access error"),
    DB_DATA_NOT_FOUND(500, ErrorCategory.CLIENT_SIDE, "Data is not found");

    private final Integer code; // error code
    private final ErrorCategory errorCategory; // error category
    private final String message; // error message

    public String getMessage(Throwable ex) {
        return this.getMessage(ex.getMessage());
    }

    public String getMessage(String message) {
        return Optional.ofNullable(message)
                .filter(Predicate.not(String::isBlank))
                .orElse(this.getMessage());
    }

    // client side error?
    public boolean isClientSideError() {
        return this.getErrorCategory() == ErrorCategory.CLIENT_SIDE;
    }

    // server side error?
    public boolean isServerSideError() {
        return this.getErrorCategory() == ErrorCategory.SERVER_SIDE;
    }

    @Override
    public String toString() {
        return String.format("%s (%d)", this.name(), this.getCode());
    }

    // error category enum
    public enum ErrorCategory {
        NORMAL, CLIENT_SIDE, SERVER_SIDE
    }
}
