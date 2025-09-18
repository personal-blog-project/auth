package com.dorodong.auth_service.exception;

public enum ErrorCode {
    CRYPTO_CONFIG("CRYPTO_CONFIG", 500),
    CRYPTO_INVALID("CRYPTO_INVALID", 400);

    private final String code;
    private final int status;

    ErrorCode(String code, int status) {
        this.code = code;
        this.status = status;
    }

    public String getCode() {
        return code;
    }

    public int getStatus() {
        return status;
    }
}
