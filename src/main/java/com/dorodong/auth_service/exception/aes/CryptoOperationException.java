package com.dorodong.auth_service.exception.aes;

public class CryptoOperationException extends RuntimeException {
    public CryptoOperationException(String m) {
        super(m);
    }

    public CryptoOperationException(String m, Throwable c) {
        super(m, c);
    }
}
