package com.dorodong.auth_service.exception.aes;

import com.dorodong.auth_service.exception.ErrorCode;

public class InvalidCiphertextException extends CryptoOperationException {
    public static final int STATUS_CODE = ErrorCode.CRYPTO_INVALID.getStatus();

    public InvalidCiphertextException(String m) {
        super("Invalid ciphertext: " + m);
    }

    public InvalidCiphertextException(String m, Throwable c) {
        super("Invalid ciphertext: " + m, c);
    }
}
