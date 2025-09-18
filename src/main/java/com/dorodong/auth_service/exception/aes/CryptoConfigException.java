package com.dorodong.auth_service.exception.aes;

import com.dorodong.auth_service.exception.ErrorCode;

public class CryptoConfigException extends CryptoOperationException {
    public static final int STATUS_CODE = ErrorCode.CRYPTO_CONFIG.getStatus();

    public CryptoConfigException(String m) {
        super("Crypto config error: " + m);
    }

    public CryptoConfigException(String m, Throwable c) {
        super("Crypto config error: " + m, c);
    }
}
