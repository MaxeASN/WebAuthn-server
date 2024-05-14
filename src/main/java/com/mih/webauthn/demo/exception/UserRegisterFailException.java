package com.mih.webauthn.demo.exception;

public class UserRegisterFailException extends RuntimeException {
    public UserRegisterFailException(String message) {
        super(message);
    }
}
