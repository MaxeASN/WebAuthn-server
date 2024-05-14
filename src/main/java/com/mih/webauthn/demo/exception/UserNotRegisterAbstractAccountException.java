package com.mih.webauthn.demo.exception;

public class UserNotRegisterAbstractAccountException extends RuntimeException {
    public UserNotRegisterAbstractAccountException(){
        super("用户尚未注册抽象账户");
    }
}
