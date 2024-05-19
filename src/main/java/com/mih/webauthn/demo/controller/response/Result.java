package com.mih.webauthn.demo.controller.response;

import com.mih.webauthn.demo.constant.ResultCode;

public class Result<T> {
    private long code;
    private String msg;
    private T data;

    protected Result() {
    }

    protected Result(long code, String message, T data) {
        this.code = code;
        this.msg = message;
        this.data = data;
    }

    public static <T> Result<T> success() {
        return new Result<T>(ResultCode.SUCCESS, "", null);
    }

    /**
     * 成功返回结果
     *
     * @param data 获取的数据
     */
    public static <T> Result<T> success(T data) {
        return new Result<T>(ResultCode.SUCCESS, "", data);
    }

    /**
     * 成功返回结果
     *
     * @param data 获取的数据
     * @param  message 提示信息
     */
    public static <T> Result<T> success(T data, String message) {
        return new Result<T>(ResultCode.SUCCESS, message, data);
    }

    public static <T> Result<T> halfSuccess(String message) {
        return new Result<T>(ResultCode.HALF_SUCCESS, message, null);
    }

    /**
     * 失败返回结果
     * @param errorMsg 错误信息
     */
    public static <T> Result<T> failed(String errorMsg) {
        return new Result<T>(ResultCode.FAILED, errorMsg, null);
    }

    /**
     * 失败返回结果
     * @param errorCode 错误码
     * @param errorMsg 错误信息
     */
    public static <T> Result<T> failed(int errorCode,String errorMsg) {
        return new Result<T>(errorCode, errorMsg, null);
    }

    public static <T> Result<T> unAuthorization() {
        return new Result<T>(400, "用户尚未登录", null);
    }

    public long getCode() {
        return code;
    }

    public void setCode(long code) {
        this.code = code;
    }

    public String getMessage() {
        return msg;
    }

    public void setMessage(String message) {
        this.msg = message;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }
}
