package com.mih.webauthn.demo.controller.response;

import com.mih.webauthn.demo.constant.ResultCode;

public class CommonResult<T> {
    private long code;
    private String message;
    private T data;

    protected CommonResult() {
    }

    protected CommonResult(long code, String message, T data) {
        this.code = code;
        this.message = message;
        this.data = data;
    }

    public static <T> CommonResult<T> success() {
        return new CommonResult<T>(ResultCode.SUCCESS, "", null);
    }

    /**
     * 成功返回结果
     *
     * @param data 获取的数据
     */
    public static <T> CommonResult<T> success(T data) {
        return new CommonResult<T>(ResultCode.SUCCESS, "", data);
    }

    /**
     * 成功返回结果
     *
     * @param data 获取的数据
     * @param  message 提示信息
     */
    public static <T> CommonResult<T> success(T data, String message) {
        return new CommonResult<T>(ResultCode.SUCCESS, message, data);
    }

    public static <T> CommonResult<T> halfSuccess(String message) {
        return new CommonResult<T>(ResultCode.HALF_SUCCESS, message, null);
    }

    /**
     * 失败返回结果
     * @param errorMsg 错误信息
     */
    public static <T> CommonResult<T> failed(String errorMsg) {
        return new CommonResult<T>(ResultCode.FAILED, errorMsg, null);
    }

    /**
     * 失败返回结果
     * @param errorCode 错误码
     * @param errorMsg 错误信息
     */
    public static <T> CommonResult<T> failed(int errorCode,String errorMsg) {
        return new CommonResult<T>(errorCode, errorMsg, null);
    }

    public static <T> CommonResult<T> unAuthorization() {
        return new CommonResult<T>(400, "用户尚未登录", null);
    }

    public long getCode() {
        return code;
    }

    public void setCode(long code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }
}
