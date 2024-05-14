package com.mih.webauthn.demo.utils;

import org.springframework.util.Base64Utils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES加密工具类
 *
 * @author ACGkaka
 * @since 2021-06-18 19:11:03
 */
public class AESUtils {
    /**
     * 编码
     */
    private static final String ENCODING = "UTF-8";
    /**
     * 算法定义
     */
    private static final String AES_ALGORITHM = "AES";
    /**
     * 指定填充方式
     */
    private static final String CIPHER_PADDING = "AES/ECB/PKCS5Padding";

    private static final String AES_PRIVATE_KET = "oemY5YEKnA35KEwT";

    /**
     * AES加密
     * @param content 待加密内容
     * @param aesKey  密码
     * @return
     */
    public static String encrypt(String content, String aesKey){
        //判断秘钥是否为16位
        try {
            //对密码进行编码
            byte[] bytes = aesKey.getBytes(ENCODING);
            //设置加密算法，生成秘钥
            SecretKeySpec skeySpec = new SecretKeySpec(bytes, AES_ALGORITHM);
            // "算法/模式/补码方式"
            Cipher cipher = Cipher.getInstance(CIPHER_PADDING);
            //选择加密
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            //根据待加密内容生成字节数组
            byte[] encrypted = cipher.doFinal(content.getBytes(ENCODING));
            //返回base64字符串
            return Base64Utils.encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String encrypt(String content){
        return encrypt(content, AES_PRIVATE_KET);
    }

    /**
     * 解密
     *
     * @param content 待解密内容
     * @param aesKey  密码
     * @return
     */
    public static String decrypt(String content, String aesKey){
        try {
            //对密码进行编码
            byte[] bytes = aesKey.getBytes(ENCODING);
            //设置解密算法，生成秘钥
            SecretKeySpec skeySpec = new SecretKeySpec(bytes, AES_ALGORITHM);
            // "算法/模式/补码方式"
            Cipher cipher = Cipher.getInstance(CIPHER_PADDING);
            //选择解密
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);

            //先进行Base64解码
            byte[] decodeBase64 = Base64Utils.decodeFromString(content);

            //根据待解密内容进行解密
            byte[] decrypted = cipher.doFinal(decodeBase64);
            //将字节数组转成字符串
            return new String(decrypted, ENCODING);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String decrypt(String content){
        return decrypt(content, AES_PRIVATE_KET);
    }

}