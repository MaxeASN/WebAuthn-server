package com.mih.webauthn.demo.utils;

import com.mih.webauthn.demo.constant.ERC20Const;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Arrays;

import static com.mih.webauthn.demo.constant.BlockchainConst.GOERLI_ID;

public class CommonUtils {
    public static String toStackTrace(Exception e)

    {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        try {
            e.printStackTrace(pw);
            return sw.toString();
        } catch(Exception e1) {
            return "";
        }
    }

    public static String chainId2name(String chainId){
        if(chainId.equals(GOERLI_ID + "")){
            return "goerli";
        }
        return chainId;
    }

    public static String coinId2Name(Integer coinId) {
        if(coinId.equals(ERC20Const.COIN_MAIN)){
            return "ETH";
        }
        return "undefine";
    }

    public static boolean isFaceData(String faceData) {
        return Arrays.stream(faceData.split(",")).allMatch((String floatStr) -> {
            try{
                Float.parseFloat(floatStr);
            }catch (Exception e){
                return false;
            }
            return true;
        });
    }
}
