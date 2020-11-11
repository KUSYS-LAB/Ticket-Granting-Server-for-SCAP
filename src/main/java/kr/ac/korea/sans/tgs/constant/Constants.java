package kr.ac.korea.sans.tgs.constant;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class Constants {
    public static String TYPE_PKI;

    @Value("${publickey.type}")
    public void setTypePki(String type) {TYPE_PKI = type;}
}
