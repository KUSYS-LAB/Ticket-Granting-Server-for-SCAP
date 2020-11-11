package kr.ac.korea.sans.tgs.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import kr.ac.korea.sans.tgs.response.TgsAppResponse;
import kr.ac.korea.sans.tgs.response.TgsErrorResponse;
import kr.ac.korea.sans.tgs.response.TgsSecretDto;
import kr.ac.korea.sans.tgs.util.CryptoHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.util.Base64Utils;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

@Service
public class TgsServiceImpl implements TgsService{

    private static final Logger logger = LoggerFactory.getLogger(TgsServiceImpl.class);

    @Override
    public TgsSecretDto decryptService(Map<String, Object> json) throws GeneralSecurityException, IOException, ParseException {
        Map<String, Object> body = (Map<String, Object>) json.get("body");
        String signature = (String) json.get("signature");

        CryptoHelper cryptoHelper = CryptoHelper.getInstance();
        ObjectMapper objectMapper = new ObjectMapper();

        //1. sigc 검증
        // 1-1) pk+c 획득
        String cpk = (String) body.get("cpk");
        PublicKey cpkPublicKey = cryptoHelper.restorePublicKeyFromPem(cpk);

        // 1-1) ECDSA 서명 검증
        byte[] decodedSignature = Base64.decode(signature);

        String bodyString = objectMapper.writeValueAsString(body);
        byte[] baBody = bodyString.getBytes("UTF-8");

        if (!cryptoHelper.verifySignature(cpkPublicKey, decodedSignature, baBody)) {
            throw new TgsErrorResponse("Signature Validation ERROR");
        }

        // 2. Ticket TGS 검증
        // 2-1) Epk+tgs (SK cs-tgs) 복호화하여 SK cs-tgs 획득.
        // 현재 base64 상태로 암호화하지 않아도 됨.

        // 2-2) SK cs-tgs 이용해 Ticket tgs 복호화해 id, hospital, time 획득
        // 현재 hospital 항목 없음, 검증시점의 시간이 time1 포함되어 있는지 확인
        byte[] ticketData2 = Base64Utils.decodeFromString((String) body.get("ticket"));
        PrivateKey privateKey = cryptoHelper.restorePrivateKeyFromPem(new FileReader("TGS-KeyPair/TGS-PrivateKey"));
        String esk = new String(cryptoHelper.decryptWithRsa(
                Base64Utils.decodeFromString((String) body.get("esk")), privateKey));
        Map<String, Object> eskMap = objectMapper.readValue(esk, Map.class);

        String skBase64 = (String) eskMap.get("sk");
        String ivBase64 = (String) eskMap.get("iv");
        SecretKeySpec sk = new SecretKeySpec(Base64Utils.decodeFromString(skBase64), "AES");
        IvParameterSpec iv = new IvParameterSpec(Base64Utils.decodeFromString(ivBase64));
        byte[] decryptedTicket = cryptoHelper.decryptWithAes(sk, iv, ticketData2);
        Map<String, Object> ticket = objectMapper.readValue(decryptedTicket, Map.class);

        Map<String, Object> timeData = (Map<String, Object>) body.get("time");

        if (!cryptoHelper.isTicketVal(ticket, timeData)){
            throw new TgsErrorResponse("Ticket Validation ERROR");
        }

        // 2-3) 사용자 인증
        // PK-tgs 이용해 Authc 복호화해 id, hospital, time 획득
        Map<String, Object> auth = objectMapper.readValue(
                new String(cryptoHelper.decryptWithRsa(
                        Base64Utils.decodeFromString((String) body.get("auth")),
                        privateKey)),
                Map.class);

        // need to fixed, check institute!
        if (!ticket.get("cname").equals(auth.get("cname"))   //|| !ticket.get("institute").equals(auth.get("institute"))
        ) {
            throw new TgsErrorResponse("Auth Validation ERROR");
        }

        return new TgsSecretDto(sk, iv, auth);
    }

    @Override
    public TgsAppResponse<Map<String, Object>> encryptService(Map<String, Object> body, TgsSecretDto tgsSecretDto) throws Exception {
        TgsAppResponse<Map<String, Object>> tgsAppResponse = new TgsAppResponse<>();
        ObjectMapper objectMapper = new ObjectMapper();
        CryptoHelper cryptoHelper = CryptoHelper.getInstance();

        // ts (Timestamp)
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String ts = formatter.format(Calendar.getInstance().getTime());

        // [1] ticket (for SS)
        String cname = tgsSecretDto.getAuth().get("cname").toString();

        Map<String, String> time = new HashMap<>();
        time.put("from", (String) ((Map<String, Object>) body.get("time")).get("from"));
        time.put("to", (String) ((Map<String, Object>) body.get("time")).get("to"));

        Map<String, Object> ticketMap = new HashMap<>();
        ticketMap.put("cname", cname);
        ticketMap.put("time", time);

        String ticketStr = objectMapper.writeValueAsString(ticketMap);

        // sk (Secret Key)
        SecretKeySpec sk = (SecretKeySpec) cryptoHelper.getSecretEncryptionKey();
        IvParameterSpec iv = cryptoHelper.getIvParameterSpec();

        Map<String, Object> eskMap = new HashMap<>();
        eskMap.put("sk", Base64Utils.encodeToString(sk.getEncoded()));
        eskMap.put("iv", Base64Utils.encodeToString(iv.getIV()));

        byte[] cipherText = cryptoHelper.encrypt(sk, iv, ticketStr);

        String ticket = Base64Utils.encodeToString(cipherText);

        // spk (TGS public key)
        String spk = Base64Utils.encodeToString(
                cryptoHelper.restorePublicKeyFromPem(
                        new FileReader("TGS-KeyPair/TGS-PublicKey")).getEncoded());

        Map<String, Object> responseBodyMap = new HashMap<>();
        responseBodyMap.put("ticket", ticket);
        responseBodyMap.put("esk", eskMap);
        responseBodyMap.put("ts", ts);
        responseBodyMap.put("spk", spk);

        // [2] Signature (body)
        String responseBodyStr = objectMapper.writeValueAsString(responseBodyMap);

        byte[] signature = cryptoHelper.getSignature(responseBodyStr);
        String postSig = Base64Utils.encodeToString(signature);

        // Response
        tgsAppResponse.setBody(responseBodyMap);
        tgsAppResponse.setSignature(postSig);

        return tgsAppResponse;
    }
}
