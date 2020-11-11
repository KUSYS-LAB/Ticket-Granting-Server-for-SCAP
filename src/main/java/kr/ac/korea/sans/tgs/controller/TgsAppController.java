package kr.ac.korea.sans.tgs.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import kr.ac.korea.sans.tgs.response.TgsAppResponse;
import kr.ac.korea.sans.tgs.response.TgsSecretDto;
import kr.ac.korea.sans.tgs.service.TgsServiceImpl;
import kr.ac.korea.sans.tgs.util.CryptoHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.Base64Utils;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.FileReader;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

@CrossOrigin("*")
@RestController
public class TgsAppController {

    @Autowired
    private TgsServiceImpl tgsService;

    @Autowired
    private CryptoHelper cryptoHelper;

    @RequestMapping(value="/hello", method = RequestMethod.GET)
    public String test (HttpServletRequest request) throws Exception {
        return "Hello!";
    }

    @RequestMapping(value="/get-ticket", method = RequestMethod.POST)
    public TgsAppResponse<Map<String, Object>> getTicket(@RequestBody Map<String, Object> json) throws Exception {
        Map<String, Object> body = (Map<String, Object>) json.get("body");

        TgsSecretDto tgsSecretDto = tgsService.decryptService(json);
        return tgsService.encryptService(body, tgsSecretDto);

    }

    @RequestMapping(value="/get-cert", method=RequestMethod.GET)
    public TgsAppResponse<Map<String, Object>> getCertificate() throws Exception {
//        PublicKey publicKey = this.cryptoHelper.getPublic("TGS-KeyPair/TGS-PublicKey", "EC");
        PublicKey publicKey = this.cryptoHelper.restorePublicKeyFromPem(new FileReader("TGS-KeyPair/TGS-PublicKey"));
        Map<String, Object> body = new HashMap<>();
        ObjectMapper objectMapper = new ObjectMapper();

        body.put("certificate", Base64Utils.encodeToString(publicKey.getEncoded()));
        String bodyStr = objectMapper.writeValueAsString(body);
        byte[] signature = this.cryptoHelper.getSignature(bodyStr);

        return new TgsAppResponse<>(body, Base64Utils.encodeToString(signature));
    }
}
