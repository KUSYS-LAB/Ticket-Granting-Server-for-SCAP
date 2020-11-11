package kr.ac.korea.sans.tgs.service;

import kr.ac.korea.sans.tgs.response.TgsAppResponse;
import kr.ac.korea.sans.tgs.response.TgsSecretDto;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.ParseException;
import java.util.Map;

public interface TgsService {
    TgsSecretDto decryptService(Map<String, Object> json) throws GeneralSecurityException, IOException, ParseException;
    TgsAppResponse<Map<String, Object>> encryptService(Map<String, Object> body, TgsSecretDto tgsSecretDto) throws Exception;
}
