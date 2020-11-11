package kr.ac.korea.sans.tgs;

import kr.ac.korea.sans.tgs.constant.Constants;
import kr.ac.korea.sans.tgs.util.CryptoHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.annotation.PostConstruct;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.util.TimeZone;

@SpringBootApplication
public class TgsApplication {
    private static final Logger logger = LoggerFactory.getLogger(TgsApplication.class);

    @Value("${publickey.type}")
    private String publicKeyType;

    public static void main(String[] args) {
        SpringApplication.run(TgsApplication.class, args);
    }

    @PostConstruct
    public void init() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException, IOException {
        TimeZone.setDefault(TimeZone.getTimeZone("Asia/Seoul"));
        Security.addProvider(new BouncyCastleProvider());

        CryptoHelper cryptoHelper = CryptoHelper.getInstance();
        if (!new File("TGS-KeyPair").exists()) new File("TGS-KeyPair").mkdir();
        if (!new File("TGS-KeyPair/TGS-PublicKey").exists() || !new File("TGS-KeyPair/TGS-PrivateKey").exists()) {
            KeyPair keyPair = null;
            if (publicKeyType.toLowerCase().trim().equals("ec")) keyPair = cryptoHelper.generateEcKeyPair();
            else if (publicKeyType.toLowerCase().trim().equals("rsa")) keyPair = cryptoHelper.generateRsaKeyPair();

            JcaPEMWriter pubPemWriter = new JcaPEMWriter(new FileWriter("TGS-KeyPair/TGS-PublicKey"));
            pubPemWriter.writeObject(keyPair.getPublic());
            pubPemWriter.close();

            JcaPEMWriter prvPemWriter = new JcaPEMWriter(new FileWriter("TGS-KeyPair/TGS-PrivateKey"));
            prvPemWriter.writeObject(keyPair.getPrivate());
            prvPemWriter.close();
        }
    }


}
