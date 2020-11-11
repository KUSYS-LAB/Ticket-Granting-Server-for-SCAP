package kr.ac.korea.sans.tgs.util;

import kr.ac.korea.sans.tgs.constant.Constants;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.TimeZone;

@Component
public class CryptoHelper {

    private static Logger logger = LoggerFactory.getLogger(CryptoHelper.class);

    private static final CryptoHelper cryptoHelper = new CryptoHelper();

    public CryptoHelper() { }

    public static CryptoHelper getInstance() {
        return cryptoHelper;
    }

    public byte[] getSignature(String data) throws Exception{
//        checkKeyPair();

//        PrivateKey privateKey = readPrivateKeyFromPemFile("TGS-KeyPair/TGS-PrivateKey");
        PrivateKey privateKey = this.restorePrivateKeyFromPem(new FileReader("TGS-KeyPair/TGS-PrivateKey"));

        Charset charset = Charset.forName("UTF-8");
        byte[] signature = getSignature(privateKey, data.getBytes(charset));

        return signature;
    }

    public static byte[] getSignature(PrivateKey privateKey, byte[] data) throws GeneralSecurityException {
        Signature signature = null;
        if (Constants.TYPE_PKI.toLowerCase().trim().equals("ec")) {
            signature = Signature.getInstance("SHA256withECDSA");
        } else if (Constants.TYPE_PKI.toLowerCase().trim().equals("rsa")) {
            signature = Signature.getInstance("SHA256withRSA");
        }

        signature.initSign(privateKey);
        signature.update(data);

        byte[] signatureData = signature.sign();
        return signatureData;
    }

    public SecretKey getSecretEncryptionKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        SecretKey secretKey = generator.generateKey();

        return secretKey;
    }

    public IvParameterSpec getIvParameterSpec() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] ivData = new byte[16]; //128 bit
        random.nextBytes(ivData);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivData);
        Charset charset = Charset.forName("UTF-8");

        return ivParameterSpec;
    }

    // CBC AES Encrypt
    public byte[] encrypt(SecretKey secretKey, IvParameterSpec iv, String plainData) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] encryptData = cipher.doFinal(plainData.getBytes());

        return encryptData;
    }

    public String getPublicKey() throws Exception {
//        checkKeyPair();

        String data = readString("TGS-KeyPair/TGS-PublicKey");

        return data;
    }

//    public void checkKeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, IOException, NoSuchProviderException {
//        if (!new File("TGS-KeyPair").exists()) new File("TGS-KeyPair").mkdir();
//        if (!new File("TGS-KeyPair/TGS-PublicKey").exists() || !new File("TGS-KeyPair/TGS-PrivateKey").exists()) {
//            KeyPair keyPair = null;
//            if (Constants.TYPE_PKI.toLowerCase().trim().equals("ec")) keyPair = this.generateEcKeyPair();
//            else if (Constants.TYPE_PKI.toLowerCase().trim().equals("rsa")) keyPair = this.generateRsaKeyPair();
//
//            JcaPEMWriter pubPemWriter = new JcaPEMWriter(new FileWriter("TGS-KeyPair/TGS-PublicKey"));
//            pubPemWriter.writeObject(keyPair.getPublic());
//            pubPemWriter.close();
//
//            JcaPEMWriter prvPemWriter = new JcaPEMWriter(new FileWriter("TGS-KeyPair/TGS-PrivateKey"));
//            prvPemWriter.writeObject(keyPair.getPrivate());
//            prvPemWriter.close();
//        }
//    }

    // Read String from File
    private String readString(String filename) throws FileNotFoundException, IOException {
        String pem = "";
        BufferedReader br = new BufferedReader(new FileReader(filename));

        String line;
        while((line = br.readLine()) != null) pem += line + "\n";

        br.close();
        return pem;
    }

    public KeyPair generateEcKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        //ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        SecureRandom random = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA");
        keyPairGenerator.initialize(ecSpec, random);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        return keyPair;
    }

    private static void writePemFile(Key key, String description, String filename)
        throws FileNotFoundException, IOException {
        PemFile pemFile = new PemFile(key, description);
        pemFile.write(filename);
    }


    public void writeToFile(File output, byte[] toWrite)
            throws IllegalBlockSizeException, BadPaddingException, IOException {
        FileOutputStream fos = new FileOutputStream(output);
        fos.write(toWrite);
        fos.flush();
        fos.close();
    }

//    public PublicKey convertStringtoPK(String cpk) throws NoSuchAlgorithmException, InvalidKeySpecException {
//        cpk = cpk.replaceAll("-----BEGIN PUBLIC KEY-----","");
//        cpk = cpk.replaceAll("-----END PUBLIC KEY-----","");
//        cpk = cpk.replaceAll(System.getProperty("line.separator"),"");
//
//        byte[] decodedCpk = org.bouncycastle.util.encoders.Base64.decode(cpk);
//
//        X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedCpk);
//        KeyFactory kf = KeyFactory.getInstance(Constants.TYPE_PKI);
//        PublicKey cpkPublicKey = kf.generatePublic(spec);
//
//        return cpkPublicKey;
//
//    }


    public static boolean verifySignature(PublicKey publicKey, byte[] signatureData,
                                          byte[] plainData) throws GeneralSecurityException {
        Signature signature = null;
        if (Constants.TYPE_PKI.toLowerCase().trim().equals("ec")) {
            signature = Signature.getInstance("SHA256withECDSA");
        } else if (Constants.TYPE_PKI.toLowerCase().trim().equals("rsa")) {
            signature = Signature.getInstance("SHA256withRSA");
        }
        signature.initVerify(publicKey);
        signature.update(plainData);
        return signature.verify(signatureData);
    }

    public static boolean isTicketVal(Map<String, Object>ticket, Map<String, Object>time) throws ParseException {
        // (1) 티켓의 timestamp와 time의 from/to 비교
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd HH:mm");
        sdf2.setTimeZone(TimeZone.getTimeZone("Asia/Seoul"));
        Date ticketTime = Calendar.getInstance(TimeZone.getTimeZone("Asia/Seoul")).getTime();
        Date timeFrom = sdf2.parse((String)time.get("from"));
        Date timeTo = sdf2.parse((String)time.get("to"));



        if (ticketTime.after(timeFrom) && ticketTime.before(timeTo)){
            return true;
        }
        return false;
    }

    public byte[] decryptWithAes(Key sk, IvParameterSpec iv, byte[] cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, sk, iv);
        byte[] decryptedData = cipher.doFinal(cipherText);
        return decryptedData;
    }

    public PublicKey restorePublicKeyFromPem(String pem) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        Reader reader = new StringReader(pem);
        SubjectPublicKeyInfo parser = (SubjectPublicKeyInfo) new PEMParser(reader).readObject();
        return new JcaPEMKeyConverter().getPublicKey(parser);
//		Reader reader = new StringReader(pem);
//		PEMKeyPair parser = (PEMKeyPair) new PEMParser(reader).readObject();
//		return new JcaPEMKeyConverter().getPublicKey(parser.getPublicKeyInfo());
    }

    public PublicKey restorePublicKeyFromPem(FileReader pemReader) throws IOException {
        SubjectPublicKeyInfo parser = (SubjectPublicKeyInfo) new PEMParser(pemReader).readObject();
        return new JcaPEMKeyConverter().getPublicKey(parser);
//		PEMKeyPair parser = (PEMKeyPair) new PEMParser(pemReader).readObject();
//		return new JcaPEMKeyConverter().getPublicKey(parser.getPublicKeyInfo());
    }

    public PrivateKey restorePrivateKeyFromPem(String pem) throws IOException {
        StringReader reader = new StringReader(pem);
        PrivateKeyInfo parser = (PrivateKeyInfo) new PEMParser(reader).readObject();
        return new JcaPEMKeyConverter().getPrivateKey(parser);
    }

    public PrivateKey restorePrivateKeyFromPem(FileReader pemReader) throws IOException {
        PEMKeyPair parser = (PEMKeyPair) new PEMParser(pemReader).readObject();
        return new JcaPEMKeyConverter().getPrivateKey(parser.getPrivateKeyInfo());
    }

    public String convertPublicKeyToPem(PublicKey publicKey) throws IOException {
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
        pemWriter.flush();
        pemWriter.close();
        String pemPublicKey = stringWriter.toString();
        stringWriter.close();

        return pemPublicKey;
    }

    public byte[] encryptWithRsa(byte[] data, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public byte[] decryptWithRsa(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

}
