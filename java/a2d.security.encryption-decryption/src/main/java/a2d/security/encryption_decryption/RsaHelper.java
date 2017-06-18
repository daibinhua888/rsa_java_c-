package a2d.security.encryption_decryption;

/**
 * Created by z on 2017/5/9.
 */

import org.apache.commons.lang.ArrayUtils;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;

import javax.crypto.Cipher;

public class RsaHelper {

    public static String getKey(String file){
        try
        {
            BufferedReader br=new BufferedReader(new FileReader(file));
            String s=br.readLine();
            StringBuilder key=new StringBuilder();
            s=br.readLine();
            while (s.charAt(0)!='-'){
                key.append(s+"\r");
                s=br.readLine();
            }
            return key.toString();
        }
        catch (Exception e)
        {
            return null;
        }
    }


    /**
     * 生成RSA密钥对(默认密钥长度为1024)
     *
     * @return
     */
    public static KeyPair generateRSAKeyPair() {
        return generateRSAKeyPair(1024);
    }

    public static KeyPair generateRSAKeyPair(String publicKey, String privateKey) {
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        BASE64Decoder decoder = new BASE64Decoder();

        PrivateKey pk_privateKey = null;
        try {
            pk_privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decoder.decodeBuffer(privateKey)));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        PublicKey pk_publicKey = null;
        try {
            pk_publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(decoder.decodeBuffer(publicKey)));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        return new KeyPair(pk_publicKey, pk_privateKey);
    }


    /**
     * 生成RSA密钥对
     *
     * @param keyLength
     *            密钥长度，范围：512～2048
     * @return
     */
    public static KeyPair generateRSAKeyPair(int keyLength) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keyLength);
            return kpg.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public static String encodePublicKeyToXml(PublicKey key) {
        if (!RSAPublicKey.class.isInstance(key)) {
            return null;
        }
        RSAPublicKey pubKey = (RSAPublicKey) key;
        StringBuilder sb = new StringBuilder();

        sb.append("<RSAKeyValue>");
        sb.append("<Modulus>")
                .append(Base64Helper.encode(pubKey.getModulus().toByteArray()))
                .append("</Modulus>");
        sb.append("<Exponent>")
                .append(Base64Helper.encode(pubKey.getPublicExponent()
                        .toByteArray())).append("</Exponent>");
        sb.append("</RSAKeyValue>");
        return sb.toString();
    }

    public static PublicKey decodePublicKeyFromXml(String xml) {
        xml = xml.replaceAll("\r", "").replaceAll("\n", "");
        BigInteger modulus = new BigInteger(1, Base64Helper.decode(StringHelper
                .GetMiddleString(xml, "<Modulus>", "</Modulus>")));
        BigInteger publicExponent = new BigInteger(1,
                Base64Helper.decode(StringHelper.GetMiddleString(xml,
                        "<Exponent>", "</Exponent>")));

        RSAPublicKeySpec rsaPubKey = new RSAPublicKeySpec(modulus,
                publicExponent);

        KeyFactory keyf;
        try {
            keyf = KeyFactory.getInstance("RSA");
            return keyf.generatePublic(rsaPubKey);
        } catch (Exception e) {
            return null;
        }
    }

    public static PrivateKey decodePrivateKeyFromXml(String xml) {
        xml = xml.replaceAll("\r", "").replaceAll("\n", "");
        BigInteger modulus = new BigInteger(1, Base64Helper.decode(StringHelper
                .GetMiddleString(xml, "<Modulus>", "</Modulus>")));
        BigInteger publicExponent = new BigInteger(1,
                Base64Helper.decode(StringHelper.GetMiddleString(xml,
                        "<Exponent>", "</Exponent>")));
        BigInteger privateExponent = new BigInteger(1,
                Base64Helper.decode(StringHelper.GetMiddleString(xml, "<D>",
                        "</D>")));
        BigInteger primeP = new BigInteger(1, Base64Helper.decode(StringHelper
                .GetMiddleString(xml, "<P>", "</P>")));
        BigInteger primeQ = new BigInteger(1, Base64Helper.decode(StringHelper
                .GetMiddleString(xml, "<Q>", "</Q>")));
        BigInteger primeExponentP = new BigInteger(1,
                Base64Helper.decode(StringHelper.GetMiddleString(xml, "<DP>",
                        "</DP>")));
        BigInteger primeExponentQ = new BigInteger(1,
                Base64Helper.decode(StringHelper.GetMiddleString(xml, "<DQ>",
                        "</DQ>")));
        BigInteger crtCoefficient = new BigInteger(1,
                Base64Helper.decode(StringHelper.GetMiddleString(xml,
                        "<InverseQ>", "</InverseQ>")));

        RSAPrivateCrtKeySpec rsaPriKey = new RSAPrivateCrtKeySpec(modulus,
                publicExponent, privateExponent, primeP, primeQ,
                primeExponentP, primeExponentQ, crtCoefficient);

        KeyFactory keyf;
        try {
            keyf = KeyFactory.getInstance("RSA");
            return keyf.generatePrivate(rsaPriKey);
        } catch (Exception e) {
            return null;
        }
    }

    public static String encodePrivateKeyToXml(PrivateKey key) {
        if (!RSAPrivateCrtKey.class.isInstance(key)) {
            return null;
        }
        RSAPrivateCrtKey priKey = (RSAPrivateCrtKey) key;
        StringBuilder sb = new StringBuilder();

        sb.append("<RSAKeyValue>");
        sb.append("<Modulus>")
                .append(Base64Helper.encode(TrimLeadingZero(priKey.getModulus().toByteArray())))
                .append("</Modulus>");
        sb.append("<Exponent>")
                .append(Base64Helper.encode(TrimLeadingZero(priKey.getPublicExponent()
                        .toByteArray()))).append("</Exponent>");
        sb.append("<P>")
                .append(Base64Helper.encode(TrimLeadingZero(priKey.getPrimeP().toByteArray())))
                .append("</P>");
        sb.append("<Q>")
                .append(Base64Helper.encode(TrimLeadingZero(priKey.getPrimeQ().toByteArray())))
                .append("</Q>");
        sb.append("<DP>")
                .append(Base64Helper.encode(TrimLeadingZero(priKey.getPrimeExponentP()
                        .toByteArray()))).append("</DP>");
        sb.append("<DQ>")
                .append(Base64Helper.encode(TrimLeadingZero(priKey.getPrimeExponentQ()
                        .toByteArray()))).append("</DQ>");
        sb.append("<InverseQ>")
                .append(Base64Helper.encode(TrimLeadingZero(priKey.getCrtCoefficient()
                        .toByteArray()))).append("</InverseQ>");
        sb.append("<D>")
                .append(Base64Helper.encode(TrimLeadingZero(priKey.getPrivateExponent()
                        .toByteArray()))).append("</D>");
        sb.append("</RSAKeyValue>");
        return sb.toString();
    }

    static byte[] TrimLeadingZero(byte[] values) {
        if ((0x00 == values[0]) && (values.length > 1)) {
            byte[] r = null;
            r = new byte[values.length - 1];
            System.arraycopy(values,1,r,0,r.length);
            return r;
        }

        return values;
    }

    // 用公钥加密
    public static byte[] encryptData(byte[] data, PublicKey pubKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);

            if (data.length <= 100)
                return cipher.doFinal(data);

            byte[] dataReturn = null;
            for (int i = 0; i < data.length; i += 100) {
                byte[] doFinal = cipher.doFinal(ArrayUtils.subarray(data, i, i + 100));
                dataReturn = ArrayUtils.addAll(dataReturn, doFinal);
            }
            return dataReturn;
        } catch (Exception e) {
            return null;
        }
    }

    public static String encrypt(String text, PublicKey pubKey) throws Exception {
    String encryptedText = "";
    Cipher cipher = Cipher.getInstance("RSA");

    cipher.init(Cipher.ENCRYPT_MODE, pubKey);
    byte[] dataReturn = null;
    byte[] data = text.getBytes("UTF-8");
    if (data.length <= 100) {
        dataReturn = cipher.doFinal(data);
    } else {
        for (int i = 0; i < data.length; i += 100) {
            byte[] doFinal = cipher.doFinal(ArrayUtils.subarray(data, i, i + 100));
            dataReturn = ArrayUtils.addAll(dataReturn, doFinal);
        }
    }
    encryptedText = (new BASE64Encoder()).encode(dataReturn);
    return encryptedText;
}

    // 用私钥解密
    public static byte[] decryptData(byte[] encryptedData, PrivateKey priKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, priKey);

            if (encryptedData.length <= 128)
                return cipher.doFinal(encryptedData);

            byte[] dataReturn = null;
            for (int i = 0; i < encryptedData.length; i += 128) {
                byte[] piece = ArrayUtils.subarray(encryptedData, i, i + 128);
                byte[] doFinal = cipher.doFinal(piece);
                dataReturn = ArrayUtils.addAll(dataReturn, doFinal);
            }

            return dataReturn;

        } catch (Exception e) {
            return null;
        }
    }

    public static String decrypt(String text, PrivateKey priKey) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.DECRYPT_MODE, priKey);
    StringBuilder sb = new StringBuilder();
    byte[] data = new BASE64Decoder().decodeBuffer(text);
    if (data.length <= 128) {
        sb.append(new String(cipher.doFinal(data)));
    } else {
        for (int i = 0; i < data.length; i += 128) {
            byte[] piece = ArrayUtils.subarray(data, i, i + 128);
            byte[] doFinal = cipher.doFinal(piece);
            sb.append(new String(doFinal, "UTF-8"));
        }
    }
    return sb.toString();
}

    /**
     * 根据指定私钥对数据进行签名(默认签名算法为"SHA1withRSA")
     *
     * @param data
     *            要签名的数据
     * @param priKey
     *            私钥
     * @return
     */
    public static byte[] signData(byte[] data, PrivateKey priKey) {
        return signData(data, priKey, "SHA1withRSA");
    }

    /**
     * 根据指定私钥和算法对数据进行签名
     *
     * @param data
     *            要签名的数据
     * @param priKey
     *            私钥
     * @param algorithm
     *            签名算法
     * @return
     */
    public static byte[] signData(byte[] data, PrivateKey priKey,
                                  String algorithm) {
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(priKey);
            signature.update(data);
            return signature.sign();
        } catch (Exception ex) {
            return null;
        }
    }

    /**
     * 用指定的公钥进行签名验证(默认签名算法为"SHA1withRSA")
     *
     * @param data
     *            数据
     * @param sign
     *            签名结果
     * @param pubKey
     *            公钥
     * @return
     */
    public static boolean verifySign(byte[] data, byte[] sign, PublicKey pubKey) {
        return verifySign(data, sign, pubKey, "SHA1withRSA");
    }

    /**
     *
     * @param data 数据
     * @param sign 签名结果
     * @param pubKey 公钥
     * @param algorithm 签名算法
     * @return
     */
    public static boolean verifySign(byte[] data, byte[] sign,
                                     PublicKey pubKey, String algorithm) {
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initVerify(pubKey);
            signature.update(data);
            return signature.verify(sign);
        } catch (Exception ex) {
            return false;
        }
    }
}