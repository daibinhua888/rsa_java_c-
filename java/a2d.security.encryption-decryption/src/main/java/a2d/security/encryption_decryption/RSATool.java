package a2d.security.encryption_decryption;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

/**
 * Created by z on 2017/5/9.
 */
public class RSATool {
    public static void main(String[] args) {

        KeyPair kp = RsaHelper.generateRSAKeyPair();
        PublicKey pubKey = kp.getPublic();
        PrivateKey priKey = kp.getPrivate();

        String pubKeyXml = RsaHelper.encodePublicKeyToXml(pubKey);
        String priKeyXml = RsaHelper.encodePrivateKeyToXml(priKey);//.net能辨认的私钥格式
        System.out.println("====公钥====");
        System.out.println(pubKeyXml);
        System.out.println("====私钥====");
        System.out.println(priKeyXml);

        String dataStr = "表示表示表示表示表示表示表示表示表示表示表示表示表示表示表示表示表示表示表示表表示表示表示表示表示表示表示表示表示表示表示表示表示表示表示表示表示表示表示表";

        try {
            System.out.println("====加密后的文本 BEGIN====");
            System.out.println(RsaHelper.encrypt(dataStr, pubKey));
            System.out.println("====加密后的文本 END====");
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
