package wisedu.xuechengencrypt.service.Impl;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.stereotype.Service;
import wisedu.xuechengencrypt.encrypt.SM2Utils;
import wisedu.xuechengencrypt.encrypt.SM3Digest;
import wisedu.xuechengencrypt.encrypt.SM4Utils;
import wisedu.xuechengencrypt.encrypt.Util;
import wisedu.xuechengencrypt.service.SmEncryptService;

import java.io.IOException;

@Service
public class SmEncryptServiceImpl implements SmEncryptService {
    //使用SM2对证书内容进行签名，签名追加到证书后面

    public String sm2SignCert(String cert) throws IOException {
        //String plainText = "{\"certID\":\"2013061367895\";\"name\":\"zhangsan\";\"publisher\":\"SEU\";\"image:0ff2384rhfdjaso8jhshdwqeouowqdcmweunq38ryvn98\"}";
        String plainText = cert;
        //plainText="{certID:2013061367895}";
        byte[] sourceData = plainText.getBytes();
        System.out.println("加密用的cert=>" + plainText);

        // 国密规范测试私钥
        String prik = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";
        String prikS = new String(Base64.encode(Util.hexToByte(prik)));

        // 国密规范测试用户ID
        String userId = "ALICE123@YAHOO.COM";

        //用id和私钥签名fff
        byte[] c = SM2Utils.sign(userId.getBytes(), Base64.decode(prikS.getBytes()), sourceData);

        return Util.getHexString(c);
    }

    //验证签名
    public boolean sm2VerifySign(String signedCert) throws IOException {
        // 国密规范测试用户ID
        String userId = "ALICE123@YAHOO.COM";

        String[] sourceArray = signedCert.split(";");
        String pubkS = sourceArray[4].substring(15, sourceArray[4].length() - 1);
        String sign = sourceArray[5].substring(8, sourceArray[5].length() - 3);
        System.out.println("pubkS:" + pubkS);
        System.out.println("sign:" + sign);

        String cert = sourceArray[0] + ";" + sourceArray[1] + ";" + sourceArray[2] + ";" + sourceArray[3] + "}\n";
        //String cert=sourceArray[0]+"}";
        System.out.println("解密用的cert=》" + cert);
        System.out.println("现长度：" + cert.length());
        //cert="{certID:2013061367895}";
        byte[] sourceData = cert.getBytes();
        //sourceData="{\"certID\":\"2013061367895\";\"name\":\"zhangsan\";\"publisher\":\"SEU\";\"image:0ff2384rhfdjaso8jhshdwqeouowqdcmweunq38ryvn98\"}".getBytes();
        //用id,公钥和明文验证签名是否通过
        boolean vs = SM2Utils.verifySign(userId.getBytes(), Base64.decode(pubkS.getBytes()), sourceData, Util.hexStringToBytes(sign));
        System.out.println(vs);

        return vs;
    }

    public String sm3CreateHash(String signedCert) throws IOException {

        byte[] md = new byte[32];
        byte[] msg1 = signedCert.getBytes();
        //System.out.println(msg1);
        SM3Digest sm3 = new SM3Digest();
        sm3.update(msg1, 0, msg1.length);
        sm3.doFinal(md, 0);
        String s = new String(Hex.encode(md));
        return s;
    }

    public String sm4EncryptCert(String signedCert) throws IOException {

        //使用sm4中的CBC模式对称加密数字证书
        SM4Utils sm4 = new SM4Utils();
        sm4.setSecretKey("JeF8U9wHFOMfs2Y8");
        sm4.setHexString(false);
        sm4.setIv("UISwD9fW6cFh9SNS");
        String cipherText = sm4.encryptData_CBC(signedCert);
        //System.out.println("密文: " + cipherText);
        return cipherText;
    }

    public String sm4DecryptCert(String cipherText) {
        SM4Utils sm4 = new SM4Utils();
        sm4.setSecretKey("JeF8U9wHFOMfs2Y8");
        sm4.setHexString(false);
        sm4.setIv("UISwD9fW6cFh9SNS");
        String signedPlainText = sm4.decryptData_CBC(cipherText);
        System.out.println("解密后:" + signedPlainText);
        return signedPlainText;
    }
}

