package wisedu.xuechengencrypt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import wisedu.xuechengencrypt.service.ProcessCertService;
import wisedu.xuechengencrypt.service.SmEncryptService;

import java.io.IOException;
import java.util.UUID;

@RestController(value = "encrypt")
public class encryptController {


    @Autowired
    private SmEncryptService smEncryptService;

    @Autowired
    private ProcessCertService processCertService;



//初始化待上链证书
    @RequestMapping(value = "/Initcert",method = RequestMethod.GET)
    public ResponseEntity<String> InitCert(@RequestParam(value = "plainText") String plainText ) throws IOException {

        long startTime=System.nanoTime();
        //从目录下读取json格式的数字证书，更换,为;
//        String plainText = ProcessCertService.readJsonCert(path);



        //对证书追加学校公钥和学校签名
        // 国密规范测试公钥
        String sign = smEncryptService.sm2SignCert(plainText);
        String signedCert = processCertService.addSchoolSign(sign, plainText);

        //使用sm3生成该证书内容的哈希值
        String hash = smEncryptService.sm3CreateHash(signedCert);
        System.out.println("hash:"+hash);

        //使用sm4中的CBC模式对称加密数字证书
        String cipherText = smEncryptService.sm4EncryptCert(signedCert);

        //生成uuid
        UUID uuid  =  UUID.randomUUID();
        System.out.println("对应的uuid为" + uuid);

//        //把加密后的参数调用外部url上链
//        String svcUrl = serviceUrl + "/api/invoke";
//        MultiValueMap<String, String> requestEntity = new LinkedMultiValueMap<>();
//        requestEntity.add("Chaincode_function", "InitCert");
//        requestEntity.add("Chaincode_args", uuid + "," + args + "," + hash + "," + cipherText);
//        ResponseEnreturn responseEntity;tity<String> responseEntity = rest.postForEntity(svcUrl,requestEntity,String.class);

        long endTime=System.nanoTime(); //获取结束时间
        System.out.println("程序运行时间： "+(endTime-startTime)+"ns");
        return new ResponseEntity<String>(cipherText,HttpStatus.OK);
    }


    @RequestMapping(value = "/sm2SignCert",method = RequestMethod.GET)
    public ResponseEntity<String> SignCert(@RequestParam(value="plainText") String plainText) throws IOException {

        String res =smEncryptService.sm2SignCert(plainText);

        return new ResponseEntity<String>(res, HttpStatus.OK);
    }

    @RequestMapping(value="/sm2VerifyCert", method = RequestMethod.GET)
    public  ResponseEntity<String> VerifySign(@RequestParam(value = "CipherText") String CipherText) throws IOException{
        String[] sourceStrArray = CipherText.split(",");

        System.out.println("aaaaaaa"+sourceStrArray[0]);

        String cipherText = sourceStrArray[3].substring(12, sourceStrArray[3].length() - 1);


        System.out.println("bbbbb"+cipherText);
        //返回SM4解密后的证书内容
        String signedPlainText=smEncryptService.sm4DecryptCert(cipherText);

        if(smEncryptService.sm2VerifySign(signedPlainText))
            return ResponseEntity.status(200).body("true");
        else
            return ResponseEntity.status(300).body("false");

          }
}
