package wisedu.xuechengencrypt.service.Impl;

import org.bouncycastle.util.encoders.Base64;
import org.springframework.stereotype.Service;
import wisedu.xuechengencrypt.encrypt.Util;
import wisedu.xuechengencrypt.service.ProcessCertService;

import java.io.*;

@Service
public class ProcessCertServiceImpl implements ProcessCertService {

    //从本地路径下的json文件从读取证书
    public String readJsonCert(String path) throws IOException {
        File file = new File(path);
        StringBuilder stringb = new StringBuilder();

        Reader reader = null;
        try {
            reader = new InputStreamReader(new FileInputStream(file));
            int tempchar;
            while ((tempchar = reader.read()) != -1) {
                //用逗号会出问题,这里把json文件的，替换掉
                if (((char) tempchar) == ',')
                    tempchar=';';
                stringb.append((char) tempchar);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        if(reader != null){
            reader.close();
        }
        String plainText=stringb.toString();
        return plainText;
    }

    public String addSchoolSign(String sign,String plainText){

        String pubk = "040AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857";
        String pubkS = new String(Base64.encode(Util.hexToByte(pubk)));
        String signedCert=plainText.replace("}",";\"SchoolpubkS\":\""+pubkS+"\";\"sign\":\""+sign+"\"}");
        return signedCert;

    }
}
