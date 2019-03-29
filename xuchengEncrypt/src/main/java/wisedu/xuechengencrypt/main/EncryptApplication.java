package wisedu.xuechengencrypt.main;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;


@SpringBootApplication
@ComponentScan(basePackages = {"wisedu.xuechengencrypt"})
public class EncryptApplication {
    public static void main(String[] args){
        SpringApplication.run(EncryptApplication.class,args);
    }
}
