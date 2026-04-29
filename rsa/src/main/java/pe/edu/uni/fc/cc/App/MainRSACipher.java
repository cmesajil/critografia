/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.App;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import static pe.edu.uni.fc.cc.common.Constans.RSA_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constans.RSA_KEY_SIZE_2048;
import pe.edu.uni.fc.cc.rsa.RSACipher;
import pe.edu.uni.fc.cc.services.RSACipherService;

/**
 *
 * @author alumno
 */
public class MainRSACipher {
           
    public static void main(String[] args) {
        
        try {
            System.out.println("Hello World RSA !!!");
            //generara las llaves antisimetricas (pair)
            KeyPairGenerator kpg =KeyPairGenerator.getInstance(RSA_ALGORITHM);
            kpg.initialize(RSA_KEY_SIZE_2048);
            KeyPair kp=kpg.generateKeyPair();
            System.out.println("Generated Key Pair !!!");
            RSACipherService service=new RSACipherService(kp);
            
            
            //cifrar con primos
            String message="This is a massage with RSA algorithm";
            String encryptedText=service.encrypt(message);
            String decryptedText=service.decrypt(encryptedText);
            
            //verificar (descifrer) con la llave publica
            System.out.println("Original text: "+message);
            System.out.println("Encrypted text: "+encryptedText);
            System.out.println("Decrypted text: "+decryptedText);
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(RSACipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        
    }
                     
            
}
