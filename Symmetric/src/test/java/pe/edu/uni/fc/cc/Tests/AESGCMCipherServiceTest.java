/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.Tests;

import java.security.SecureRandom;
import org.junit.jupiter.api.Test;
import static pe.edu.uni.fc.cc.common.Constans.AES_CBC_IV_LENGTH;
import pe.edu.uni.fc.cc.common.Utils;
import static pe.edu.uni.fc.cc.common.Utils.generateIV;
import pe.edu.uni.fc.cc.service.AESCBCCipherService;

/**
 *
 * @author alumno
 */
public class AESGCMCipherServiceTest {
    
    @Test
    public void testEnctyptdecrypt(){
        System.out.println("Main Symmetric AES CBC service!!!");
        
        SecureRandom sr=new SecureRandom();
        byte[] key=new byte[AES_CBC_IV_LENGTH];
        sr.nextBytes(key);
        
       byte[] initVector;
       initVector=generateIV(AES_CBC_IV_LENGTH);
       
       //Visualizacion 
        System.out.println("Key: "+ Utils.byteToHex(key));
        System.out.println("Key: "+ Utils.byteToHex(initVector));
       
        AESCBCCipherService cipher=new AESCBCCipherService(key);
        
        String payload="This is plaintext sent from Alice to bob.";
        String encrypted=cipher.encrypt(initVector,payload);
        String decrypted=cipher.decrypt(encrypted); //initVector no debe eser entrada aqui
        
        System.out.println("Texto original: "+payload);
        System.out.println("Texto cifrado:"+ encrypted);
        System.out.println("Texto decifrado:"+ decrypted);
        
        String result=decrypted.equals(payload) ? "OK":"KO!";
        System.out.println("Iguales"+result);
    }
    
}
