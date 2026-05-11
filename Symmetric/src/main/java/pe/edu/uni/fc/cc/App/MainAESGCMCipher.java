/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.App;

import java.security.SecureRandom;
import static pe.edu.uni.fc.cc.common.Constans.AES_GCM_AAD;
import static pe.edu.uni.fc.cc.common.Constans.AES_GCM_IV_LENGTH;
import pe.edu.uni.fc.cc.common.Utils;
import pe.edu.uni.fc.cc.service.AESGCMCipherService;

/**
 *
 * @author alumno
 */
public class MainAESGCMCipher {
    public static void main(String[] args){
        System.out.println("MainAESGCMCipher !!!");
        String msg="This is a message";
        byte[] key=new byte[16];
        SecureRandom r=new SecureRandom();
        r.nextBytes(key);
        AESGCMCipherService aes_gcm=new AESGCMCipherService(key);
        
        byte[] iv=Utils.generateIV(AES_GCM_IV_LENGTH);
      
        String encrypted = aes_gcm.encrypt(msg,iv,AES_GCM_AAD);
        String decrypted = aes_gcm.decrypt(encrypted,AES_GCM_AAD);
        
        System.out.println("original "+msg);
        System.out.println("Encrypted "+encrypted);
        System.out.println("Decrypt "+decrypted);
                
    }
}
