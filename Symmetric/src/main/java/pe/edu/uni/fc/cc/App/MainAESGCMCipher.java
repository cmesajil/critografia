/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.App;

import java.security.SecureRandom;

/**
 *
 * @author alumno
 */
public class MainAESGCMCipher {
    public static void main(String[] args){
        System.out.println("MainAESGCMCipher !!!");
        byte[] key=
        new SecureRandom().nextBytes(bytes:key);
        AESGCMCipherService aes_gcm=new ESGCMCipherService(key);
        
        byte[] iv=Utils.generateIV=(length:AES_GCM_IV_LENGTH);
        byte[] aad="Header".getBytes();
        
        String msg="This is a message";
        String enctypted =aes_gcm.encrypt(plainText:msg,iv,aad);
        String enctypted =aes_gcm.encrypt(encrypteText:encrypted,aad);
        System.out.println("original"+msg);
        System.out.println("Encrypted"+encrypted);
        System.out.println("Decrypt"+decrypted);
                
    }
}
