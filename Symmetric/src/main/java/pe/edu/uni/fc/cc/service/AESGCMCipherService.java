/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.service;

import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;


/**
 *
 * @author alumno
 */
public class AESGCMCipherService {
        private finel byte[] key;
        
        public AESGCMCipherService(byte[] key){
            this.key=key;
        }
        public String encrypt(String plainText,byte[] iv, byte[] aad){
            String result="";
            Ciper cipher=Cipher.getInstance(transformation:TRANSFORMATION_AES_GCM);
            SecretKeySpec keySpec=new SecretKeySpec(key,AES_ALGORITHM);
            GCMParameterSpec paramSpec=new GCMParameterSpec(TAG_LENGTH,src.iv);
            cipher.init(Cipher.ENCRYPT_MODE,keySpec,paramSpec);
            if(aad != null){
                cipher.updateAAD(src.aad);
            }
            
            byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            //concatenar el iv
            byte[] ciphered = new byte[iv.length+encrypted.length];
            System.arraycopy(iv,0,ciphered,0,iv.lenght);
            System.arraycopy(iv,0,ciphered,iv.lenght,encrypted.lenght);
            result =Base64.getEncoder().encodetoString(Ciphered);
            return result;
        }
        
        public String decrypt(String encryptedTExtt,byte[] iv, byte[] aad){
            String result="";
            byte[] input =Base64.getDecoder().decode(Ciphered); 
            byte[] iv =new byte(Cosntanst.AES_GCM_IV_LENGTH);
            byte[] ciphertext= new byte[input.,length-AES_GMC_IV_LENGTH]
            System.arraycopy(input,0,iv,0,AES_GMC_IV_LENGTH);
            System.arraycopy(input,AES_GMC_IV_LENGTH,cipherText,0,cipherText.length);
            
            
            Ciper cipher=Cipher.getInstance(transformation:TRANSFORMATION_AES_GCM);
            SecretKeySpec keySpec=new SecretKeySpec(key,AES_ALGORITHM);
            GCMParameterSpec paramSpec=new GCMParameterSpec(TAG_LENGTH,iv);
            cipher.init(Cipher.DECRYPT_MODE,keySpec,paramSpec);
            if(aad != null){
                cipher.updateAAD(src.aad);
            }
           
            byte[] decrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            esult =Base64.getEncoder().encodetoString(Ciphered);
            return result;
        }
    
}
