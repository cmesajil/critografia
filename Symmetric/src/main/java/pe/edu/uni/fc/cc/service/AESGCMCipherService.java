/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.service;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import static pe.edu.uni.fc.cc.common.Constans.AES_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constans.AES_GCM_IV_LENGTH;
import static pe.edu.uni.fc.cc.common.Constans.TAG_LENGTH;
import static pe.edu.uni.fc.cc.common.Constans.TRANSFORMATION_AES_GCM;


/**
 *
 * @author alumno
 */
public class AESGCMCipherService {
        private final byte[] key;
        
        public AESGCMCipherService(byte[] key){
            this.key=key;
        }
        public byte[] encrypt(byte[] plainText,byte[] iv, byte[] aad){
            byte[] result=null;
            try {
                Cipher cipher=Cipher.getInstance(TRANSFORMATION_AES_GCM);
                SecretKeySpec keySpec=new SecretKeySpec(key,AES_ALGORITHM);
                GCMParameterSpec paramSpec=new GCMParameterSpec(TAG_LENGTH,iv);
                cipher.init(Cipher.ENCRYPT_MODE,keySpec,paramSpec);
                if(aad != null){
                    cipher.updateAAD(aad);
                }
                
                byte[] encrypted = cipher.doFinal(plainText);
                //concatenar el iv
                byte[] ciphered = new byte[iv.length+encrypted.length];
                System.arraycopy(iv,0,ciphered,0,iv.length);
                System.arraycopy(encrypted,0,ciphered,iv.length,encrypted.length);
                result =ciphered;
                
            } catch (NoSuchAlgorithmException ex) {
                System.getLogger(AESGCMCipherService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            } catch (NoSuchPaddingException ex) {
                System.getLogger(AESGCMCipherService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            } catch (InvalidKeyException ex) {
                System.getLogger(AESGCMCipherService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            } catch (InvalidAlgorithmParameterException ex) {
                System.getLogger(AESGCMCipherService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            } catch (IllegalBlockSizeException ex) {
                System.getLogger(AESGCMCipherService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            } catch (BadPaddingException ex) {
                System.getLogger(AESGCMCipherService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            }
      
            return result;
        
        }
        
        public String encrypt(String plaintext,byte[] iv,byte[] aad){
            byte[] ciphered=encrypt(plaintext.getBytes(StandardCharsets.UTF_8),iv,aad);
            return Base64.getEncoder().encodeToString(ciphered);
        }
        
        public byte[] decrypt(byte[] encryptedText, byte[] aad){
            byte[] result=null;
            try {
                
                byte[] input =encryptedText;
                byte[] iv =new byte[AES_GCM_IV_LENGTH];
                byte[] cipherText=new byte[input.length-iv.length];
                System.arraycopy(input,0,iv,0,iv.length);
                System.arraycopy(input,iv.length,cipherText,0,cipherText.length);
                
                
                Cipher cipher=Cipher.getInstance(TRANSFORMATION_AES_GCM);
                SecretKeySpec keySpec=new SecretKeySpec(key,AES_ALGORITHM);
                GCMParameterSpec paramSpec=new GCMParameterSpec(TAG_LENGTH,iv);
                cipher.init(Cipher.DECRYPT_MODE,keySpec,paramSpec);
                if(aad != null){
                    cipher.updateAAD(aad);
                }
                byte[] decrypted = cipher.doFinal(cipherText);
                //result =Base64.getEncoder().encodeToString(decrypted);
                result = decrypted;
                return result;
            } catch (NoSuchAlgorithmException ex) {
                System.getLogger(AESGCMCipherService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            } catch (NoSuchPaddingException ex) {
                System.getLogger(AESGCMCipherService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            } catch (InvalidKeyException ex) {
                System.getLogger(AESGCMCipherService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            } catch (InvalidAlgorithmParameterException ex) {
                System.getLogger(AESGCMCipherService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            } catch (IllegalBlockSizeException ex) {
                System.getLogger(AESGCMCipherService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            } catch (BadPaddingException ex) {
                System.getLogger(AESGCMCipherService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            }
        
        return result;
        }
        
        public String decrypt(String encryptedText,byte[] aad){
            byte[] decrypted=decrypt(Base64.getDecoder().decode(encryptedText),aad);
            return new String(decrypted,StandardCharsets.UTF_8);
        }
    
}
