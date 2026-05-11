/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.services;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import static pe.edu.uni.fc.cc.common.Constans.RSA_ALGORITHM;
import pe.edu.uni.fc.cc.rsa.RSACipher;

/**
 *
 * @author alumno
 */
public class RSACipherService {
    private final PublicKey publicKey ;
    private final PrivateKey privateKey;
    
    public RSACipherService(KeyPair kp){
        
        this.publicKey=kp.getPublic();
        this.privateKey=kp.getPrivate();
               
    }
    
    public byte[] encrypt(byte[] byteText){
        if(publicKey==null) return null;
        byte[] result=null;
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE,this.publicKey);
            byte[] encryptedText=cipher.doFinal(byteText);
            result=encryptedText;
        
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(RSACipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchPaddingException ex) {
            System.getLogger(RSACipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (InvalidKeyException ex) {
            System.getLogger(RSACipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (IllegalBlockSizeException ex) {
            System.getLogger(RSACipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (BadPaddingException ex) {
            System.getLogger(RSACipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        
        return result;
    }
    
    public String encrypt(String plainText){
        byte[] encryptedText=encrypt(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedText);
    }
    
    public byte[] decrypt(byte[] encryptedText){
        if(publicKey==null) return null;
        byte[] result=null;
        try {
            
            Cipher cipher=Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE,this.privateKey);
            byte[] decodeEncryptedText=encryptedText;
            byte[] decryptedText=cipher.doFinal(decodeEncryptedText);
            result=decryptedText;
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(RSACipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchPaddingException ex) {
            System.getLogger(RSACipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (InvalidKeyException ex) {
            System.getLogger(RSACipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (IllegalBlockSizeException ex) {
            System.getLogger(RSACipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (BadPaddingException ex) {
            System.getLogger(RSACipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
         return result;   
     }
    
    public String decrypt(String encryptedText){
        byte[] decryptedText=decrypt(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedText);
    }
}

