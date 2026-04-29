/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package pe.edu.uni.fc.cc.rsa;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import static pe.edu.uni.fc.cc.common.Constans.RSA_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constans.RSA_KEY_SIZE_2048;

/**
 *
 * @author alumno
 */
public class RSACipher {

    public static void main(String[] args) {
        
        
        try {
            System.out.println("Hello World RSA !!!");
            //generara las llaves antisimetricas (pair)
            KeyPairGenerator kpg =KeyPairGenerator.getInstance(RSA_ALGORITHM);
            kpg.initialize(RSA_KEY_SIZE_2048);
            KeyPair kp=kpg.generateKeyPair();
            PublicKey pubKey= kp.getPublic();
            PrivateKey priKey=kp.getPrivate();
            System.out.println("Generated Key Pair !!!");
            //cifrar con primos
            String message="This is a massage with RSA algorithm";
            String encryptedText=encrypt(pubKey,message);
            String decryptedText=decrypt(priKey,encryptedText);
            
            //verificar (descifrer) con la llave publica
            System.out.println("Original text: "+message);
            System.out.println("Encrypted text: "+encryptedText);
            System.out.println("Decrypted text: "+decryptedText);
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(RSACipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        
 
    }
    
    
    
    private static String encrypt(PublicKey pubKey,String plainText){
        String result="";
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE,pubKey);
            byte[] encryptedText=cipher.doFinal(plainText.getBytes());
            result=Base64.getEncoder().encodeToString(encryptedText);
        
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
    
     private static String decrypt(PrivateKey priKey,String encryptedText){
         String result="";
        try {
            
            Cipher cipher=Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE,priKey);
            byte[] decodeEncryptedText=Base64.getDecoder().decode(encryptedText);
            byte[] decryptedText=cipher.doFinal(decodeEncryptedText);
            result=new String(decryptedText);
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
    
    
}
