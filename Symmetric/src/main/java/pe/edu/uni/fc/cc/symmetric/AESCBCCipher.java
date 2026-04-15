package pe.edu.uni.fc.cc.symmetric;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author mcg
 */


//como se construyo es diferenede de que se construyo

public class AESCBCCipher {
    
    
    public static String encrypt(byte[] key,byte[] initVector,String PlainText){
        String result="";
        try {
           
            IvParameterSpec iv=new IvParameterSpec(initVector); //vector de inicializacion , contenido
            SecretKeySpec sKeySpec = new SecretKeySpec(key,"AES");  //en que tipo de algoritmo lo vas a utilizar?
            Cipher cipher= Cipher.getInstance("AES/CBC/PKCS5Padding"); //en que modo , cual es su IV , cual es su llave, instancia , modo de operacion(ECB CBC GCM) transformacion , tiene relleno
            cipher.init(Cipher.ENCRYPT_MODE,sKeySpec,iv);
            byte[] encrypted = cipher.doFinal(PlainText.getBytes(StandardCharsets.UTF_8)); //codificacion clasica UTF-8 , falta add trhows
            result =Base64.getEncoder().encodeToString(encrypted);
            
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(AESCBCCipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchPaddingException ex) {
            System.getLogger(AESCBCCipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (InvalidKeyException ex) {
            System.getLogger(AESCBCCipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            System.getLogger(AESCBCCipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (IllegalBlockSizeException ex) {
            System.getLogger(AESCBCCipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (BadPaddingException ex) {
            System.getLogger(AESCBCCipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        
        return result;
    }
    
    public static String decrypt(byte[] key,byte[] initVector,String cipheredText){
        String result="";
        try {
            
            IvParameterSpec iv=new IvParameterSpec(initVector);
            SecretKeySpec sKeySpec = new SecretKeySpec(key,"AES");
            Cipher cipher= Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE,sKeySpec,iv);
            byte[] decrypted=cipher.doFinal(Base64.getDecoder().decode(cipheredText));
            result = new String(decrypted,StandardCharsets.UTF_8);
            
            
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(AESCBCCipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchPaddingException ex) {
            System.getLogger(AESCBCCipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (InvalidKeyException ex) {
            System.getLogger(AESCBCCipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            System.getLogger(AESCBCCipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (IllegalBlockSizeException ex) {
            System.getLogger(AESCBCCipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (BadPaddingException ex) {
            System.getLogger(AESCBCCipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        return result;
    }
    
    
    public static void main(String[] args) {
        System.out.println("Symmetric AES CBC !!!");
        
        
        //fuente de aleatoriedad
    
        SecureRandom sr=new SecureRandom();
        //llave AES 128bits
        byte[] key=new byte[16];
        //guarda en la llave con los bytes aleatorios de sr
        sr.nextBytes(key);

        //vector de inicializacion (IV) , mismo size que el anterior
        byte[] initVector = new byte[16];
        sr.nextBytes(initVector);   

        String payload="This is plaintext sent from Alice to bob.";
        String encrypted=encrypt(key,initVector,payload);
        String decrypted=decrypt(key,initVector,encrypted); //initVector no debe eser entrada aqui
        
        System.out.println("Texto original: "+payload);
        System.out.println("Texto cifrado:"+ encrypted);
        System.out.println("Texto decifrado:"+ decrypted);
        
        String result=decrypted.equals(payload) ? "OK":"KO!";
        System.out.println("Iguales"+result);
               
    }
    
}
