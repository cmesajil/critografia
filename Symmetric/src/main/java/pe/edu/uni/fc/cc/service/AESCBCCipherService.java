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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import static pe.edu.uni.fc.cc.common.Constans.AES_CBC_IV_LENGTH;
import static pe.edu.uni.fc.cc.common.Constans.TRANSFORMATION_AES_CBC;
import pe.edu.uni.fc.cc.symmetric.AESCBCCipher;

/**
 *
 * @author mcg
 */
public class AESCBCCipherService {
    
    private final byte[] key;
    
    public AESCBCCipherService(byte[] key) {
        this.key=key;
    }
    
    
    public String encrypt(byte[] initVector,String PlainText){
        String result="";
        try {
           
            IvParameterSpec iv=new IvParameterSpec(initVector); //vector de inicializacion , contenido
            SecretKeySpec sKeySpec = new SecretKeySpec(key,"AES");  //en que tipo de algoritmo lo vas a utilizar?
            Cipher cipher= Cipher.getInstance(TRANSFORMATION_AES_CBC); //en que modo , cual es su IV , cual es su llave, instancia , modo de operacion(ECB CBC GCM) transformacion , tiene relleno
            cipher.init(Cipher.ENCRYPT_MODE,sKeySpec,iv);
            byte[] encrypted = cipher.doFinal(PlainText.getBytes(StandardCharsets.UTF_8)); //codificacion clasica UTF-8 
            
            //iv,ciphertext (cosa que manejas)
            byte[] combined=new byte[initVector.length+encrypted.length];
            System.arraycopy(initVector, 0,combined, 0, initVector.length);
            System.arraycopy(encrypted, 0,combined, initVector.length, encrypted.length);
            result =Base64.getEncoder().encodeToString(combined);
            
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
    
    /*mejora
    ByteBuffer bb = ByteBuffer.wrap(paqueteCompleto);

// Creamos los contenedores
byte[] extractedIv = new byte[16];
byte[] cipherText = new byte[48];

// El método .get() extrae bytes y mueve el puntero automáticamente
bb.get(extractedIv); 
bb.get(cipherText);
    */
    
    
    public String decrypt(String encryptedText){
        String result="";
        try {
            byte[] combined=Base64.getDecoder().decode(encryptedText);
            byte[] initVector=new byte[AES_CBC_IV_LENGTH];
            byte[] cipheredText=new byte[combined.length-initVector.length];
            System.arraycopy(combined, 0,initVector, 0, initVector.length);
            System.arraycopy(combined, initVector.length,cipheredText,0,cipheredText.length ); // que copias fuente, la fuente desde donde, a donde copias , desde que parte copias , a donde 
            
            
            IvParameterSpec iv=new IvParameterSpec(initVector); //vector de inicializacion , contenido
            SecretKeySpec sKeySpec = new SecretKeySpec(key,"AES");  //en que tipo de algoritmo lo vas a utilizar?
            Cipher cipher= Cipher.getInstance(TRANSFORMATION_AES_CBC); //en que modo , cual es su IV , cual es su llave, instancia , modo de operacion(ECB CBC GCM) transformacion , tiene relleno
            cipher.init(Cipher.DECRYPT_MODE,sKeySpec,iv);
            byte[] decrypted = cipher.doFinal(cipheredText); //codificacion clasica UTF-8 , falta add trhows
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
    
    

    
}
