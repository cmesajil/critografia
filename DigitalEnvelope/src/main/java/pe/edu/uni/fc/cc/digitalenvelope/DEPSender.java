/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.digitalenvelope;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import static pe.edu.uni.fc.cc.common.Constans.AES_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constans.AES_GCM_AAD;
import static pe.edu.uni.fc.cc.common.Constans.AES_GCM_IV_LENGTH;
import static pe.edu.uni.fc.cc.common.Constans.AES_KEY_SIZE_256;
import pe.edu.uni.fc.cc.common.Utils;
import pe.edu.uni.fc.cc.service.AESGCMCipherService;
import pe.edu.uni.fc.cc.services.RSACipherService;

/**
 *
 * @author mcg
 */
public class DEPSender {
    private byte[] iv;
    private byte[] cipheredMessage;
    private byte[] digitalEnvelope;

    public byte[] getIv() {
        return iv;
    }

    public byte[] getCipheredMessage() {
        return cipheredMessage;
    }

    public byte[] getDigitalEnvelope() {
        return digitalEnvelope;
    }
    
    public void prepareForShipping(String message,PublicKey pubKey){
        
        try {
            KeyGenerator kg=KeyGenerator.getInstance(AES_ALGORITHM);
            kg.init(AES_KEY_SIZE_256);
            SecretKey aesKey=kg.generateKey();
            
            
            AESGCMCipherService aes_gcm=new AESGCMCipherService(aesKey.getEncoded());
            iv=Utils.generateIV(AES_GCM_IV_LENGTH);
      
            cipheredMessage= aes_gcm.encrypt(message.getBytes(),iv,AES_GCM_AAD);
            
            RSACipherService rsa_cipher=new RSACipherService(pubKey);
            digitalEnvelope= rsa_cipher.encrypt(aesKey.getEncoded());
            
            System.out.println("Sender: Mensaje cifrado y sobre digital sellado");
            
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(DEPSender.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        
    }
}
