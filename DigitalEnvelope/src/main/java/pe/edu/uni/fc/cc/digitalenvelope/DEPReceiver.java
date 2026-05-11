/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.digitalenvelope;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import static pe.edu.uni.fc.cc.common.Constans.AES_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constans.AES_GCM_AAD;
import static pe.edu.uni.fc.cc.common.Constans.AES_GCM_IV_LENGTH;
import pe.edu.uni.fc.cc.common.Utils;
import pe.edu.uni.fc.cc.service.AESGCMCipherService;
import pe.edu.uni.fc.cc.services.RSACipherService;

/**
 *
 * @author mcg
 */
public class DEPReceiver {
    
    public String processShippedPayload(byte[] cipheredMessage,byte[] digitalEnvelope,PrivateKey priKey){
    
        RSACipherService rsa_cipher=new RSACipherService(priKey);
        byte[] rawAesKey= rsa_cipher.decrypt(digitalEnvelope);
        SecretKey aesKey=new SecretKeySpec(rawAesKey,AES_ALGORITHM);

        AESGCMCipherService aes_gcm=new AESGCMCipherService(aesKey.getEncoded());
        byte[] decryptedMessage=aes_gcm.decrypt(cipheredMessage,AES_GCM_AAD);
        String result =new String(decryptedMessage,StandardCharsets.UTF_8);

        System.out.println("Receiver: Mensaje descifrado recuperado");   
        return result;    
    }
    
}
