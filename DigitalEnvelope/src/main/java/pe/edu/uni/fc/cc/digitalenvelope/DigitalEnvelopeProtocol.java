/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package pe.edu.uni.fc.cc.digitalenvelope;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import static pe.edu.uni.fc.cc.common.Constans.RSA_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constans.RSA_KEY_SIZE_2048;
import pe.edu.uni.fc.cc.common.Utils;

/**
 *
 * @author mcg
 */
public class DigitalEnvelopeProtocol {

    public static void main(String[] args) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            kpg.initialize(RSA_KEY_SIZE_2048);
            KeyPair kp=kpg.generateKeyPair();
            
            String secret_message="Este es un mensaje confidencial enviado desde el emisor al receptor";
            DEPSender sender=new DEPSender();
            sender.prepareForShipping(secret_message, kp.getPublic());
            System.out.println("Digital Envelope: "+  Utils.byteToHex(sender.getDigitalEnvelope()));
            System.out.println("Mensaje cifrado: "+  Utils.byteToHex(sender.getCipheredMessage()));
            
            
            DEPReceiver receiver=new DEPReceiver();
            String recovered_message=receiver.processShippedPayload(sender.getCipheredMessage(), sender.getDigitalEnvelope(), kp.getPrivate());
            System.out.println("Mensaje secreto: "+  secret_message);
            System.out.println("Mensaje recuperado: "+  recovered_message);
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(DigitalEnvelopeProtocol.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
    }
}
