/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package pe.edu.uni.fc.cc.digitalsignature;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import static pe.edu.uni.fc.cc.common.Constans.RSA_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constans.RSA_KEY_SIZE_2048;
import static pe.edu.uni.fc.cc.common.Constans.SHA_256_ALGORITHM;

/**
 *
 * @author mcg
 */
public class ProtocolDigitalSignature {

    public static void main(String[] args) {
        System.out.println("Digital Signature !!!");
       
        
        try {
            String message="Hola soy cristian";
            //hash del mensaje
            MessageDigest md=MessageDigest.getInstance(SHA_256_ALGORITHM);
            md.update(message.getBytes());
            byte[] messageHash=md.digest();
            //generacion de llave rsa
            KeyPairGenerator kp = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            kp.initialize(RSA_KEY_SIZE_2048);
            KeyPair userKeyPair=kp.genKeyPair();
            //clase para manejar llave rsa
            RSAPrivateKey privateKey=(RSAPrivateKey) userKeyPair.getPrivate();
            RSAPublicKey publicKey=(RSAPublicKey) userKeyPair.getPublic();
            //obtener (d,n) y meessage biginteger
            BigInteger d=privateKey.getPrivateExponent();
            BigInteger n=privateKey.getModulus();
            BigInteger messagebig=new BigInteger(1,messageHash);
            //obtener firma
            BigInteger signature=messagebig.modPow(d, n);
            System.out.println("Mensaje originalr: "+ message);
            System.out.println("firma digital: "+ signature.toString(16));
            //obtener validacion 3 pasos
            //paso1 newdigest
            byte[] newdigest=md.digest(message.getBytes());
            BigInteger newdigestbig=new BigInteger(1,newdigest);
            System.out.println("Nuevo Hash: "+ newdigestbig.toString(16));
            //paso2 validation de firma
            BigInteger e=publicKey.getPublicExponent();
            BigInteger validation=signature.modPow(e, n);
            System.out.println("validacion: "+ validation.toString(16));
           
            //paso3 test validation
            boolean verified=newdigestbig.equals(validation);
            System.out.println("Firma validada: "+ verified);
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(ProtocolDigitalSignature.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        
        //64carcteres hexadecimalees ,2 caracteres valen un byte ,
        //osea 32 bytes , multiplicado por 8bits por byte , tenemos 256bits de hash
        
        
    }
}
