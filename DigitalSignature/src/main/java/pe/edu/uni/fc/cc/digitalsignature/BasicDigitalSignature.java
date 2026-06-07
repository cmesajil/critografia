/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package pe.edu.uni.fc.cc.digitalsignature;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import static pe.edu.uni.fc.cc.common.Constans.RSA_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constans.RSA_KEY_SIZE_2048;

/**
 *
 * @author mcg
 */
public class BasicDigitalSignature {

    public static void main(String[] args) {
        System.out.println("Digital Signature !!!");
       
        
        try {
            String message="Hola soy cristian";
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
            BigInteger messagebig=new BigInteger(1,message.getBytes());
            //obtener firma
            BigInteger signature=messagebig.modPow(d, n);
            System.out.println("Mensaje big integer: "+ messagebig.toString(16));
            System.out.println("firma digital: "+ signature.toString(16));
            //obtener validacion
            BigInteger e=publicKey.getPublicExponent();
            BigInteger validation=signature.modPow(e, n);
            System.out.println("validacion: "+ validation.toString(16));
            
            //test
            boolean verified=messagebig.equals(validation);
            System.out.println("Firma validada: "+ verified);
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(BasicDigitalSignature.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        
       
        
        
    }
}
