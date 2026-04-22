/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.hashing;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import static pe.edu.uni.fc.cc.common.Constans.PBKDF2_WITH_HMAC_SHA_256_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constans.SHA_256_ALGORITHM;
import pe.edu.uni.fc.cc.common.Utils;

/**
 *
 * @author alumno
 */
public class HashingWithSalt {
    

    public static void main(String[] args) {
        
        try {
            System.out.println("HashingWithSalt!!!");
            final String password="12345";
            //SecureRandom r=new SecureRandom(); y se guarda en una database
            final String salt="user@example.com";
            final int iterations = 32; //baja entropia
            final int keySize = 512;
            
            PBEKeySpec keySpec=new PBEKeySpec(password.toCharArray(),salt.getBytes(),iterations,keySize);
            
            SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_WITH_HMAC_SHA_256_ALGORITHM);
            byte[] hashed =skf.generateSecret(keySpec).getEncoded();
            System.out.println("El valor SHA-256 con salt y con PBKDF es: "+ Utils.byteToHex(hashed));
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(HashingWithSalt.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (InvalidKeySpecException ex) {
            System.getLogger(HashingWithSalt.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
            
        
    }

}
