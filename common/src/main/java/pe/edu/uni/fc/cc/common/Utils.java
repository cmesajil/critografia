/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.common;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;
import javax.crypto.SecretKey;
import static pe.edu.uni.fc.cc.common.Constans.SHA_256_ALGORITHM;


/**
 *
 * @author mcg
 */
public class Utils {
    public static String byteToHex(byte[] bytes){
        return HexFormat.of().withUpperCase().withDelimiter(" ").formatHex(bytes);
    }
    
    public static byte[] generateIV(int lenghtinitVector){
        byte[] initVector = new byte[lenghtinitVector];
        SecureRandom sr=new SecureRandom();
        sr.nextBytes(initVector);
        return initVector;
    }
    
    public static String getKeyHash(SecretKey sk){
         byte[] hash=null;
        try {
            byte[] keyBytes =sk.getEncoded();
            MessageDigest md=MessageDigest.getInstance(SHA_256_ALGORITHM);
            hash=md.digest(keyBytes);
      
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(Utils.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        return byteToHex(hash);
    }
}
