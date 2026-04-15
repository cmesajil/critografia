/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.common;

import java.security.SecureRandom;
import java.util.HexFormat;


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
}
