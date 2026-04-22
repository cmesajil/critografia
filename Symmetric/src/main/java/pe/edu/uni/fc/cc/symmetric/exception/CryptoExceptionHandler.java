/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.symmetric.exception;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author alumno
 */
//direcciona el error hacia un lugar
public class CryptoExceptionHandler {
    
    public static RuntimeException handle(Exception e){
        if(e instanceof NoSuchAlgorithmException || e instanceof NoSuchPaddingException){
            return new CryptoConfigurationException("Error de configuracion criptografica",e);
        }
    return new CryptoException("Error  criptografica general",e);
    }
}
