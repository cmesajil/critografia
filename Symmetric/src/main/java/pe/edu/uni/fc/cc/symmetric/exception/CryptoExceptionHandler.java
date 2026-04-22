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
        if(e instanceof InvalidKeyException  || e instanceof InvalidAlgorithmParameterException){
            return new CryptoKeyException("Error en la llave o parametro",e);
        }
        if(e instanceof InvalidKeyException  || e instanceof InvalidAlgorithmParameterException){
            return new CryptoOperationException("Error en la llave o parametro",e);
        }
    return new CryptoException("Error  criptografica general",e);
    }
}
