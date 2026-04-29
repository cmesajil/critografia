/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.common;

/**
 *
 * @author mcg
 */
public class Constans {
    public static final int ALPHABET_SET_SIZE=26;
    public static final String AES_ALGORITHM="AES";
    public static final String SHA_256_ALGORITHM="SHA-256";
    
    public static final String PBKDF2_WITH_HMAC_SHA_256_ALGORITHM="PBKDF2WithHmacSHA256";
    public static final String TRANSFORMATION_AES_CBC="AES/CBC/PKCS5Padding";
    public static final String TRANSFORMATION_AES_GCM="AES/GCM/NoPadding";
   
    public static final int AES_CBC_IV_LENGTH=16;
    public static final int AES_GCM_IV_LENGTH=12;
    
    public static final int TAG_LENGTH=128; //bits
    
    
    // container
    public static final String PKCS12_KEYSTORE_TYPE="PKCS12"; //JKS otra opcion , es modificable
    public static final String CONTAINER_FILENAME="/home/mcg/contenedor.p12"; //volatil
    public static final String CONTAINER_PASSWORD="container-password";
    
    
    public static final String RSA_ALGORITHM="RSA";
    public static final int RSA_KEY_SIZE_2048=2048;
    //llave
    //se necesita AES
    public static final String AES_ALIAS="aes_key"; //ID de llave
    public static final String KEY_USE_PASSWORD="key-use-password";  //activacion
    public static final int AES_KEY_SIZE_256=256;
}
