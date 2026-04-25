/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.App;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import javax.crypto.SecretKey;
import static pe.edu.uni.fc.cc.common.Constans.AES_ALIAS;
import static pe.edu.uni.fc.cc.common.Constans.AES_GCM_IV_LENGTH;
import static pe.edu.uni.fc.cc.common.Constans.CONTAINER_FILENAME;
import static pe.edu.uni.fc.cc.common.Constans.CONTAINER_PASSWORD;
import static pe.edu.uni.fc.cc.common.Constans.KEY_USE_PASSWORD;
import static pe.edu.uni.fc.cc.common.Constans.PKCS12_KEYSTORE_TYPE;
import pe.edu.uni.fc.cc.common.Utils;
import pe.edu.uni.fc.cc.service.AESGCMCipherService;

/**
 *keystore explorer
 * @author mcg
 */
public class MainPKCS12AESGCMCipher {
    public static void main(String[] args) {
        System.out.println("MainPKCS12AESGCMCipher !!!");
        String msg="This is a message Ciphered with a AES key embebed into a PKCS12 container";
        byte[] aesKeBytes=null;
        
        try {
            //cargar el contenedor
            KeyStore ks=KeyStore.getInstance(PKCS12_KEYSTORE_TYPE);
            FileInputStream fis=new FileInputStream(CONTAINER_FILENAME);
            
            //abrir el contenedor, configurando la llamanda a la caja fuerte secretKeyEntry
            ks.load(fis,CONTAINER_PASSWORD.toCharArray());
            KeyStore.PasswordProtection protection=new KeyStore.PasswordProtection(KEY_USE_PASSWORD.toCharArray());
            KeyStore.SecretKeyEntry entry=(KeyStore.SecretKeyEntry)ks.getEntry(AES_ALIAS, protection);
            //verificar la cajita si es vacia
            if(entry==null){
                System.out.println("No se encontro la llave el alias");
                return;
            }
            //extraer la llave
            SecretKey sk=entry.getSecretKey();
            
            //obtener el hash de la llave para verificar que es la misma llave ,2 veces para confirmar
            System.out.println("hash de la llave AES: "+ Utils.getKeyHash(sk));
            
            aesKeBytes=sk.getEncoded();
            AESGCMCipherService aes_gcm=new AESGCMCipherService(aesKeBytes);
        
            byte[] iv=Utils.generateIV(AES_GCM_IV_LENGTH);
            byte[] aad="Header".getBytes();

            String encrypted = aes_gcm.encrypt(msg,iv,aad);
            String decrypted = aes_gcm.decrypt(encrypted,aad);

            System.out.println("original "+msg);
            System.out.println("Encrypted "+encrypted);
            System.out.println("Decrypt "+decrypted);
                
        } catch (KeyStoreException ex) {
            System.getLogger(MainPKCS12AESGCMCipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (FileNotFoundException ex) {
            System.getLogger(MainPKCS12AESGCMCipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (IOException ex) {
            System.getLogger(MainPKCS12AESGCMCipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(MainPKCS12AESGCMCipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (CertificateException ex) {
            System.getLogger(MainPKCS12AESGCMCipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (UnrecoverableEntryException ex) {
            System.getLogger(MainPKCS12AESGCMCipher.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        
        
    }
}
