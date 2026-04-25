/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package pe.edu.uni.fc.cc.container;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import static pe.edu.uni.fc.cc.common.Constans.AES_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constans.AES_ALIAS;
import static pe.edu.uni.fc.cc.common.Constans.AES_KEY_SIZE_256;
import static pe.edu.uni.fc.cc.common.Constans.CONTAINER_FILENAME;
import static pe.edu.uni.fc.cc.common.Constans.CONTAINER_PASSWORD;
import static pe.edu.uni.fc.cc.common.Constans.KEY_USE_PASSWORD;
import static pe.edu.uni.fc.cc.common.Constans.PKCS12_KEYSTORE_TYPE;

/**
 *
 * @author mcg
 */
public class PKCS12Container {

    public static void main(String[] args) throws KeyStoreException {
        try {
            System.out.println("PKCS12Container !!!");
            //Generar llave AES
            KeyGenerator keygen=KeyGenerator.getInstance(AES_ALGORITHM);
            keygen.init(AES_KEY_SIZE_256);
            SecretKey secretKeyOriginal=keygen.generateKey();
            
            //crear contenedor 
            KeyStore ks=KeyStore.getInstance(PKCS12_KEYSTORE_TYPE);
            ks.load(null,CONTAINER_PASSWORD.toCharArray());
            
            //preparando la llave para su almacenamiento
            KeyStore.SecretKeyEntry entry=new KeyStore.SecretKeyEntry(secretKeyOriginal);
            KeyStore.PasswordProtection protection=new KeyStore.PasswordProtection(KEY_USE_PASSWORD.toCharArray());
            //guardando en el almacen
            ks.setEntry(AES_ALIAS, entry, protection);
            //guardar el contenedor en el archivo
            FileOutputStream ios=new FileOutputStream(CONTAINER_FILENAME);
            ks.store(ios,CONTAINER_PASSWORD.toCharArray());
            
            System.out.println("DONE");
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(PKCS12Container.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (IOException ex) {
            System.getLogger(PKCS12Container.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (CertificateException ex) {
            System.getLogger(PKCS12Container.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
    }
}
