/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.kpiServices;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import static pe.edu.uni.fc.cc.common.Constans.BCFIPS_PROVIDER;
import static pe.edu.uni.fc.cc.common.Constans.PKCS12_KEYSTORE_TYPE;

/**
 *
 * @author mcg
 */
public class KeyStoreStorageService {
    public void saveToPublicPKCS12File(String filePath,String password,String alias,PrivateKey privatekey,X509Certificate certificate){
        KeyStore ks;
        try {
            ks = KeyStore.getInstance(PKCS12_KEYSTORE_TYPE,BCFIPS_PROVIDER);
            ks.load(null,null);
            X509Certificate[] chain=new X509Certificate[]{certificate};
            ks.setKeyEntry(alias, privatekey, password.toCharArray(), chain);
            try(FileOutputStream fos=new FileOutputStream(filePath)){
                ks.store(fos,password.toCharArray());
            };
            
        } catch (KeyStoreException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchProviderException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (IOException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (CertificateException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }

    }  
    
    public void saveTrustPKCS12File(String filePath,String password,String alias,X509Certificate certificate){
        try {
            KeyStore ks=KeyStore.getInstance(PKCS12_KEYSTORE_TYPE);
            ks.load(null,null);
            ks.setCertificateEntry(alias, certificate);
            
            try (FileOutputStream fos=new FileOutputStream(filePath)){
                ks.store(fos,password.toCharArray());
                System.out.println("Truststore generado");
                System.out.println("Entradas: " + ks.size());
            };
            
            
        } catch (KeyStoreException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (IOException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (CertificateException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
    
    }
    
    public Credential loadKeyMaterialFromPKCS12File(String filePath,String password,String alias){
        Credential credential=null;
        try {
            KeyStore ks=KeyStore.getInstance(PKCS12_KEYSTORE_TYPE,BCFIPS_PROVIDER);
            try(FileInputStream fis=new FileInputStream(filePath)){
                ks.load(fis,password.toCharArray());
            }
            PrivateKey privateKey=(PrivateKey)ks.getKey(alias, password.toCharArray());
            X509Certificate certificate=(X509Certificate)ks.getCertificate(alias);
            credential=new Credential(privateKey,certificate);
        } catch (IOException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (CertificateException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (KeyStoreException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchProviderException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (UnrecoverableKeyException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        
        return credential; 
    }
    
    public static class Credential{
        private final X509Certificate cer;
        private final PrivateKey privateKey;
        
        public Credential(PrivateKey privateKey, X509Certificate cer) {
            this.cer=cer;
            this.privateKey=privateKey;
        }
        public X509Certificate getCer() {
            return cer;
        } 
        public PrivateKey getPrivateKey() {
            return privateKey;
        }
        
    }
            
}
