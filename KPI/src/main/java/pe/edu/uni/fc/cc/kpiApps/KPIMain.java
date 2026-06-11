/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.kpiApps;

import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import static pe.edu.uni.fc.cc.common.Constans.CONTAINER_PASSWORD;
import static pe.edu.uni.fc.cc.common.Constans.ROOT_CONTAINER_ALIAS;
import static pe.edu.uni.fc.cc.common.Constans.ROOT_CONTAINER_FILENAME;
import static pe.edu.uni.fc.cc.common.Constans.USER_CONTAINER_ALIAS;
import static pe.edu.uni.fc.cc.common.Constans.USER_CONTAINER_FILENAME;
import pe.edu.uni.fc.cc.kpiServices.CSRGeneratorService;
import pe.edu.uni.fc.cc.kpiServices.CerticateSigningService;
import pe.edu.uni.fc.cc.kpiServices.CertificationAuthorityGenerationService;
import pe.edu.uni.fc.cc.kpiServices.KeyStoreStorageService;

/**
 *
 * @author mcg
 */
public class KPIMain {
    public static void main(String[] args) {
        //Security.addProvider(new BouncyCastleFipsProvider());
        Security.addProvider(new BouncyCastleFipsProvider());
        
        CSRGeneratorService csrService=new CSRGeneratorService();
        CertificationAuthorityGenerationService caGenService=new CertificationAuthorityGenerationService();
        KeyStoreStorageService ksService=new KeyStoreStorageService();
        CerticateSigningService cerSignService=new CerticateSigningService();
        
        
        String user_dn="CN=Ronald Martinez, OU=Facultad de Ciencias , O=UNI, C=FC";
  
        try {
            KeyPair userKeyPair = csrService.generateKeyPair();
            PKCS10CertificationRequest csr=csrService.createCSR(user_dn, userKeyPair);
            String ca_dn="CN= UNI root, O= UNI , C=FC";
            KeyPair caKeyPair=caGenService.generateKeyPair();
            X509Certificate caCer=caGenService.createSelfSignedCertificate(caKeyPair, ca_dn, 25);
            ksService.saveToPublicPKCS12File(
                    ROOT_CONTAINER_FILENAME,
                    CONTAINER_PASSWORD,
                    ROOT_CONTAINER_ALIAS, 
                    caKeyPair.getPrivate(), 
                    caCer);
            KeyStoreStorageService.Credential caCredential=ksService.loadKeyMaterialFromPKCS12File(ROOT_CONTAINER_FILENAME,CONTAINER_PASSWORD, ROOT_CONTAINER_ALIAS);
            X509Certificate certificate=cerSignService.signCsr(csr,caCredential,1);
            ksService.saveToPublicPKCS12File(
                    USER_CONTAINER_FILENAME,
                    CONTAINER_PASSWORD,
                    USER_CONTAINER_ALIAS, 
                    userKeyPair.getPrivate(), 
                    certificate);
        } catch (NoSuchProviderException ex) {
            System.getLogger(KPIMain.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (CertificateException ex) {
            System.getLogger(KPIMain.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        
        
    }
}
