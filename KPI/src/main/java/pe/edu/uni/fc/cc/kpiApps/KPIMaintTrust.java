/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.kpiApps;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import static pe.edu.uni.fc.cc.common.Constans.CONTAINER_PASSWORD;
import static pe.edu.uni.fc.cc.common.Constans.ROOT_CONTAINER_FILENAME;
import static pe.edu.uni.fc.cc.common.Constans.TRUST_ROOT_CONTAINER_ALIAS;
import static pe.edu.uni.fc.cc.common.Constans.TRUST_ROOT_CONTAINER_FILENAME;
import pe.edu.uni.fc.cc.kpiServices.CertificationAuthorityGenerationService;
import pe.edu.uni.fc.cc.kpiServices.KeyStoreStorageService;

/**
 *
 * @author mcg
 */
public class KPIMaintTrust {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleFipsProvider());
    
        //CertificationAuthorityGenerationService
        //KeyStoreStorageService
        CertificationAuthorityGenerationService AutoCerService=new CertificationAuthorityGenerationService();
        KeyStoreStorageService ksService=new KeyStoreStorageService();
        
        KeyPair kp=AutoCerService.generateKeyPair();
        String ca_dn="CN= UNI root , O=UNI ,C=FC ";
        
        X509Certificate certificado=AutoCerService.createSelfSignedCertificate(kp, ca_dn, 25);
        ksService.saveTrustPKCS12File(
                TRUST_ROOT_CONTAINER_FILENAME,
                CONTAINER_PASSWORD,
                TRUST_ROOT_CONTAINER_ALIAS, 
                certificado);
        ksService.saveToPublicPKCS12File(
                ROOT_CONTAINER_FILENAME, 
                CONTAINER_PASSWORD, 
                TRUST_ROOT_CONTAINER_ALIAS,
                kp.getPrivate(), 
                certificado);
        
    } 
    
}
