/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.kpiServices;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import static pe.edu.uni.fc.cc.common.Constans.BCFIPS_PROVIDER;
import static pe.edu.uni.fc.cc.common.Constans.RSA_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constans.RSA_KEY_SIZE_2048;
import static pe.edu.uni.fc.cc.common.Constans.RSA_SIGN_ALGORITHM;

/**
 *
 * @author mcg
 */
public class CertificationAuthorityGenerationService {
    public X509Certificate createSelfSignedCertificate(KeyPair kp,String issuerDN,int validityYears){
        X509Certificate certificate=null;
        PublicKey publicKey=kp.getPublic();
        PrivateKey privateKey=kp.getPrivate();
        X500Name caDn=new X500Name(issuerDN);
        BigInteger serialNumber=BigInteger.valueOf(System.currentTimeMillis());
        Date startDate=new Date();
        Date endDate=new Date((long) (System.currentTimeMillis()+(365L*validityYears*24*00*00*1000)));
        X509v3CertificateBuilder cerBuilder=new JcaX509v3CertificateBuilder(
                caDn,
                serialNumber,
                startDate,
                endDate,
                caDn,
                publicKey
        );
        try {
            ContentSigner cerSigner=new JcaContentSignerBuilder(RSA_SIGN_ALGORITHM)
                    .setProvider(BCFIPS_PROVIDER)
                    .build(privateKey);
            X509CertificateHolder cerHolder=cerBuilder.build(cerSigner);
            certificate=new JcaX509CertificateConverter()
                    .setProvider(BCFIPS_PROVIDER)
                    .getCertificate(cerHolder);
        } catch (OperatorCreationException ex) {
            System.getLogger(CertificationAuthorityGenerationService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (CertificateException ex) {
            System.getLogger(CertificationAuthorityGenerationService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        return certificate;
    }
    public KeyPair generateKeyPair(){
        KeyPair kp=null;
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            kpg.initialize(RSA_KEY_SIZE_2048);
            kp=kpg.genKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(CertificationAuthorityGenerationService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        return kp;
    }
}
