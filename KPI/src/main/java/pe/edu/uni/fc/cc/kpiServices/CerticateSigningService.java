/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.kpiServices;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import static pe.edu.uni.fc.cc.common.Constans.BCFIPS_PROVIDER;
import static pe.edu.uni.fc.cc.common.Constans.RSA_SIGN_ALGORITHM;

/**
 *
 * @author mcg
 */
public class CerticateSigningService {
    public X509Certificate signCsr(PKCS10CertificationRequest csr,KeyStoreStorageService.Credential caCredential,int validityDays) throws CertificateException{
        X509Certificate cer=null;
        JcaPKCS10CertificationRequest jcaCsr=new JcaPKCS10CertificationRequest(csr).setProvider(BCFIPS_PROVIDER);
        
        try {
            PublicKey userPublicKey = jcaCsr.getPublicKey();
            X500Name issuerDN = X500Name.getInstance(caCredential.getCer().getSubjectX500Principal().getEncoded());
            BigInteger serialNumber=BigInteger.valueOf(System.currentTimeMillis());
            Date startDate=new Date();
            Date endDate =new Date((long) (System.currentTimeMillis()+(validityDays*24*00*00*1000)));
            X509v3CertificateBuilder cerBuilder=new JcaX509v3CertificateBuilder(
                    issuerDN,
                    serialNumber,
                    startDate,endDate,
                    csr.getSubject(), //no esl o mismo que jcaCsr.getSubject()?
                    userPublicKey);
            ContentSigner cerSigner = new JcaContentSignerBuilder(RSA_SIGN_ALGORITHM)
                    .setProvider(BCFIPS_PROVIDER)
                    .build(caCredential.getPrivateKey());
            X509CertificateHolder cerHolder=cerBuilder.build(cerSigner);
            cer=new JcaX509CertificateConverter()
                    .setProvider(BCFIPS_PROVIDER)
                    .getCertificate(cerHolder);
            
        } catch (OperatorCreationException ex) {
            System.getLogger(CerticateSigningService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }catch (InvalidKeyException ex) {
            System.getLogger(CerticateSigningService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(CerticateSigningService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        
        return cer;
    }
}
