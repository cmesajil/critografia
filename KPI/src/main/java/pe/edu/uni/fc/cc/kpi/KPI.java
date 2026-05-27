/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package pe.edu.uni.fc.cc.kpi;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import static pe.edu.uni.fc.cc.common.Constans.BCFIPS_PROVIDER;
import static pe.edu.uni.fc.cc.common.Constans.RSA_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constans.RSA_KEY_SIZE_2048;
import static pe.edu.uni.fc.cc.common.Constans.RSA_SIGN_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constans.USER_CD_FILENAME;

/**
 *
 * @author mcg
 */
public class KPI {

    public static void main(String[] args) {
        System.out.println("PKI!");
        //agregando el proveedor criptografico
        Security.addProvider(new BouncyCastleFipsProvider());
        try {
            
            //generar llaver
            KeyPairGenerator kpg=KeyPairGenerator.getInstance(RSA_ALGORITHM);
            kpg.initialize(RSA_KEY_SIZE_2048);
            KeyPair userKeyPair=kpg.genKeyPair();
            //Elaborar el DN del subject del usuario
            String user_dn="CN=Ronald Martinez, OU=Facultad de Ciencias , O=UNI, C=FC";
            X500Name subjectDN = new X500Name(user_dn);
            //generacion de CSR
            JcaPKCS10CertificationRequestBuilder csrBuilder= new JcaPKCS10CertificationRequestBuilder(subjectDN,userKeyPair.getPublic()); 
            ContentSigner userSigner=new JcaContentSignerBuilder(RSA_SIGN_ALGORITHM).build(userKeyPair.getPrivate());
            PKCS10CertificationRequest csr=csrBuilder.build(userSigner);
            System.out.println("CSR generated" + csr.getSubject().toString());
            //En la Autoridad de Certificacion CA se recibe el CSR, se valida y se emite el CD
            //simulando CA
            KeyPair caKeyPair=kpg.genKeyPair();
            String ca_dn="CN= UNI root, O= UNI , C=FC";
            X500Name issuerDN = new X500Name(ca_dn);
            BigInteger serialNumber=BigInteger.valueOf(System.currentTimeMillis());
            Date startDate=new Date();
            Date endDate =new Date((long) (System.currentTimeMillis()+(365D*24*00*00*1000)));
            //Obteniendo la llave publica desde el CSN
            JcaPKCS10CertificationRequest jcaCsr= new JcaPKCS10CertificationRequest(csr).setProvider(BCFIPS_PROVIDER);
            PublicKey userPublicKey=jcaCsr.getPublicKey();
            //construir el formato x.509v3
            X509v3CertificateBuilder crtBuilder= new JcaX509v3CertificateBuilder(issuerDN,serialNumber,startDate,endDate,csr.getSubject(),userPublicKey);
            //firmar el CD utilizando la llave privada de CA
            ContentSigner csSigner=new JcaContentSignerBuilder(RSA_SIGN_ALGORITHM).build(caKeyPair.getPrivate());
            //Guardando el CD en:
            // Generar el certificado X.509 firmado
            X509CertificateHolder certHolder = crtBuilder.build(csSigner);
            //convertir al estandar JAVA
            X509Certificate userDC =new JcaX509CertificateConverter().setProvider(BCFIPS_PROVIDER).getCertificate(certHolder);
            System.out.println("Firmar: "+ userDC.getIssuerX500Principal());
            System.out.println("Subject: "+ userDC.getSubjectX500Principal());
            try {
                //guardar el CD en archivo:
                FileOutputStream fos=new FileOutputStream(USER_CD_FILENAME);
                fos.write(userDC.getEncoded());
                System.out.println("Archivo Almacenado: "+ USER_CD_FILENAME);
                
        } catch (FileNotFoundException ex) {
            System.getLogger(KPI.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }   catch (IOException ex) {
                System.getLogger(KPI.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            }
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(KPI.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (OperatorCreationException ex) {
            System.getLogger(KPI.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (InvalidKeyException ex) {
            System.getLogger(KPI.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (CertificateException ex) {
            System.getLogger(KPI.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
    }
}
