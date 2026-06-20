/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.tls;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Scanner;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import static pe.edu.uni.fc.cc.common.Constans.CONTAINER_PASSWORD;
import static pe.edu.uni.fc.cc.common.Constans.PKCS12_KEYSTORE_TYPE;
import static pe.edu.uni.fc.cc.common.Constans.TLS_CONTEXT;
import static pe.edu.uni.fc.cc.common.Constans.TRUST_ROOT_CONTAINER_FILENAME;

/**
 *
 * @author mcg
 */
public class ClientTLS {
    public static void main(String[] args) {
        System.setOut(new PrintStream(System.out,true,StandardCharsets.UTF_8));
        String host="localhost";
        int port=8888;
        String PKCS12TrustContairnerPath=TRUST_ROOT_CONTAINER_FILENAME;
        char[] passwordPKCS12=CONTAINER_PASSWORD.toCharArray();
        
        try {
            KeyStore ks=KeyStore.getInstance(PKCS12_KEYSTORE_TYPE);
            try(FileInputStream fis=new FileInputStream(PKCS12TrustContairnerPath)){
                ks.load(fis,passwordPKCS12);
                //confianza
                TrustManagerFactory tmf=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(ks);
                //contexto
                SSLContext sslContext=SSLContext.getInstance(TLS_CONTEXT);
                sslContext.init(null, tmf.getTrustManagers(), null);
                //Capa de abstraccion de red
                SSLSocketFactory ssf=sslContext.getSocketFactory();
                
                //Captura de datos por consola
                Scanner sc=new Scanner(System.in);
                System.out.println("[Cliente] Ingresa el texto a enviar(de manera segura) al servidor");
                String mensajeToBeSent = sc.nextLine();
                
                //conectar al servidor
                //capa de transporte seguro
                try(
                    SSLSocket socket=(SSLSocket) ssf.createSocket(host,port);
                    BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                    PrintWriter output=new PrintWriter(socket.getOutputStream(), true);
                ){
                        //establecer la version
                        socket.setEnabledProtocols(new String[] {TLS_CONTEXT} ); //es para el socket , no para el contexto
                        //handshake
                        System.out.println("[Cliente] Ejecutando handshake TLS...");
                        socket.startHandshake();
                        System.out.println("[Cliente] Handshake ejecutado satisfactoriamente");
                        System.out.println("[Hilo Servidor] Protocolo Establecido: " + socket.getSession().getProtocol());
                        //  enviamos el texto capturado
                        output.println(mensajeToBeSent);
                        System.out.println("[Cliente] Mensaje enviado");
                        //Esperamos la respuesta
                        String response = input.readLine();
                        if (response == null || response.isBlank()) {
                            System.out.println("[Cliente] El servidor no proceso el texto enviado");
                        } else{
                            System.out.println("[Cliente] respuesta descifrada desde el servidor: "+ response); //saliendo del socket que estaba cifrado
                        }
                }
                
            } catch (IOException ex) {
                System.getLogger(ClientTLS.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            } catch (NoSuchAlgorithmException ex) {
                System.getLogger(ClientTLS.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            } catch (CertificateException ex) {
                System.getLogger(ClientTLS.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            } catch (KeyManagementException ex) {
                System.getLogger(ClientTLS.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            }
        } catch (KeyStoreException ex) {
            System.getLogger(ClientTLS.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        
    }
}
