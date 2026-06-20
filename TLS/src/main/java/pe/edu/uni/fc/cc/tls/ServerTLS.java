/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package pe.edu.uni.fc.cc.tls;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import static pe.edu.uni.fc.cc.common.Constans.CONTAINER_PASSWORD;
import static pe.edu.uni.fc.cc.common.Constans.PKCS12_KEYSTORE_TYPE;
import static pe.edu.uni.fc.cc.common.Constans.ROOT_CONTAINER_FILENAME;
import static pe.edu.uni.fc.cc.common.Constans.TLS_CONTEXT;

/**
 *
 * @author mcg
 */
public class ServerTLS {

    public static void main(String[] args) {
        System.setOut(new PrintStream(System.out,true,StandardCharsets.UTF_8));
        System.out.println("Transport Layer Security!");
        int port=8888;
        String PKC12Path=ROOT_CONTAINER_FILENAME;
        char[] passwordPKCS12=CONTAINER_PASSWORD.toCharArray();
        
        try {
            // 1. Cargar el contenedor PKCS12
            KeyStore ks=KeyStore.getInstance(PKCS12_KEYSTORE_TYPE);
            try(FileInputStream fis=new FileInputStream(PKC12Path)){
                ks.load(fis, passwordPKCS12);
                
                // 2. Inicializar el KeyManagerFactory con el KeyStore
                KeyManagerFactory kmf=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(ks, passwordPKCS12);
                
                // 3. Crear el contexto SSL/TLS (Usando TLS v1.3 que es el estándar actual)
                SSLContext sslContext=SSLContext.getInstance(TLS_CONTEXT);
                sslContext.init(kmf.getKeyManagers(),null, null);
                
                // 4. Crear el ServerSocket Seguro
                SSLServerSocketFactory ssf=sslContext.getServerSocketFactory();
                SSLServerSocket serverSocket=(SSLServerSocket) ssf.createServerSocket(port);
                
                serverSocket.setEnabledProtocols(new String[]{TLS_CONTEXT});
                System.out.println(
                "Servidor TLS de mensajería corriendo de forma segura en el puerto " +
                    port
                );
                //ClientHandler[] clientes;
                while(true){
                    // Espera a que un cliente se conecte por TLS
                    Socket clientSocket = serverSocket.accept();
                    
                    // Creamos el manejador pasándole el socket seguro
                    ClientHandler manejador=new ClientHandler(clientSocket);
                    
                    // Iniciamos el hilo para ese cliente
                    Thread hilo=new Thread(manejador);
                    hilo.run();
                }
                
            } catch (FileNotFoundException ex) {
                System.getLogger(ServerTLS.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            } catch (IOException ex) {
                System.getLogger(ServerTLS.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            } catch (NoSuchAlgorithmException ex) {
                System.getLogger(ServerTLS.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            } catch (CertificateException ex) {
                System.getLogger(ServerTLS.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            } catch (UnrecoverableKeyException ex) {
                System.getLogger(ServerTLS.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            } catch (KeyManagementException ex) {
                System.getLogger(ServerTLS.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            }
        } catch (KeyStoreException ex) {
            System.getLogger(ServerTLS.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        
       
        
    }
}
