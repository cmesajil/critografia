package pe.edu.uni.fc.cc.tls;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

public class ClientHandler implements Runnable {
    private final Socket socket;

    // El constructor solo recibe y almacena la referencia del socket
    public ClientHandler(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() { 
        // TRUCO: Declaramos e inicializamos todo dentro del Try-with-resources separado por ';'
        try (
            Socket s = this.socket; // Al meterlo aquí, también se cerrará el socket al final
            BufferedReader input = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
            PrintWriter output = new PrintWriter(s.getOutputStream(), true)
        ) {
            
            // Si estás usando SSL/TLS, es buena idea castearlo para obtener la sesión segura
            if (s instanceof SSLSocket) {
                SSLSession session = ((SSLSocket) s).getSession();
                System.out.println("[Hilo Servidor] Protocolo Establecido: " + session.getProtocol());
                System.out.println("[Hilo Servidor] Suite de cifrado Establecido: " + session.getCipherSuite());
            }
            
            // 1. LEER EL PRIMER MENSAJE
            String mensajeIn = input.readLine();
            if (mensajeIn == null || mensajeIn.isBlank()) {
                System.out.println("[Hilo Servidor] El mensaje recibido es inválido! No es procesado");
            } else {
                System.out.println("[Hilo Servidor] Mensaje seguro recibido desde el cliente: " + mensajeIn);
                String mensajeOut = mensajeIn.toUpperCase(); // Ojo: habías puesto 'mensajeout' en minúscula abajo
                System.out.println("[Hilo Servidor] Mensaje fue procesado Exitosamente!");
                
                output.println(mensajeOut); // Usamos println para que mande el salto de línea '\n'
                System.out.println("[Hilo Servidor] Respuesta cifrada al cliente!");
            }
            
            System.out.println("[Hilo Servidor] Conexión Segura con Cliente finalizada!");
            
        } catch (IOException ex) {
            System.getLogger(ClientHandler.class.getName()).log(System.Logger.Level.ERROR, "Error en la sesión del cliente", ex);
        }
        // Nota: Quité el catch de ClassNotFoundException porque ya no usas ObjectInputStream
    }
}