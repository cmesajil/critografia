/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.tls;

import java.net.Socket;

/**
 *
 * @author mcg
 */
public class ClientHandler implements Runnable{
    Socket clientSocket;
    
    public ClientHandler(Socket clientSocket){
        this.clientSocket=clientSocket;
    }

    @Override
    public void run() { 
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }
    
}
