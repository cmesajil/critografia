/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.Tests;

/**
 *
 * @author alumno
 */
public class AESGCMCipherServiceTest {
    
    @Test
    public void testEnctyptdecrypt(){
        byte[] key=new byte[16];
        byte[] iv=Utils.generateIV(AES_GCM_IV_LENGTH);
        //main 
        
        asserEquals(original , decypted);
    }
    
}
