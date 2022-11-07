package client;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.security.*;
import java.net.*;
import server.SecurityFunctions;

public class ClienteMain {

    private static String host = "localhost";
    private static int puerto = 2017;

    private static Socket s;
    
    private static SecurityFunctions f;
    private static String dlg;

    public static void main(String[] args) throws IOException {
        s = new Socket(host, puerto);
        DataOutputStream os = new DataOutputStream(s.getOutputStream());
        System.out.println("Connection socket created on port: "+puerto);
        f = new SecurityFunctions();
        String xd = "1";
        dlg = new String("concurrent server " + 0 + ": ");
        PrivateKey privadaServidor = f.read_kmin("../../datos_asim_srv.pri",dlg);
		PublicKey publicaServidor = f.read_kplus("../../datos_asim_srv.pub",dlg);
		try {
			byte[] cifrado = f.aenc(publicaServidor, xd);
			String recuperado1 = f.adec(cifrado, privadaServidor);
			int alo = Integer.parseInt(recuperado1);
			alo++;
			byte[] cifrado2 = f.aenc(publicaServidor, alo+"");
			
			String recuperado = f.adec(cifrado2, privadaServidor);
			//System.out.println(recuperado);
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        BufferedReader dc = new BufferedReader(new InputStreamReader(s.getInputStream()));
        
        //String linea = dc.readLine();
        //System.out.println(linea);
        //for(int i=0;i<1000;i++) {
        os.writeBytes("Hola si buenas");
        //}
        
        s.close();
        
    
    }
}
