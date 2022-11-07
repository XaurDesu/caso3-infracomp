package client;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
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
        PrintWriter ac = new PrintWriter(s.getOutputStream() , true);

        System.out.println("Connection socket created on port: "+puerto);
        f = new SecurityFunctions();
        String xd = "1";
        dlg = new String("concurrent server " + 0 + ": ");
        PublicKey publicaServidor = f.read_kplus("../../datos_asim_srv.pub",dlg);
//		try {
//			byte[] cifrado = f.aenc(publicaServidor, xd);
//			String recuperado1 = f.adec(cifrado, privadaServidor);
//			int alo = Integer.parseInt(recuperado1);
//			alo++;
//			byte[] cifrado2 = f.aenc(publicaServidor, alo+"");
//			
//			String recuperado = f.adec(cifrado2, privadaServidor);
//			//System.out.println(recuperado);
//			
//		} catch (Exception e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
        
        BufferedReader dc = new BufferedReader(new InputStreamReader(s.getInputStream()));
        ac.println("SECURE INIT");
        
        String g =dc.readLine();
        String p =dc.readLine();
        String g2x =dc.readLine();
        //System.out.println("Esto? "+ dc.readLine());
        String auth =dc.readLine();
        System.out.println(g2x);
        byte[] byte_authentication = str2byte(auth);
        try {
        	String msj = g+","+p+","+g2x;
			if(f.checkSignature(publicaServidor, byte_authentication, msj)) {
				System.out.println("Check correct");
				ac.println("OK");
			}
			else {
				System.out.println("Check incorrect");
				ac.println("ERROR");
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        
        //G2Y
        ac.println("23");
        //str_consulta
        ac.println("1");
        //str_mac
        ac.println("3");
        //str_iv1
        ac.println("4");
        
        System.out.println("Estado (?) "+ dc.readLine());
        System.out.println("m1 "+ dc.readLine());
        System.out.println("m2 "+ dc.readLine());
        System.out.println("str_iv2 "+ dc.readLine());
        
        ac.println("OK");
        
        
        
        
        s.close();
        
    
    }
    public static byte[] str2byte( String ss)
	{	
		// Encapsulamiento con hexadecimales
		byte[] ret = new byte[ss.length()/2];
		for (int i = 0 ; i < ret.length ; i++) {
			ret[i] = (byte) Integer.parseInt(ss.substring(i*2,(i+1)*2), 16);
		}
		return ret;
	}
}
