package client;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.*;

import javax.crypto.SecretKey;

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
        dlg = new String("concurrent server " + 0 + ": ");
        PublicKey publicaServidor = f.read_kplus("../../datos_asim_srv.pub",dlg);

        BufferedReader dc = new BufferedReader(new InputStreamReader(s.getInputStream()));
        BufferedReader bf = new BufferedReader(new InputStreamReader(System.in));
        ac.println("SECURE INIT");
        
        String g =dc.readLine();
        String p =dc.readLine();
        String g2x =dc.readLine();
        //System.out.println("Esto? "+ dc.readLine());
        String auth =dc.readLine();
        //System.out.println(g2x);
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
        
        
        //Calcular G2Y = g*x mod p o es z = y*x mod p
        BigInteger g1 = new BigInteger(g);
        BigInteger p1 = new BigInteger(p);
        BigInteger g2x1 = new BigInteger(g2x);
        SecureRandom r = new SecureRandom();
        int x = Math.abs(r.nextInt());
		
        
        

		Long longx = Long.valueOf(x);
        BigInteger bix = BigInteger.valueOf(longx);
        BigInteger g2y = g1.modPow(bix, g2x1);
        ac.println(g2y);
        
      //calcular_llave_maestra
        BigInteger llave_maestra = calcular_llave_maestra(g2y,bix,p1);
        
        
     // generating symmetric key
        String str_llave = llave_maestra.toString();
        SecretKey sk_srv=null;
        SecretKey sk_mac=null;
     	try {
			sk_srv = f.csk1(str_llave);
			sk_mac = f.csk2(str_llave);
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
     	
     			
        //str_consulta
     	System.out.println("Ingrese el numero que desea modificar");
     	String entrada = bf.readLine();
        int valorConsulta=Integer.parseInt(entrada);
        try {
			byte[] cifrado = f.aenc(publicaServidor, valorConsulta+"");
			String valor = byte2str(cifrado);
			ac.println(valor);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        //str_mac
        byte[] hmacBytes = str2byte(valorConsulta+"");
        byte[] hmacReturn=null;
        try {
			hmacReturn = f.hmac(hmacBytes, sk_mac);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        String retHmacString = byte2str(hmacReturn);
        ac.println(retHmacString);
        //str_iv1
        byte[] iv1 = generateIvBytes();
    	String str_iv1 = byte2str(iv1);
        ac.println(str_iv1);
        
        System.out.println("Dato modificado: "+dc.readLine());
        
        System.out.println("Estado"+ dc.readLine());
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
    public static String byte2str( byte[] b )
	{	
		// Encapsulamiento con hexadecimales
		String ret = "";
		for (int i = 0 ; i < b.length ; i++) {
			String g = Integer.toHexString(((char)b[i])&0x00ff);
			ret += (g.length()==1?"0":"") + g;
		}
		return ret;
	}
    private static BigInteger calcular_llave_maestra(BigInteger base, BigInteger exponente, BigInteger modulo) {
		return base.modPow(exponente, modulo);
	}
    private static byte[] generateIvBytes() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return iv;
	}
}
