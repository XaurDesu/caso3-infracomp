package client;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;

import javax.crypto.SecretKey;

import java.net.*;
import server.SecurityFunctions;

public class ClienteMain extends Thread{
	
	public static long tiempo1 = 0;
	public static long tiempo2 = 0;
	public static long tiempo4 = 0;
	public static long contadorHilos = 0;

    private final static String host = "localhost";
    public final static int puerto = 2017;

    private Socket s;
    
    private  SecurityFunctions f;
    private  String dlg;

    public void run()
    {
    	try {
    		agregarHilo();
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
            
            
            //HERE2
            long start2 = System.nanoTime();
            
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
            
            
            long finish2 = System.nanoTime();
            long timeElapsed2 = (long) ((finish2 - start2)*(Math.pow(10, -6)));
            agregar2(timeElapsed2);
            //System.out.println("2: codigo de autenticacion: "+timeElapsed2+" ms");
            //HERE2
            
            
            
            //HERE4
            long start4 = System.nanoTime();
            
            
            //Calcular G2Y = g*x mod p o es z = y*x mod p
            BigInteger g1 = new BigInteger(g);
            BigInteger p1 = new BigInteger(p);
            BigInteger g2x1 = new BigInteger(g2x);
            SecureRandom r = new SecureRandom();
            int x = Math.abs(r.nextInt());
    		
            
            System.out.println("test");

    		Long longx = Long.valueOf(x);
            BigInteger bix = BigInteger.valueOf(longx);
            BigInteger g2y = g1.modPow(bix, g2x1);
            
            long finish4 = System.nanoTime();
            long timeElapsed4 = (long) ((finish4 - start4)*(Math.pow(10, -6)));
            //System.out.println("4: Calcular G^2: "+timeElapsed4+" ms");
            agregar4(timeElapsed4);
            //HERE4
            
            
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
         	//System.out.println("Ingrese el numero que desea modificar");
            long start = System.nanoTime();
         	//String entrada = bf.readLine();
            String entrada = "500";
         	
         	//HERE 1
         	long start1 = System.nanoTime();
         	
            int valorConsulta=Integer.parseInt(entrada);
            try {
    			byte[] cifrado = f.aenc(publicaServidor, valorConsulta+"");
    			String valor = byte2str(cifrado);
    			ac.println(valor);
    		} catch (Exception e) {
    			// TODO Auto-generated catch block
    			e.printStackTrace();
    		}
            
            long finish1 = System.nanoTime();
            long timeElapsed1 = (long) ((finish1 - start1)*(Math.pow(10, -6)));
            //System.out.println("1: Cifrar la consulta: "+timeElapsed1+" ms");
            agregar1(timeElapsed1);
            //HERE1
            
            
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

            long finish = System.nanoTime();
            long timeElapsed = (long) ((finish - start)*(Math.pow(10, -6)));
            //System.out.println("tiempo pasado: "+timeElapsed+" ms");
            System.out.println("Estado"+ dc.readLine());

            System.out.println("m1 "+ dc.readLine());
            System.out.println("m2 "+ dc.readLine());
            System.out.println("str_iv2 "+ dc.readLine());
            
            ac.println("ERROR");
              
            
            s.close();
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}
        System.out.println("Threads: " + contadorHilos + "");
        System.out.println("T1: " + tiempo1 + "");
        System.out.println("T2: " + tiempo2 + "");
        System.out.println("T4: " + tiempo4 + "");
    
    }
    
    public static void main(String[] args)
    {
    	  int n = 4; // Number of threads
    	  ArrayList<ClienteMain> arrayHilos = new ArrayList<ClienteMain>();
          for (int i = 0; i < n; i++) {
              ClienteMain hilo = new ClienteMain();
              arrayHilos.add(hilo);
          }
          
          for (int i = 0; i < n; i++) {
        	  arrayHilos.get(i).start();
          }
          
          
          System.out.println("Threads: " + contadorHilos + "");
          System.out.println("T1: " + tiempo1 + "");
          System.out.println("T2: " + tiempo2 + "");
          System.out.println("T4: " + tiempo4 + "");
          
	}
    
    
   public synchronized void agregar1(long time)
   {
	   tiempo1 = tiempo1 + time;
   }
   
   public synchronized void agregar2(long time)
   {
	   tiempo2 = tiempo2 + time;
   }
   
   public synchronized void agregar4(long time)
   {
	   tiempo4 = tiempo4 + time;
   }
   
   public synchronized void agregarHilo()
   {
	   contadorHilos = contadorHilos + 1;
   }
    
    public byte[] str2byte( String ss)
	{	
		// Encapsulamiento con hexadecimales
		byte[] ret = new byte[ss.length()/2];
		for (int i = 0 ; i < ret.length ; i++) {
			ret[i] = (byte) Integer.parseInt(ss.substring(i*2,(i+1)*2), 16);
		}
		return ret;
	}
    public String byte2str( byte[] b )
	{	
		// Encapsulamiento con hexadecimales
		String ret = "";
		for (int i = 0 ; i < b.length ; i++) {
			String g = Integer.toHexString(((char)b[i])&0x00ff);
			ret += (g.length()==1?"0":"") + g;
		}
		return ret;
	}
    private BigInteger calcular_llave_maestra(BigInteger base, BigInteger exponente, BigInteger modulo) {
		return base.modPow(exponente, modulo);
	}
    private byte[] generateIvBytes() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return iv;
	}
}
