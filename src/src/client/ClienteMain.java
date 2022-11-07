package client;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.*;
import java.net.*;

public class ClienteMain {

    private static String host = "localhost";
    private static int puerto = 4030;

    private static Socket s;

    public static void main(String[] args) throws IOException {
        s = new Socket(host, puerto);
        System.out.println("Connection socket created on port: "+puerto);

        ObjectOutputStream os = new ObjectOutputStream(s.getOutputStream());
    }
}
