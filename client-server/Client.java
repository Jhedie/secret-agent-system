import java.io.*;
import java.net.*;

class Client {

    public static void main(String[] args) throws Exception {

        if (args.length < 3) {
            System.err.println("Usage: java Client <host> <port> <userid>");
            System.exit(1);
        }

        String host = args[0]; // hostname of server
        int port = Integer.parseInt(args[1]); // port of server
        String userid = args[2]; // user id

        try {
            Socket s = new Socket(host, port);
            DataOutputStream dos = new DataOutputStream(s.getOutputStream());

            dos.writeUTF("Hello World! From user: " + userid);
            dos.writeUTF("Happy new year! From user: " + userid);

        } catch (Exception e) {
            System.err.println("Cannot connect to server.");
        }

    }
}
