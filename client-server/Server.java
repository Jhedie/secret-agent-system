import java.io.*;
import java.net.*;

class Server {

    public static void main(String[] args) throws Exception {

        if (args.length < 1) {
            System.err.println("Usage: java Server <port>");
            System.exit(1);
        }

        int port = Integer.parseInt(args[0]); // port of server
        ServerSocket ss = new ServerSocket(port);
        System.out.println("Waiting incoming connection...");

        Socket s = ss.accept();
        DataInputStream dis = new DataInputStream(s.getInputStream());

        String x = null;

        try {
            while ((x = dis.readUTF()) != null) {

                System.out.println(x);

            }
        } catch (IOException e) {
            System.err.println("Client closed its connection.");
        }
    }
}
