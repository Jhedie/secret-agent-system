import java.io.*;
import java.net.*;

class Server {

    public static void main(String[] args) throws Exception {
        try {
            String serverString, clientMessage;

            if (args.length < 1) {
                System.err.println("Usage: java Server <port>");
                System.exit(1);
            }

            int port = Integer.parseInt(args[0]); // port of server

            System.out.println("Waiting incoming connection...");
            ServerSocket ss = new ServerSocket(port);
            Socket s = ss.accept();
            DataInputStream dis = new DataInputStream(s.getInputStream());
            DataOutputStream dout = new DataOutputStream(s.getOutputStream());
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

            do {
                clientMessage = dis.readUTF(); // read input for the client
                System.out.println("Client says " + clientMessage);
                if (clientMessage.equals("stop")) {
                    break;
                }


                
                System.out.print("Write something to client > ");// prom
                serverString = br.readLine(); // read their input

                dout.writeUTF(serverString);// write it into the output stream.
                dout.flush();// send

            } while (!serverString.equals("stop"));// stop if stop

            dis.close();
            s.close();
            ss.close();
        } catch (IOException e) {
            System.err.println("Client closed its connection.");
        }
    }
}
