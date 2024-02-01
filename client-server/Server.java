import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;

class Server {
    private static final HashMap<String, ArrayList<String>> messages = new HashMap<>();

    public static void main(String[] args) throws Exception {

        if (args.length < 1) {
            System.err.println("Usage: java Server <port>");
            System.exit(1);
        }

        int port = Integer.parseInt(args[0]); // port of server

        System.out.println("Waiting incoming connection...");
        try (ServerSocket ss = new ServerSocket(port);) {
            while (true) {
                final Socket s = ss.accept();
                new Thread(() -> handleClient(s)).start();
            }
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }

    }

    private static void handleClient(Socket s) {
        try (DataInputStream dis = new DataInputStream(s.getInputStream());
                DataOutputStream dos = new DataOutputStream(s.getOutputStream());) {
            String clientMessage = dis.readUTF();
            messages.putIfAbsent(clientMessage, new ArrayList<>());
            System.out.println("login from user " + clientMessage);

            System.out.println("Delivering " + messages.get(clientMessage).size() + " messages");
            dos.writeUTF("There are " + messages.get(clientMessage).size() + " message(s) for you");

            String msg;
            while ((msg = dis.readUTF()) != null) {
                System.out.println(msg);
                dos.writeUTF(msg);
            }
        } catch (IOException e) {
            System.err.println("Client closed its connection.");
        }
    }

    public static int getClientMessageCount(String userid) {
        return messages.getOrDefault(userid, new ArrayList<>()).size();

    }

}
