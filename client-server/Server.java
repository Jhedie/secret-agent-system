import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;

class Server {
    private static final HashMap<String, ArrayList<String>> messages = new HashMap<>();

    private static final String currentUser = "";

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
            if (messages.get(clientMessage).size() > 0) {
                // Send each message to the client
                for (String msg : messages.get(clientMessage)) {
                    dos.writeUTF(msg);

                    // Upon receiving these contents, the server first verifies the signature with
                    // the appropriate key.

                    // If the signature does not verify, or if the sender userid is unrecognised (no
                    // corresponding key of that userid is present in the server) the message is
                    // discarded

                    // Otherwise, it decrypts the message, and finds out the recipient userid.

                    // If the decryption fails (i.e., it results in a BadPaddingException), the
                    // message is again discarded.

                    // The server then re-encrypts the message (but without the recipient userid).

                    // Finally the server computes the hashed recipient userid, and saves it and the
                    // encrypted message to its collection of messages. The original (unhashed)
                    // recipient userid is not stored. The signature is also not stored.

                    // The connection then ends and the server should wait for the next client. The
                    // server should not quit or terminate (even if the signature check fails or the
                    // client terminated their connection early).

                }

                // Clear the messages for this user
                messages.get(clientMessage).clear();
            }

            String msg;
            while ((msg = dis.readUTF()) != null) {
                System.out.println(msg);

            }
        } catch (IOException e) {
            System.err.println("Client closed its connection.");
        }
    }

    public static int getClientMessageCount(String userid) {
        return messages.getOrDefault(userid, new ArrayList<>()).size();

    }

}
