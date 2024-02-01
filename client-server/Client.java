import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class Client {

    public static void main(String[] args) throws Exception {

        if (args.length < 3) {
            System.err.println("Usage: java Client <host> <port> <userid>");
            System.exit(1);
        }
        String host = args[0]; // hostname of server
        int port = Integer.parseInt(args[1]); // port of server
        String userid = args[2]; // user id

        try (Socket s = new Socket(host, port);
                DataInputStream dis = new DataInputStream(s.getInputStream());
                DataOutputStream dos = new DataOutputStream(s.getOutputStream());
                BufferedReader br = new BufferedReader(new InputStreamReader(System.in));) {
            // Generate hashed userID
            String hashedUserID = hashUserId(userid);
            dos.writeUTF(hashedUserID); // add to an output stream
            dos.flush(); // send message

            Thread readingThread = new Thread(() -> {
                try {
                    String msg;
                    while ((msg = dis.readUTF()) != null) {
                        System.out.println(msg);

                        System.out.println("Do you want to send a message? (y/n)");
                        String userInput = br.readLine();
                        if ("y".equalsIgnoreCase(userInput)) {
                            System.out.println("Enter recipient's user id:");
                            String recipient = br.readLine();
                            System.out.println("Enter message:");
                            String message = br.readLine();

                            String messageToSend = recipient + "|" + message;
                            dos.writeUTF(messageToSend);
                            break;
                        } else {
                            System.out.println("Goodbye!");
                            break;
                        }

                    }
                } catch (IOException e) {
                    System.err.println("Server closed its connection.");
                }
            });
            readingThread.start();

            // Wait for the reading thread to finish
            readingThread.join();
        } catch (IOException | NoSuchAlgorithmException e) {
            System.out.println("Error: " + e.getMessage());
        }

    }

    private static String hashUserId(String userid) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(("gfhk2024:" + userid).getBytes());
        byte[] digest = md.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02X", b));
        }
        String s = sb.toString();

        return s;

    }

}
