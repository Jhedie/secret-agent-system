import java.io.*;
import java.net.*;
import java.security.MessageDigest;
import java.util.Base64;

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
            String serverString, clientString;

            Socket s = new Socket(host, port);
            DataInputStream din = new DataInputStream(s.getInputStream());
            DataOutputStream dout = new DataOutputStream(s.getOutputStream());
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

            do {
                // Generate hashed userID
                String hashedUserID = hashUserId(userid);

                dout.writeUTF(hashedUserID); // add to an output stream
                dout.flush(); // send message

                System.out.println("Enter a message for the server> "); // prompt the user
                clientString = br.readLine(); // get user input
                dout.writeUTF(clientString); // add to an output stream
                dout.flush(); // send message

                serverString = din.readUTF();
                if (serverString.equals("stop")) {
                    break;
                }
                System.out.println("Server says: " + serverString);

            } while (!serverString.equals("stop"));
            dout.close();
            s.close();
        } catch (Exception e) {
            System.out.println(e);
        }

    }

    private static String hashUserId(String userid) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(("gfhk2024:" + userid).getBytes());
        byte[] digest = md.digest();
        return Base64.getEncoder().encodeToString(digest);
    }

}
