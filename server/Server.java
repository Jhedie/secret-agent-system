import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

class Server {

    /**
     * Represents a message with text and a timestamp.
     */
    private static class Message {
        private final String text;
        private final String timestamp;

        public Message(String text, String timestamp) {
            this.text = text;
            this.timestamp = timestamp;
        }

        // getters
        public String getText() {
            return text;
        }

        public String getTimestamp() {
            return timestamp;
        }
    }

    /**
     * A map that stores messages for each user.
     * The key is the hashed user ID and the value is a list of messages that the
     * user
     * has sent or received.
     */
    private static final HashMap<String, ArrayList<Message>> MESSAGES = new HashMap<>();
    private static int port = 0;

    public static void main(String[] args) throws Exception {

        if (args.length < 1) {
            System.err.println("Usage: java Server <port>");
            System.exit(1);
        }

        port = Integer.parseInt(args[0]);

        System.out.println("Waiting incoming connection...");

        // Create a ServerSocket that listens on the specified port
        try (ServerSocket ss = new ServerSocket(port);) {
            while (true) {
                // Accept a new connection
                final Socket s = ss.accept();

                // Create a new thread to handle the client associated with the connection
                new Thread(() -> {
                    try {
                        // Handle the client's requests
                        handleClient(s);
                    } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException
                            | SignatureException | NoSuchPaddingException | IllegalBlockSizeException
                            | BadPaddingException e) {
                        System.out.println("Error: " + e.getMessage());
                    }
                }).start();
            }
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }

    }

    private static void handleClient(Socket s)
            throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, SignatureException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        try (DataInputStream dataInputStream = new DataInputStream(s.getInputStream());
                DataOutputStream dataOutputStream = new DataOutputStream(s.getOutputStream());) {

            String clientMessage = dataInputStream.readUTF();
            System.out.println("login from user " + clientMessage);
            MESSAGES.putIfAbsent(clientMessage, new ArrayList<>());

            System.out.println("Delivering " + MESSAGES.get(clientMessage).size() + " MESSAGES");
            dataOutputStream.writeUTF(String.valueOf(MESSAGES.get(clientMessage).size()));
            dataOutputStream.flush();
            // If this number is not zero, then for each such message,
            if (MESSAGES.get(clientMessage).size() > 0) {
                System.out.println("messages available");
                for (Message message : MESSAGES.get(clientMessage)) {
                    // the server generates a signature based on its encrypted content and
                    // timestamp, with a key that proves the identity of the server.
                    // create signature object for signing with SHA256withRSA
                    Signature signature = Signature.getInstance("SHA256withRSA");
                    // get the private key of the server.
                    PrivateKey serverPrivateKey = getServerPrivateKey();
                    // initialize the signature object with the private key
                    String messageToSign = message.getText() + message.getTimestamp().toString();
                    signature.initSign(serverPrivateKey);
                    // use the signature object to sign the data
                    signature.update(messageToSign.getBytes());

                    byte[] digitalSignature = signature.sign();
                    // The server then sends the message (encrypted content and timestamp) and the
                    // signature to the client.
                    dataOutputStream.writeUTF(Base64.getEncoder().encodeToString(digitalSignature));
                    dataOutputStream.writeUTF(message.getTimestamp().toString());
                    dataOutputStream.writeUTF(message.getText());
                    dataOutputStream.flush();
                    // The message is deleted from the server afterwards.
                }

                MESSAGES.get(clientMessage).clear();
            }
            while (true) {
                // The server receives a message from the client in the following order:
                // 1. rawUserId
                // 2. signature
                // 3. timestamp
                // 4. encryptedMessage
                String incomingRawUserId = dataInputStream.readUTF();
                String incomingSignature = dataInputStream.readUTF();
                String incomingTimestamp = dataInputStream.readUTF();
                String incomingEncryptedMessage = dataInputStream.readUTF();

                System.out.println("rawUserId: \n" + incomingRawUserId);
                System.out.println("signature: \n" + incomingSignature);
                System.out.println("timestamp: \n" + incomingTimestamp);
                System.out.println("encryptedMessage: \n" + incomingEncryptedMessage);
                // Upon receiving these contents, the server first verifies the signature with
                // the appropriate key.
                // create signature object for verification specified with SHA256withRSA
                Signature signature = Signature.getInstance("SHA256withRSA");

                // get the public key of the sender
                // corresponding key of that userid is present in the server) the message is
                // discarded
                PublicKey senderPublicKey = getSenderPublicKey(incomingRawUserId);
                // initialize the signature object with the public key
                signature.initVerify(senderPublicKey);

                // update the signature object with the original data that was signed
                signature.update(Base64.getDecoder().decode(incomingEncryptedMessage));

                // verify the signature
                boolean isVerified = signature.verify(Base64.getDecoder().decode(incomingSignature.getBytes()));
                // If the signature does not verify, or if the sender userid is unrecognised (no
                System.out.println("Signature verified: " + isVerified);
                if (!isVerified) {
                    throw new SignatureException("Signature verification failed. Message discarded.");
                }

                // Otherwise, it decrypts the message, and finds out the recipient userid.
                // decrypt the message
                // If the decryption fails (i.e., it results in a BadPaddingException), the
                // message is again discarded.
                String decryptedMessage = decryptMessage(Base64.getDecoder().decode(incomingEncryptedMessage));

                // Split the decrypted message into parts using the "|" character as the
                // delimiter
                String[] messageParts = decryptedMessage.split("\\|");
                String recipientUserId = messageParts[0];
                String message = messageParts[1];

                // The server then re-encrypts the message (but without the recipient userid).
                String reEncryptedMessage = encryptMessageForRecipient(message, recipientUserId);
                // Finally the server computes the hashed recipient userid, and saves it and the
                // encrypted message to its collection of messages.
                String hashedUserId = hashUserId(recipientUserId);

                MESSAGES.putIfAbsent(hashedUserId, new ArrayList<>());
                MESSAGES.get(hashedUserId).add(new Message(reEncryptedMessage, incomingTimestamp));

                // The original (unhashed) recipient userid is not stored. The signature is also
                // not stored.

                // The connection then ends and the server should wait for the next client. The
                // server should not quit or terminate (even if the signature check fails or the
                // client terminated their connection early).

            }
        } catch (IOException e) {
            System.err.println("Client closed its connection.");
        }
    }

    public static int getClientMessageCount(String userid) {
        return MESSAGES.getOrDefault(userid, new ArrayList<>()).size();

    }

    public static PublicKey getSenderPublicKey(String userid)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path path = Paths.get(".", userid + ".pub");
        File f = path.toFile();
        if (!f.exists()) {
            throw new IOException("Unrecognized user id");
        }
        byte[] keyBytes = Files.readAllBytes(f.toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory;
        keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(spec);

        return publicKey;
    }

    private static PrivateKey getServerPrivateKey()
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        Path path = Paths.get(".", "server.prv");
        File f = path.toFile();
        byte[] keyBytes = Files.readAllBytes(f.toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private static String decryptMessage(byte[] encryptedMessage)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        // Decrypt the message
        // get the private key of the server
        PrivateKey serverPrivateKey = getServerPrivateKey();
        // create a cipher object for decryption
        Cipher cipher = Cipher.getInstance("RSA");
        // initialize the cipher object with the private key
        cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
        // decrypt the message
        byte[] decryptedMessage = cipher.doFinal(encryptedMessage);

        String decryptedMessageString = new String(decryptedMessage, "UTF-8");

        return decryptedMessageString;
    }

    private static String hashUserId(String userid) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(("gfhk2024:" + userid).getBytes());
        byte[] digest = md.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02X", b));
        }
        String hashedString = sb.toString();

        return hashedString;

    }

    private static String encryptMessageForRecipient(String message, String recipientUserId)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, InvalidKeySpecException, IOException {
        // get the public key of the recipient
        PublicKey recipientPublicKey = getSenderPublicKey(recipientUserId);
        // create a cipher object for encryption
        Cipher cipher = Cipher.getInstance("RSA");
        // initialize the cipher object with the public key
        cipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey);
        // encrypt the message
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        // return the encrypted message as a Base64-encoded string
        return Base64.getEncoder().encodeToString(encryptedMessage);// return the encrypted message as a Base64-encoded
    }

}
