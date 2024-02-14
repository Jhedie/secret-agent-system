
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
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
import java.time.Instant;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

class Client {

    private static String userid = "";

    public static void main(String[] args) {

        if (args.length < 3) {
            System.err.println("Usage: java Client <host> <port> <userid>");
            System.exit(1);
        }
        String host = args[0]; // hostname of server
        int port = Integer.parseInt(args[1]); // port of server
        userid = args[2]; // user id

        // use try-with-resources to auto-close the socket
        try (Socket s = new Socket(host, port);
                DataInputStream dis = new DataInputStream(s.getInputStream());
                DataOutputStream dos = new DataOutputStream(s.getOutputStream());
                BufferedReader br = new BufferedReader(new InputStreamReader(System.in));) {
            // Generate hashed userID
            String hashedUserID = hashUserId(userid);
            dos.writeUTF(hashedUserID); // add to an output stream
            dos.flush(); // send message

            // Create a new thread to read messages from the server
            Thread readingThread = new Thread(() -> {
                try {

                    while (true) {
                        String numberOfMessages = dis.readUTF();
                        System.out.println("There are " + numberOfMessages + " message(s) for you");

                        if (Integer.parseInt(numberOfMessages) > 0) {
                            for (int i = 0; i < Integer.parseInt(numberOfMessages); i++) {

                                // The server will send the client the following contents
                                // in the following order:
                                // 1. The digital signature of the encrypted message
                                // 2. The timestamp of the message
                                // 3. The encrypted message
                                String incomingDigitalSignature = dis.readUTF();
                                String incomingTimeStamp = dis.readUTF();
                                String incomingEncryptedMessage = dis.readUTF();
                                // Upon receiving these contents,

                                String messageToVerify = incomingEncryptedMessage
                                        + incomingTimeStamp;
                                byte[] bytesToVerify = messageToVerify.getBytes();

                                // Initialize a Signature object for verification.
                                Signature signatureForVerification = Signature.getInstance("SHA256withRSA");
                                signatureForVerification.initVerify(getServerPublicKey());
                                // update the signature object with the data to be verified
                                signatureForVerification.update(bytesToVerify);
                                // If the key does not verify, it should terminate the connection
                                // immediately.
                                boolean isVerified = signatureForVerification
                                        .verify(Base64.getDecoder().decode(incomingDigitalSignature));

                                if (!isVerified) {
                                    throw new SignatureException(
                                            "Signature verification failed. Terminating connection.");
                                }
                                // Otherwise, it decrypts the message with the appropriate key, and displays the
                                // decrypted message and the timestamp on screen.
                                Cipher cipher = Cipher.getInstance("RSA");
                                cipher.init(Cipher.DECRYPT_MODE, getClientPrivateKey());
                                byte[] decryptedMessage = cipher
                                        .doFinal(Base64.getDecoder().decode(incomingEncryptedMessage.getBytes()));
                                System.out.println("Decrypted message: " + new String(decryptedMessage,
                                        "UTF-8"));
                            }
                        }

                        // After displaying all these messages, the client program then asks the user
                        // whether they want to send a message.
                        System.out.print("Do you want to send a message? (y/n): ");
                        String userInput = br.readLine();
                        if ("y".equalsIgnoreCase(userInput)) {
                            System.out.println("Enter recipient's user id:");
                            String recipient = br.readLine();
                            System.out.println("Enter message:");
                            String message = br.readLine();

                            String messageToSend = recipient + "|" + message;
                            // encrypt message
                            byte[] encryptedMessage = encryptMessage(messageToSend);

                            // Generate a timestamp
                            Instant timestamp = getTimestamp();

                            // generate a signature
                            byte[] digitalSignature = signDigitalSignature(encryptedMessage);

                            // Send the encrypted message, timestamp, signature, and unhashed sender userid
                            // to the server
                            dos.writeUTF(userid);
                            dos.writeUTF(Base64.getEncoder().encodeToString(digitalSignature));
                            dos.writeUTF(timestamp.toString());
                            dos.writeUTF(Base64.getEncoder().encodeToString(encryptedMessage));

                            System.out.println("Message sent!");
                            dos.flush();
                            break;
                        } else {
                            System.out.println("Goodbye!");
                            break;
                        }
                    }

                } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
                        | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException
                        | SignatureException e) {
                    e.printStackTrace();
                }
            });
            // Start waiting for messages from the server
            readingThread.start();

            // Wait for the reading thread to finish before closing the socket
            readingThread.join();
        } catch (IOException | NoSuchAlgorithmException |

                InterruptedException e) {
            System.out.println("Error: " + e.getMessage());
        }

    }

    private static Instant getTimestamp() {
        Instant timestamp = Instant.now();
        return timestamp;
    }

    private static byte[] signDigitalSignature(byte[] encryptedMessage) throws NoSuchAlgorithmException,
            InvalidKeyException, IOException, InvalidKeySpecException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(getClientPrivateKey());
        signature.update(encryptedMessage);
        byte[] digitalSignature = signature.sign();
        return digitalSignature;
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

    private static PublicKey getServerPublicKey()
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        Path path = Paths.get(".", "server.pub");
        File f = path.toFile();
        byte[] keyBytes = Files.readAllBytes(f.toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory;
        keyFactory = KeyFactory.getInstance("RSA");

        PublicKey publicKey = keyFactory.generatePublic(spec);

        return publicKey;
    }

    private static PrivateKey getClientPrivateKey()
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        Path path = Paths.get(".", userid + ".prv");

        File f = path.toFile();
        byte[] keyBytes = Files.readAllBytes(f.toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory;
        keyFactory = KeyFactory.getInstance("RSA");

        PrivateKey privateKey = keyFactory.generatePrivate(spec);

        return privateKey;
    }

    private static byte[] encryptMessage(String message)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, InvalidKeySpecException, IOException {
        PublicKey serverPublicKey = getServerPublicKey();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        return encryptedMessage;

    }

}
