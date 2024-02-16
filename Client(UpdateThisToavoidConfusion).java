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
    private static String host = "";
    private static int port = 0;

    public static void main(String[] args) {

        if (args.length < 3) {
            System.err.println("Usage: java Client <host> <port> <userid>");
            System.exit(1);
        }
        host = args[0];
        port = Integer.parseInt(args[1]);
        userid = args[2];

        // Guard for ensuring that a user does not attempt to access or send from
        // another user's account. This is done by attempting to find the priv key of
        // the user
        Path path = Paths.get(".", userid + ".prv");
        if (!Files.exists(path)) {
            System.err.println(userid + " not recognized. Please ensure you are using a valid user ID.");
            System.exit(1);
        }

        // wrap streams in try-with-resources to ensure they are properly closed
        try (Socket s = new Socket(host, port);
                DataInputStream dataInputStream = new DataInputStream(s.getInputStream());
                DataOutputStream dataOutputStream = new DataOutputStream(s.getOutputStream());
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));) {

            String hashedUserID = hashUserId(userid);
            dataOutputStream.writeUTF(hashedUserID); // add to an output stream
            dataOutputStream.flush(); // send message

            // Create a new thread to read messages from the server
            Thread readingThread = new Thread(() -> {
                try {
                    while (true) {
                        String numberOfMessages = dataInputStream.readUTF();
                        System.out.println("There are " + numberOfMessages + " message(s) for you");

                        if (Integer.parseInt(numberOfMessages) > 0) {
                            for (int i = 0; i < Integer.parseInt(numberOfMessages); i++) {

                                // The server will send the client the following contents
                                // in the following order:
                                // 1. The digital signature of the encrypted message
                                // 2. The timestamp of the message
                                // 3. The encrypted message
                                String incomingDigitalSignature = dataInputStream.readUTF();
                                String incomingTimeStamp = dataInputStream.readUTF();
                                String incomingEncryptedMessage = dataInputStream.readUTF();

                                // print the digital signature, timestamp, and encrypted message
                                System.out.println("Digital Signature: " + incomingDigitalSignature);
                                System.out.println("Timestamp: " + incomingTimeStamp);
                                System.out.println("Encrypted Message: " + incomingEncryptedMessage);

                                // Upon receiving above contents, verify
                                boolean isVerified = verifySignature(incomingDigitalSignature, incomingTimeStamp,
                                        incomingEncryptedMessage);

                                if (!isVerified) {
                                    throw new SignatureException(
                                            "Signature verification failed. Terminating connection.");
                                }

                                // Otherwise, it decrypts the message with the appropriate key, and displays the
                                // decrypted message and the timestamp on screen.
                                String decryptedMessage = new String(getDecryptedMessage(incomingEncryptedMessage),
                                        "UTF-8");
                                System.out.println("Date: " + incomingTimeStamp);
                                System.out.println("Message: " + decryptedMessage);
                            }
                        }

                        // After displaying all these messages, the client program then asks the user
                        // whether they want to send a message.
                        System.out.print("Do you want to send a message? (y/n): ");
                        String userInput = bufferedReader.readLine();
                        if ("y".equalsIgnoreCase(userInput)) {
                            System.out.print("Enter recipient's user id: ");
                            String recipient = bufferedReader.readLine();
                            System.out.print("Enter your message: ");
                            String message = bufferedReader.readLine();

                            // Prepare the message to be encrypted
                            String messageToSend = recipient + "|" + message;
                            byte[] encryptedMessage = encryptMessage(messageToSend);

                            // generate a signature
                            byte[] digitalSignature = signDigitalSignature(encryptedMessage);

                            // encode the encrypted message and digital signature to base64
                            String digitalSignatureString = Base64.getEncoder().encodeToString(digitalSignature);
                            String encryptedMessageString = Base64.getEncoder().encodeToString(encryptedMessage);

                            // Generate a timestamp
                            String timestamp = getTimestamp();

                            // print the digital signature, timestamp, and encrypted message
                            System.out.println("Digital Signature: " + digitalSignatureString);
                            System.out.println("Timestamp: " + timestamp);
                            System.out.println("Encrypted Message: " + encryptedMessageString);

                            // Send the encrypted message, timestamp, signature, and unhashed sender userid
                            // to the server
                            dataOutputStream.writeUTF(userid);
                            dataOutputStream.writeUTF(digitalSignatureString);
                            dataOutputStream.writeUTF(timestamp);
                            dataOutputStream.writeUTF(encryptedMessageString);

                            System.out.println("Message sent!");
                            break;
                        } else if ("n".equalsIgnoreCase(userInput)) {
                            System.out.println("Goodbye!");
                            break;
                        } else {
                            throw new IOException("Invalid input. Terminating connection.");
                        }
                    }
                } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
                        | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException
                        | SignatureException e) {
                    System.out.println("Error: " + e + e.getMessage());
                    System.exit(1);
                }
            });
            // Start the thread that reads messages from the server
            readingThread.start();

            // Pause the current thread until the reading thread has finished execution
            // This ensures that the main program does not exit before all messages have
            // been read
            readingThread.join();

        } catch (IOException | NoSuchAlgorithmException | InterruptedException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    private static byte[] getDecryptedMessage(String incomingEncryptedMessage)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException,
            InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, getClientPrivateKey());
        byte[] decryptedMessage = cipher
                .doFinal(Base64.getDecoder().decode(incomingEncryptedMessage.getBytes()));
        return decryptedMessage;
    }

    private static boolean verifySignature(String incomingDigitalSignature, String incomingTimeStamp,
            String incomingEncryptedMessage) throws NoSuchAlgorithmException, InvalidKeyException, IOException,
            InvalidKeySpecException, SignatureException {

        String messageToVerify = incomingEncryptedMessage
                + incomingTimeStamp;
        byte[] mesageToVerifyInBytes = messageToVerify.getBytes();

        // Initialize a Signature object for verification.
        Signature signatureForVerification = Signature.getInstance("SHA256withRSA");
        signatureForVerification.initVerify(getServerPublicKey());
        // update the signature object with the data to be verified
        signatureForVerification.update(mesageToVerifyInBytes);
        // If the key does not verify, it should terminate the connection immediately.
        boolean isVerified = signatureForVerification
                .verify(Base64.getDecoder().decode(incomingDigitalSignature));
        return isVerified;
    }

    private static String getTimestamp() {
        Instant timestamp = Instant.now();
        return timestamp.toString();
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

    private static byte[] encryptMessage(String message)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, InvalidKeySpecException, IOException {

        PublicKey serverPublicKey = getServerPublicKey();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());

        return encryptedMessage;
    }

    private static PublicKey getServerPublicKey()
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

        // Construct the path to the public key file
        Path path = Paths.get(".", "server.pub");

        // Create a File object from the path
        File f = path.toFile();
        byte[] keyBytes = Files.readAllBytes(f.toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(spec);

        return publicKey;
    }

    private static PrivateKey getClientPrivateKey()
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        // Construct the path to the private key file
        // The file name is the user id with ".prv" extension
        Path path = Paths.get(".", userid + ".prv");
        // Create a File object from the path
        File f = path.toFile();
        byte[] keyBytes = Files.readAllBytes(f.toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(spec);

        return privateKey;
    }

}
