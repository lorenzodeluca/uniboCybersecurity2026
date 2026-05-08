import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class DH {
    public static void main(String[] args) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(2048);
            KeyPair senderPair = keyGen.generateKeyPair();
            PublicKey senderPub = senderPair.getPublic();
            PrivateKey senderPriv = senderPair.getPrivate();
            KeyPair receiverPair = keyGen.generateKeyPair();
            PublicKey receiverPub = receiverPair.getPublic();
            PrivateKey receiverPriv = receiverPair.getPrivate();

            // Sender side
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(senderPriv);
            ka.doPhase(receiverPub, true);
            byte[] senderSharedSecret = ka.generateSecret();

            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            byte[] senderSecretHash = hash.digest(senderSharedSecret);
            SecretKeySpec secretKey = new SecretKeySpec(senderSecretHash, "AES");

            Cipher c = Cipher.getInstance("AES");
            c.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] message = "Hello!".getBytes();
            byte[] encryptedMessage = c.doFinal(message);
            
            // Receiver side
            ka.init(receiverPriv);
            ka.doPhase(senderPub, true);
            byte[] receiverSharedSecret = ka.generateSecret();
            byte[] receiverSecretHash = hash.digest(receiverSharedSecret);
            SecretKeySpec receiverSecretKey = new SecretKeySpec(receiverSecretHash, "AES");
            c.init(Cipher.DECRYPT_MODE, receiverSecretKey);
            byte[] decryptedMessage = c.doFinal(encryptedMessage);
            System.out.println("Decrypted Message: " + new String(decryptedMessage));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}