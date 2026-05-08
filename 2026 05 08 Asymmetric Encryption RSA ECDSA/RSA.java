import java.security.*;
import java.security.spec.*;
import javax.crypto.*;

public class RSA {
    public static void main(String[] args) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSASSA-PSS");
            keyGen.initialize(2048);  // 3072 would be better
            KeyPair myPair = keyGen.generateKeyPair();
            KeyPair receiverPair = keyGen.generateKeyPair();

            PublicKey senderPublicKey = myPair.getPublic();
            PrivateKey senderPrivateKey = myPair.getPrivate();
            PublicKey receiverPublicKey = receiverPair.getPublic();
            PrivateKey receiverPrivateKey = receiverPair.getPrivate();

            // SENDER SIDE
            // Encrypting a message using the receiver's public key
            byte[] message = "Hello!".getBytes();

            Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            c.init(Cipher.ENCRYPT_MODE, receiverPublicKey);
            byte[] encryptedMessage = c.doFinal(message);

            // Signing the message with the sender's private key
            Signature sigSign = Signature.getInstance("RSASSA-PSS");
            sigSign.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, PSSParameterSpec.TRAILER_FIELD_BC));
            sigSign.initSign(senderPrivateKey);
            sigSign.update(encryptedMessage);
            byte[] signature = sigSign.sign();

            // RECEIVER SIDE
            // Verifying the signature using the sender's public key
            Signature sigVerify = Signature.getInstance("RSASSA-PSS");
            sigVerify.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, PSSParameterSpec.TRAILER_FIELD_BC));
            sigVerify.initVerify(senderPublicKey);
            sigVerify.update(encryptedMessage);
            boolean isVerified = sigVerify.verify(signature);
            System.out.println("Signature Verified: " + isVerified);

            // Decrypting the message using the receiver's private key
            c.init(Cipher.DECRYPT_MODE, receiverPrivateKey);
            byte[] decryptedMessage = c.doFinal(encryptedMessage);
            System.out.println("Decrypted Message: " + new String(decryptedMessage));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}