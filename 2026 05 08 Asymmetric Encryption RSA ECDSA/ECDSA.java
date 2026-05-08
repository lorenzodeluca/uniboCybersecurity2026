import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class ECDSA {
    public static void main(String[] args) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
            keyGen.initialize(ecSpec, new SecureRandom());
            KeyPair senderPair = keyGen.generateKeyPair();

            PublicKey senderPublicKey = senderPair.getPublic();
            PrivateKey senderPrivateKey = senderPair.getPrivate();

            // SENDER SIDE
            // Encrypting a message using the receiver's public key
            byte[] message = "Hello!".getBytes();

            Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
            ecdsaSign.initSign(senderPrivateKey);
            ecdsaSign.update(message);
            byte[] signature = ecdsaSign.sign();
            System.out.println("Firma: " + Base64.getEncoder().encodeToString(signature));


            // RECEIVER SIDE
            Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
            ecdsaVerify.initVerify(senderPublicKey);
            ecdsaVerify.update(message);

            boolean isCorrect = ecdsaVerify.verify(signature);
            System.out.println("Is the signature valid? " + isCorrect);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}