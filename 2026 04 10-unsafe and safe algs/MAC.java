import java.security.*;
import java.util.HexFormat;
import javax.crypto.*;
import javax.crypto.spec.*;

public class MAC {
 
    public static void main(String[] args) {

        try {

            // Encryption
            SecureRandom sr = new SecureRandom();

            KeyGenerator secretKeyGenerator = KeyGenerator.getInstance("AES");
            secretKeyGenerator.init(256, sr);
            SecretKey secretKey = secretKeyGenerator.generateKey();

            KeyGenerator macKeyGenerator = KeyGenerator.getInstance("HmacSHA256");
            macKeyGenerator.init(256, sr);
            SecretKey macKey = macKeyGenerator.generateKey();

            byte[] iv = new byte[16];
            sr.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            Mac macInstance = Mac.getInstance("HmacSHA256");
            macInstance.init(macKey);

            byte[] plaintext = "Sicurezza dell'Informazione".getBytes();
            byte[] ciphertext = cipher.doFinal(plaintext);
            byte[] mac = macInstance.doFinal(ciphertext); 
            String encodedCiphertext = HexFormat.of().formatHex(ciphertext);
            String encodedMac = HexFormat.of().formatHex(mac);
            System.out.println("Ciphertext: " + encodedCiphertext);
            System.out.println("MAC: " + encodedMac);

            // Decryption
            //The receiver already has the keys and the IV
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            macInstance.init(macKey);

            byte[] computedMac = macInstance.doFinal(ciphertext);
            if(!MessageDigest.isEqual(mac, computedMac)) {
                System.out.println("MAC verification failed.");
                return;
            }
            byte[] decryptedPlaintextBytes = cipher.doFinal(ciphertext);
            String decryptedPlaintext = new String(decryptedPlaintextBytes);
            System.out.println("Decrypted Plaintext: " + decryptedPlaintext);

        } catch (Exception e) {
        }

    }

}
