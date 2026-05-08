import java.security.*;
import java.util.HexFormat;
import javax.crypto.*;
import javax.crypto.spec.*;

public class BlockCipher {
 
    public static void main(String[] args) {

        try {

            // Encryption
            SecureRandom sr = new SecureRandom();
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256, sr);
            SecretKey key = kg.generateKey();

            byte[] iv = new byte[16];
            sr.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

            byte[] plaintext = "Sicurezza dell'Informazione".getBytes();
            byte[] ciphertext = cipher.doFinal(plaintext);
            String encodedCiphertext = HexFormat.of().formatHex(ciphertext);
            System.out.println("Ciphertext: " + encodedCiphertext);

            // Decryption
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            byte[] decryptedPlaintextBytes = cipher.doFinal(ciphertext);
            String decryptedPlaintext = new String(decryptedPlaintextBytes);
            System.out.println("Decrypted Plaintext: " + decryptedPlaintext);

        } catch (Exception e) {
        }

    }

}
