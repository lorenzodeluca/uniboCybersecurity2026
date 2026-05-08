import java.security.*;
import java.util.HexFormat;
import javax.crypto.*;
import javax.crypto.spec.*;

public class StreamCipher {
 
    public static void main(String[] args) {

        try {

            // Encryption
            SecureRandom sr = new SecureRandom();
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256, sr);
            SecretKey key = kg.generateKey();

            byte[] nonce = new byte[12];
            sr.nextBytes(nonce);
            int counter = sr.nextInt();
            ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(nonce, counter);

            Cipher cipher = Cipher.getInstance("CHACHA20");
            cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

            byte[] plaintext = "Sicurezza dell'Informazione".getBytes();
            byte[] ciphertext = cipher.doFinal(plaintext);
            String encodedCiphertext = HexFormat.of().formatHex(ciphertext);
            System.out.println("Ciphertext: " + encodedCiphertext);

            // Decryption
            cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
            byte[] decryptedPlaintextBytes = cipher.doFinal(ciphertext);
            String decryptedPlaintext = new String(decryptedPlaintextBytes);
            System.out.println("Decrypted Plaintext: " + decryptedPlaintext);

        } catch (Exception e) {
        }

    }

}
