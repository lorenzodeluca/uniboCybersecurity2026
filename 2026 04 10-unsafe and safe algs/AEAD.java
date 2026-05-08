import java.security.*;
import java.util.HexFormat;
import javax.crypto.*;
import javax.crypto.spec.*;

public class AEAD {
 
    public static void main(String[] args) {

        try {
            // Encryption
            SecureRandom sr = new SecureRandom();
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256, sr);
            SecretKey key = kg.generateKey();

            byte[] iv = new byte[16];
            sr.nextBytes(iv);
            GCMParameterSpec paramSpec = new GCMParameterSpec(128, iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

            byte[] plainText1 = "Sicurezza ".getBytes();
            byte[] plainText2 = "dell'".getBytes();
            byte[] plainText3 = "Informazione".getBytes();
            byte[] AAD = "Prof: Rebecca Montanari".getBytes();
            cipher.updateAAD(AAD);
            cipher.update(plainText1);
            cipher.update(plainText2);
            byte[] ciphertext = cipher.doFinal(plainText3);
            String encodedCiphertext = HexFormat.of().formatHex(ciphertext);
            System.out.println("Ciphertext: " + encodedCiphertext);

            // Decryption
            cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
            cipher.updateAAD(AAD);
            ciphertext[0] ^= 1;
            byte[] decryptedPlaintextBytes = cipher.doFinal(ciphertext);
            String decryptedPlaintext = new String(decryptedPlaintextBytes);
            System.out.println("Decrypted Plaintext: " + decryptedPlaintext);

        } catch (AEADBadTagException e) {
            System.out.println("Authentication failed!");
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
