import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.HexFormat;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Exercises {

    /*
    * Treasure Hunt! Calculate the hash using SHA-256 algorithm on the string generated in this way:
    * "tutorato" + year of foundation of Bologna Calcio + 
    * secret word hidden into the slides + slide number with the comparison of the Linux penguin with ECB encryption
    * The string is all lowercase, all attached, without spaces.
    * Return the hash as byte array.
    */
    public static byte[] firstExercise(String password)throws NoSuchAlgorithmException {
        byte[] hash;
        // Stringa risultante: tutorato + 1909 + penguin + 32
        String messageString="tutorato1909penguin32";
        byte[] messageBytes = messageString.getBytes();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        ByteBuffer messageBuffer = ByteBuffer.wrap(messageBytes);
        md.update(messageBuffer);
        return md.digest();
    }

    /*
    * Create a PRNG using the SHA1PRNG algorithm, using as seed the result of the previous exercise.
    * Calculate after how many iterations the PRNG returns the integer value: 1328311680
    * The first iteration counts as 1, not as 0.
    * Return the number of iterations needed to get the desired value.
    */

    //since its an educational project i dont handle the NoSuchAlgorithmException...
    public static int secondExercise(byte[] seed)  throws NoSuchAlgorithmException{

        SecureRandom prng;
        int iterations=1;
        int goal = 1328311680;
        SecureRandom sr1 =SecureRandom.getInstance("SHA1PRNG");
        sr1.setSeed(seed);
        while(sr1.nextInt()!=goal){
            iterations++;
        }
        System.out.println(iterations);
        return iterations;

    }

    /*
     * A plaintext has been encrypted 3 times.
     * - The first time was encrypted using AES-GCM with additional data.
     * - The second time was encrypted using ChaCha20.
     * - The third time was encrypted using ECB.
     *
     * Ciphertext = E_ECB(E_ChaCha(E_GCM(plaintext))).
     * *
     * ⚠️ For the AES-GCM Encryption:
     * - The key is key1.
     * - The IV is the FIRST value obtained by nextBytes() using the same PRNG as in the previous exercise (16 bytes).
     * - MAC dimension is 128.
     * - The additional data is the string used in the first exercise, converted in bytes.
     *
     * ⚠️ For the ChaCha20 Encryption:
     * - The key is key2.
     * - The nonce is the SECOND value obtained by nextBytes() using the same PRNG as in the previous exercise (12 bytes).
     * - The counter is the output of the second exercise.
     * * ⚠️ For the ECB Encryption:
     * - The key is key1.
     * * Finally, return the plaintext.
    */
    public static String thirdExercise(byte[] seed, int counter, byte[] ciphertext, SecretKey key1, SecretKey key2, String password) throws Exception  {
        // Per decifrare, dobbiamo invertire l'ordine: ECB -> ChaCha20 -> GCM
        
        // Setup PRNG per recuperare IV e Nonce
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        
        byte[] iv = new byte[16];
        sr.nextBytes(iv); // Primo valore (per GCM)
        
        byte[] nonce = new byte[12];
        sr.nextBytes(nonce); // Secondo valore (per ChaCha20)

        // 1. Decifratura ECB (L'ultima operazione di cifratura è stata ECB)
        Cipher cypherEcb = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cypherEcb.init(Cipher.DECRYPT_MODE, key1);
        byte[] step1 = cypherEcb.doFinal(ciphertext);

        // 2. Decifratura ChaCha20
        Cipher cypherChacha20 = Cipher.getInstance("CHACHA20");
        ChaCha20ParameterSpec specChacha20 = new ChaCha20ParameterSpec(nonce, counter);
        cypherChacha20.init(Cipher.DECRYPT_MODE, key2, specChacha20);
        byte[] step2 = cypherChacha20.doFinal(step1);

        // 3. Decifratura AES-GCM
        Cipher cypherAesgcm = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec specGcm = new GCMParameterSpec(128, iv);
        cypherAesgcm.init(Cipher.DECRYPT_MODE, key1, specGcm);
        // Aggiunta dati addizionali (AAD) richiesti
        String aad = "tutorato1909penguin32";
        cypherAesgcm.updateAAD(aad.getBytes());
        
        byte[] plaintextBytes = cypherAesgcm.doFinal(step2);
        String finalPlaintext = new String(plaintextBytes);

        return finalPlaintext;
    }

    /*
     * Calculate the MAC of the ciphertext and check if it is valid.
     * Mac is calculated using HMAC-SHA256.
     * The key is macKey.
     * Return true if the MAC is valid, false otherwise.
     */
    public static boolean fourthExercise(SecretKey macKey, byte[] ciphertext, byte[] mac) {

        boolean isMacValid = false;
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(macKey);
            byte[] computedMac = hmac.doFinal(ciphertext);
            
            // Comparazione sicura
            isMacValid = MessageDigest.isEqual(computedMac, mac);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return isMacValid;
    }

    /*
    * Encrypt again the message and save it into a file using CipherOutputStream class.
    * Use the encryption algorithm you prefer.
    */
    public static void fifthExercise(SecretKey key, String filename, String message) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            try (FileOutputStream fos = new FileOutputStream(filename);
                 CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
                cos.write(message.getBytes());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return;
    }

    public static void main(String[] args) throws Exception {

        byte[] keyBytes1 = HexFormat.of().parseHex("15c02ffef35dd17d0084b17a8ae448046f8a31fe89e0e253216b795c44216252");
        SecretKey key1 = new javax.crypto.spec.SecretKeySpec(keyBytes1, "AES");
        byte[] keyBytes2 = HexFormat.of().parseHex("bed7f74d35e479aec9073fda0845cdfd49c54637d35ea4ab9f0c0a0566c0bb04");
        SecretKey key2 = new javax.crypto.spec.SecretKeySpec(keyBytes2, "ChaCha20");
        byte[] macKeyBytes = HexFormat.of().parseHex("5bfa7047a4c034d90ac98f2c62c0f5bb7fbcfd24f2f8917a36f01dd6085e16c4");
        SecretKey macKey = new javax.crypto.spec.SecretKeySpec(macKeyBytes, "HmacSHA256");

        byte[] ciphertext = HexFormat.of().parseHex("529b43613598c1b9db5d3f87887bdee6b949ce42ca3d154e6209593f5eed8ce2658c71192916499b22222fbf56e8e3568a80f7b6a9bbc020cd8d9cadddd8e007e1bdc6cc96b6bd4aa7cbb4903f416abd");
        byte[] mac = HexFormat.of().parseHex("2a36ab7dfc0d3cf25796127c9a5dd4f308ed803b7daadad47d14a0ef57a6ee02");

        /* FIRST EXERCISE */
        String password = "tutorato1909penguin32";   // Password trovata dalle slide
        byte[] seed = firstExercise(password);

        /* SECOND EXERCISE */
        int counter = secondExercise(seed);

        /* THIRD EXERCISE */
        String plaintext = thirdExercise(seed, counter, ciphertext, key1, key2, password);
        System.out.println("Plaintext: " + plaintext);

        /* FOURTH EXERCISE */
        boolean isMacValid;
        isMacValid = fourthExercise(macKey, ciphertext, mac);
        System.out.println("Is the MAC valid? " + isMacValid);

        /* FIFTH EXERCISE */
        fifthExercise(key1, "risultato.enc", plaintext);  // Nome file a scelta
        System.out.println("File created with the encryted message.");

        return;

    }
    
}