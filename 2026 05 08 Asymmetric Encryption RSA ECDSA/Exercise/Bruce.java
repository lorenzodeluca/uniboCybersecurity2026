import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;

/*
    Simulates Bruce's side of the communication. He has a certificate, exposing his public key,
    and wants to securely exchange messages with Alice.
    Nothing in this code should be modified.
*/
public class Bruce {

    private static final String PRIV_B64 = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgr6qwtwFzcyQaWtzw\r\n" + //
                "OWAWyQdT3H7Xs/Mg16U+VVVicH2hRANCAATSgl/GG/8RG5Kk8WHo9CiFek54cW0l\r\n" + //
                "lbOMLBt0BTR7YNkKu15Q8mlZr5F+q/5QqMS4tNPWveRfu/efFblxu/lH";
    
    private static final String CERT_B64 = "MIICnzCCAkWgAwIBAgIUEMFgWWpkP2GDwKC8/6mMEUgygYIwCgYIKoZIzj0EAwIw\r\n" + //
                "gaQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApOZXcgSmVyc2V5MRQwEgYDVQQHDAtH\r\n" + //
                "b3RoYW0gQ2l0eTEaMBgGA1UECgwRV2F5bmUgRW50ZXJwcmlzZXMxFjAUBgNVBAsM\r\n" + //
                "DVNlY3JldFByb2plY3QxFDASBgNVBAMMC0JydWNlIFdheW5lMSAwHgYJKoZIhvcN\r\n" + //
                "AQkBFhFiYXRsb3ZlckByaWNoLmNvbTAeFw0yNjA0MjgxMDEyMjVaFw0yNzA0Mjgx\r\n" + //
                "MDEyMjVaMIGkMQswCQYDVQQGEwJVUzETMBEGA1UECAwKTmV3IEplcnNleTEUMBIG\r\n" + //
                "A1UEBwwLR290aGFtIENpdHkxGjAYBgNVBAoMEVdheW5lIEVudGVycHJpc2VzMRYw\r\n" + //
                "FAYDVQQLDA1TZWNyZXRQcm9qZWN0MRQwEgYDVQQDDAtCcnVjZSBXYXluZTEgMB4G\r\n" + //
                "CSqGSIb3DQEJARYRYmF0bG92ZXJAcmljaC5jb20wWTATBgcqhkjOPQIBBggqhkjO\r\n" + //
                "PQMBBwNCAATSgl/GG/8RG5Kk8WHo9CiFek54cW0llbOMLBt0BTR7YNkKu15Q8mlZ\r\n" + //
                "r5F+q/5QqMS4tNPWveRfu/efFblxu/lHo1MwUTAdBgNVHQ4EFgQU0cMrgRvVf8YU\r\n" + //
                "pGKZstJd2nW0EcowHwYDVR0jBBgwFoAU0cMrgRvVf8YUpGKZstJd2nW0EcowDwYD\r\n" + //
                "VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiAkdOuP0Dp6HiF1Q+ldAeti\r\n" + //
                "dQoQgBqPtXUCqIw8/1jA8gIhALS4ub6zQD/L3P00IHfMaZtX8KtxEv5qfUeiKEIr\r\n" + //
                "ukPD";

    public static final PrivateKey PRIVATE_KEY = initPrivateKey();
    public static final X509Certificate CERTIFICATE = initCertificate();
    public static final PublicKey PUBLIC_KEY = CERTIFICATE.getPublicKey();

    public PublicKey alicePubKey;
    private SecretKey symmetricKey;

    private static PrivateKey initPrivateKey() {
        try {
            byte[] data = Base64.getMimeDecoder().decode(PRIV_B64);
            return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(data));
        } catch (Exception e) { throw new RuntimeException("Error PrivKey", e); }
    }

    private static X509Certificate initCertificate() {
        try {
            byte[] data = Base64.getMimeDecoder().decode(CERT_B64);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(data));
        } catch (Exception e) { throw new RuntimeException("Error Cert", e); }
    }

    // Get Alice's public key, verify signature, and save it for ECDH
    public void sendPublicKey(PublicKey alicePub, byte[] signature) {
        try {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initVerify(alicePub);
            s.update(alicePub.getEncoded());
            if (!s.verify(signature)) {
                System.out.println("Invalid signature from Alice.");
                return;
            }
            this.alicePubKey = alicePub;
            getSecretKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Simulates the ECDH key agreement and derives the symmetric key
    // to use during conversation.
    private void getSecretKey() {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(PRIVATE_KEY);
            ka.doPhase(alicePubKey, true);
            byte[] sharedSecret = ka.generateSecret();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] secretHash = md.digest(sharedSecret);
            this.symmetricKey = new SecretKeySpec(secretHash, "AES");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Get the encrypted message from Bruce
    public byte[] getMessage() {
        byte[] message = "It's not who I am underneath... but what I do that defines me.".getBytes();
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            String dn = CERTIFICATE.getSubjectX500Principal().getName();
            byte[] ou = extractOrganizationalUnitName(dn).getBytes();
            sr.setSeed(ou);
            byte[] iv = new byte[16];
            sr.nextBytes(iv);
            GCMParameterSpec params = new GCMParameterSpec(128, iv);
            c.init(Cipher.ENCRYPT_MODE, symmetricKey, params);
            return c.doFinal(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // Receive the encrypted message from Alice, verifies and decrypts it
    public boolean sendMessage(byte[] ciphertext, GCMParameterSpec params) {
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, symmetricKey, params);
            byte[] decrypted = c.doFinal(ciphertext);
            String decryptedMessage = new String(decrypted);
            System.out.println("Decrypted message from Alice: " + decryptedMessage);
            return true;
        } catch (Exception e) {
            System.out.println("Failed to decrypt message from Alice.");
            return false;
        }
    }

    // Helper function to extract the OU field from the certificate's subject DN, used for IV generation
    private static String extractOrganizationalUnitName(String dn) {
        for (String entry : dn.split(",")) {
            if (entry.trim().startsWith("OU=")) {
                return entry.trim().substring(3);
            }
        }
        return "";
    }
    
}