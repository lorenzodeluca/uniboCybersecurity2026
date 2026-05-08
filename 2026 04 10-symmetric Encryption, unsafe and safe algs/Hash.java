import java.security.*;
import java.util.HexFormat;

public class Hash {

    public static void main(String[] args) {

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update("Sicurezza ".getBytes());
            md.update("dell'".getBytes());
            md.update("Informazione".getBytes());

            byte[] digest = md.digest();
            System.out.println("Digest: " + HexFormat.of().formatHex(digest));

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        /*
        try{
            String message = "Sicurezza dell'Informazione";
            byte[] messageBytes = message.getBytes();
            ByteBuffer buf = ByteBuffer.wrap(messageBytes);

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(buf);

            byte[] digest = md.digest();
            String hexDigest = HexFormat.of().formatHex(digest);

            System.out.println("Message: " + message);
            System.out.println("Digest: " + hexDigest);
        }catch(NoSuchAlgorithmException e){
            System.out.println("Algorithm not found: " + e.getMessage());
        }
        */

    }
}