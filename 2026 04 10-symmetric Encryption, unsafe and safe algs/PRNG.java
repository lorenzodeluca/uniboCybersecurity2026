import java.security.*;

public class PRNG {

    public static void main(String[] args) {

        SecureRandom sr1, sr2;
        try{
            sr1 = SecureRandom.getInstance("SHA1PRNG");
            sr2 = SecureRandom.getInstance("SHA1PRNG");
        }catch(NoSuchAlgorithmException e){
            System.out.println("Strong algorithm not found: " + e.getMessage());
            return;
        }

        sr1.setSeed(1);
        sr1.setSeed(2);
        sr2.setSeed(3);

        System.out.println("1 ("+sr1.getAlgorithm()+"): " + Integer.toString(sr1.nextInt()));
        System.out.println("2 ("+sr2.getAlgorithm()+"): " + Integer.toString(sr2.nextInt()));

    }
}