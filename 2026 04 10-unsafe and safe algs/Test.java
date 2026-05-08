import java.security.*;

public class Test {
    public static void main(String[] args) {
        for (Provider provider : Security.getProviders()) {
            System.out.println(provider.getName() + " - " + provider.getInfo());
        }
    }
}