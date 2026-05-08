import java.io.FileInputStream;
import java.security.PublicKey;
import java.security.cert.*;

public class CertificateExample {
    public static void main(String[] args) {
        try {
            FileInputStream fis = new FileInputStream("./Asymmetric/myCert.pem");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);

            PublicKey publicKey = cert.getPublicKey();
            //System.out.println("Public Key: " + publicKey);

            cert.verify(publicKey);
            System.out.println("Certificate is valid.");

            cert.checkValidity();
            System.out.println("Certificate is within its validity period.");

            System.out.println("Certificate Subject: " + cert.getSubjectX500Principal());
            System.out.println("Certificate Serial Number: " + cert.getSerialNumber()); 
            System.out.println("Certificate Issuer: " + cert.getIssuerX500Principal());           

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}