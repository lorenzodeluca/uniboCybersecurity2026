import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Chat{
    public static final class Config{
        static String configFilePath = "config.properties";
        static String mode;
        static String host;
        static int port;
        static String keysPath;
        static String keysStoragePass;
        static String privateKeyPass;
        static String alias; //username / key alias

        public Config(String mode, String host, int port, String keysPath, String keysStoragePass, String privateKeyPass, String alias) {
            this.mode = mode;
            this.host = host;
            this.port = port;
            this.keysPath = keysPath;
            this.keysStoragePass = keysStoragePass;
            this.privateKeyPass = privateKeyPass;
            this.alias = alias;
        }

        //method to load from the config file, default path: "config.properties"
        static Config loadFromFile(String path) throws IOException {
            Properties p = new Properties();
            InputStream in = new FileInputStream(configFilePath);
            try{
                p.load(in);
            }catch(Exception e){
                System.out.println("config error: cannot decode file");
            }
            
            return new Config(
                p.getProperty("mode"),
                p.getProperty("host", "127.0.0.1"),
                Integer.parseInt(p.getProperty("port","0")),
                p.getProperty("keysPath","keystore.p12"),
                p.getProperty("keysStoragePass"),
                p.getProperty("privateKeyPass"),
                p.getProperty("alias")
            );
        }
    }
    
    public static void main(String[] args) throws Exception{
    }
}