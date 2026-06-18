// except the default constructors(generated probably by vscode copilot by default on vscode), 0 lines of code in this file have been written by LLMs (for safety purposes)

import java.io.Closeable;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/*
    PROJECT:
    - end to end encrypted chat
    - one user is the host/server, the other user connect as a client
    - mutual certificates, ECDH, HKDF and AES/GCM.
    - goals: integrity/auth/forward secrecy/replay attack resistency

    plan:
    - integrity/privacy: AES-GCM with keys calculated using ECDH
    - auth: X.509 certificate (for the demo they are self signed)
    - forward secrecy: ECDH ephimeral session keys
    - replay attack prevention: sequence numbers inside AAD and IV(init vector) = seed + counter
*/
public class Chat{
    private final Config config;

    public Chat(Config c){
        this.config = c;
    }

    

    // open the socket in host mode or client mode
    private Socket connect() throws IOException{
        if(config.mode.equalsIgnoreCase("host")){
            ServerSocket socket = new ServerSocket(config.port);
            System.out.println("[INFO] listening on 0.0.0.0:" +  socket.getLocalPort());
            return socket.accept();
        }else if(config.mode.equalsIgnoreCase("client")){
            Socket socket = new Socket(config.host,config.port);
            System.out.println("[INFO] listening on " +  config.host + ":" + config.port);
            return socket;
        }
        throw new IllegalArgumentException("[ERROR] invalid mode -> mode: host/client");
    }

    private void startChat(Config config) throws Exception{
        try(Socket socket = connect()){
            System.out.println("[INFO] connected with " +  socket.getRemoteSocketAddress());
            System.out.println("[INFO] ---STEP 1 completed: unsafe connection achieved---");

            //handshake 
            //alias = key alias
            //TODO (maybe): ask user to insert keys manually at every app launch and remove them from config.
            // or ask the user for passwords if they are not included in the config file
            //maybe it should ask the users for all the configs that are not included in the file 
            KeysStorage infosForHandshake = KeysStorage.loadFromFile(config.keysPath, config.keysStoragePass,config.privateKeyPass,config.alias);
            
            //---step 2: create a safe channel inside the unsafe connection -> AES/GCM with sequence numbers
            SecureChannel 
        }
    }
    
    public static void main(String[] args) throws Exception{
        System.out.println("lorenzodeluca.it - end to end encrypted chat - default demo ;)");

        // config init
        Config config = Config.loadFromFile("config.properties");

        // end to end basic socket connection opening
        
    }

    //im saving all the data needed for this app in different classes because i plan to reuse the code as much as possible for both the client and host

    //config file rappresentation
    private static final class Config{
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

    // keys wallet for handshake, loading done from file
    private static final class KeysStorage{
        final PrivateKey privateKey;
        final X509Certificate certificate;

        public KeysStorage(PrivateKey privateKey, X509Certificate certificate) {
            this.privateKey = privateKey;
            this.certificate = certificate;
        }

        static KeysStorage loadFromFile(String path, String storePass, String keyPassword, String alias) throws Exception{
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try(InputStream is = new FileInputStream(path)){
                ks.load(is, storePass.toCharArray());
            }
            PrivateKey key = (PrivateKey)ks.getKey(alias, keyPassword.toCharArray());
            Certificate cert = ks.getCertificate(alias);
            return new KeysStorage(key, (X509Certificate)cert);
        }
    }

    // AES/GCM with sequence numbers
    private static final class SecureChannel implements Closeable{
        //in
        private final DataInputStream in;
        private final SecretKey recvKey;
        private final byte[] recvSeed;
        private final AtomicLong recvCounter = new AtomicLong(0);

        //out
        private final DataOutputStream out;
        private final SecretKey sendKey;
        private final byte[] sendSeed;
        private final AtomicLong sendCounter = new AtomicLong(0);

        //channel status
        private volatile boolean closed = false;



        SecureChannel(DataInputStream in, DataOutputStream out, SecretKey sendKey, SecretKey recvKey, byte[] sendSeed, byte[] recvSeed){
              this.in = in;
              this.out = out;
              this.sendKey = sendKey;
              this.recvKey = recvKey;
              this.sendSeed = sendSeed;
              this.recvSeed = recvSeed;
        }

        //this method sends a message using AES/GCM + sequence number + UTF-8 charset
        public synchronized void send(String message) throws Exception{
            //preparing ciphertext
            if(closed)return;
            long counter = sendCounter.incrementAndGet(); //atomic counter
            byte[] iv = buildIV(sendSeed, counter);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, sendKey, new GCMParameterSpec(128, iv));
            cipher.updateAAD( longToBytes(counter) );
            byte[] ciphertext = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

            //sending ciphertext
            out.writeLong(counter);
            out.writeInt(ciphertext.length);
            out.write(ciphertext);
            out.flush();
        }

        //TODO check the anti replay mechanism
        public String receive(String message) throws Exception{
            if(closed)return null; //returns null if channel closed / EOF

            try{
                long counter = in.readLong();
                int len = in.readInt();
                byte[] ciphertext = in.readNBytes(len);
                recvCounter.updateAndGet(prev -> Math.max(prev, counter)); //TODO check if there is a risk that this line trash valid messages
                byte[] iv = buildIV(recvSeed, counter);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE,recvKey,new GCMParameterSpec(128, iv));
                cipher.updateAAD(longToBytes(counter));
                byte[] plaintext = cipher.doFinal(ciphertext);
                return new String(plaintext, StandardCharsets.UTF_8);
            }catch(EOFException eof){
                close();
                return null;
            }
        }

        @Override 
        public synchronized void close(){
            if(closed) return;
            closed = true;
            try{ in.close(); }catch(IOException ignored){}
            try{ out.close(); }catch(IOException ignored){}
        }

        //helper methods

        //it compose the init vector
        // IV = seed || counter
        private static byte[] buildIV(byte[] seed, long counter){
            ByteBuffer bb = ByteBuffer.allocate(12);
            bb.put(seed); //8bytes
            bb.putInt((int)counter);//4bytes
            return bb.array(); //total: 12bytes
        }

        //longToBytes
        private static byte[] longToBytes(long value){
            return ByteBuffer.allocate(8).putLong(value).array();
        }
    }

}