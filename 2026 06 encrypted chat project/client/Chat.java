package client;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.format.SignStyle;
import java.util.Arrays;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/*
    GenAI infos: except the default constructors and some standard helper function code(generated probably by vscode copilot by default on vscode), 0 lines of code in this file have been written by LLMs (for safety purposes)


    PROJECT:
    - end to end encrypted chat
    - one user is the host/server, the other user connect as a client
    - mutual certificates, ECDH, HKDF and AES/GCM.
    - goals: integrity/auth/forward secrecy/replay attack resistency

    plan:
    - integrity/privacy: AES-GCM with keys calculated using ECDH
    - auth: X.509 certificate (for the demo they are self signed)
    - forward secrecy: ECDH ephimeral session keys(with NIST approved elliptic curve)
    - replay attack prevention: sequence numbers inside AAD and IV(init vector) = seed + counter
*/
public class Chat{
    private final Config config;

    public Chat(Config c){
        this.config = c;
    }

    public static void main(String[] args) throws Exception{
        System.out.println("lorenzodeluca.it - end to end encrypted chat - default demo ;)");

        // config init
        Config config = Config.loadFromFile("config.properties");

        // end to end basic socket connection opening
        new Chat(config).startChat(config);
        
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
            KeysStorage keysStorage = KeysStorage.loadFromFile(config.keysPath, config.keysStoragePass,config.privateKeyPass,config.alias);
            
            //---step 2: create a safe channel inside the unsafe connection -> AES/GCM with sequence numbers
            SecureChannel secureChannel = handshake(socket, keysStorage, config.host.equalsIgnoreCase("host"));
        
            //---step 3:start chat inside secure channel
            //one thread for receiving and one thread for sending so that both can be done simultaneously
            ExecutorService exec = Executors.newFixedThreadPool(2);

            // Sender thread
            exec.submit(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.equalsIgnoreCase("/quit")) {
                            secureChannel.close();
                            break;
                        }
                        secureChannel.send(line);
                    }
                } catch (Exception e) {
                    System.err.println("Send error: " + e.getMessage());
                }
            });

            // Receiver thread
            exec.submit(() -> {
                try {
                    String msg = "";
                    while (true){
                        secureChannel.receive(msg);
                        if(msg==null) System.out.println("[peer] " + msg);
                        else break;
                    }; 
                } catch (Exception e) {
                    System.err.println("Receive error: " + e.getMessage());
                } finally {
                    secureChannel.close();
                }
            });
        }
    }

    //this method performs the ECDH handshake and returns the secure channel
    // secp256r1 = NIST P-256 elliptic curve
    private SecureChannel handshake(Socket socket, KeysStorage localKeys, boolean ishost) throws Exception{
        //ECDH key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ephPair = keyPairGenerator.generateKeyPair();

        //payload
        byte[] nonce = secureRandomBytes(32);
        byte[] ephPubEncoded = ephPair.getPublic().getEncoded();
        byte[] payloadToSign = concatByteArrays(ephPubEncoded, nonce);

        //sign
        String signatureAlg = signatureAlgFromKey(localKeys.privateKey);
        Signature signFunction = Signature.getInstance(signatureAlg);
        signFunction.initSign(localKeys.privateKey);
        signFunction.update(payloadToSign);
        byte[] signature = signFunction.sign();

        HandshakeMessage outgoing = new HandshakeMessage(localKeys.certificate.getEncoded(), nonce, ephPubEncoded, signature, signatureAlg);

        InputStream in = socket.getInputStream();
        OutputStream out = socket.getOutputStream();
        DataInputStream dataIn = new DataInputStream(new BufferedInputStream(in));
        DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));

        HandshakeMessage incoming;

        //sending payload
        // host sends first and the other client replies
        if(ishost){
            outgoing.writeTo(dataOut);
            dataOut.flush();
            incoming = HandshakeMessage.readFrom(dataIn);
        }else{
            incoming = HandshakeMessage.readFrom(dataIn);
            outgoing.writeTo(dataOut);
            dataOut.flush();
        }

        // certificates validation
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate peerCert = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(incoming.certificateBytes));
        peerCert.checkValidity();

        //signature validation 
        Signature verifier = Signature.getInstance(incoming.signatureAlgorithm);
        verifier.initVerify(peerCert);
        verifier.update(concatByteArrays(incoming.ephemeralPublicKey,incoming.nonce)); //pub key concatenated with nonce
        if(!verifier.verify(incoming.signature)){
            throw new GeneralSecurityException("[ERROR] Peer signature verification failed (STACCA STACCA CI STANNO TRACCIANDO)");
        }

        //rebuilding the EC public key from the X509 encoded form
        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey peerEphPublic = kf.generatePublic(new X509EncodedKeySpec(incoming.ephemeralPublicKey));

        // Compute ECDH shared secret
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(ephPair.getPrivate());
        keyAgreement.doPhase(peerEphPublic, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        byte[] info;
        if(ishost){
            info =concatByteArrays("SecureChat-v1".getBytes(StandardCharsets.UTF_8),nonce,incoming.nonce);
        }else{
            info =concatByteArrays("SecureChat-v1".getBytes(StandardCharsets.UTF_8),incoming.nonce, nonce);
        }

        //calculating keying material: each client has key+IV seed
        byte[] keyMaterial = hkdf(sharedSecret, null, info, 80);//32+8 + 32+8
        byte[] serverKeyBytes = Arrays.copyOfRange(keyMaterial, 0, 32);
        byte[] serverIvSeed = Arrays.copyOfRange(keyMaterial, 32, 40);
        byte[] clientKeyBytes = Arrays.copyOfRange(keyMaterial, 40, 72);
        byte[] clientIvSeed = Arrays.copyOfRange(keyMaterial, 72, 80);

        SecretKeySpec sendKey;
        SecretKeySpec recvKey;
        byte[] sendIvSeed;
        byte[] recvIvSeed;

        // Map derived material to local send/receive directions
        if (ishost) {
            sendKey = new SecretKeySpec(serverKeyBytes, "AES");
            sendIvSeed = serverIvSeed;
            recvKey = new SecretKeySpec(clientKeyBytes, "AES");
            recvIvSeed = clientIvSeed;
        } else {
            sendKey = new SecretKeySpec(clientKeyBytes, "AES");
            sendIvSeed = clientIvSeed;
            recvKey = new SecretKeySpec(serverKeyBytes, "AES");
            recvIvSeed = serverIvSeed;
        }

        System.out.println("[INFO] Handshake complete.");
        System.out.println("[INFO] Local signature algorithm: " + signatureAlg);
        System.out.println("[INFO] Peer certificate: " + peerCert.getSubjectX500Principal());
        System.out.println("[INFO] Symmetric channel: AES/GCM/NoPadding");

        return new SecureChannel(dataIn, dataOut, sendKey, recvKey, sendIvSeed, recvIvSeed);
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

        //secure channel helper methods

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

    //serializable handshake to exchange cert + nonce + epheemeral key
    private static final class HandshakeMessage{
        final byte[] certificateBytes;
        final byte[] nonce;
        final byte[] ephemeralPublicKey;
        final byte[] signature;
        final String signatureAlgorithm;

        public HandshakeMessage(byte[] certificateBytes, byte[] nonce, byte[] ephemeralPublicKey, byte[] signature, String signatureAlgorithm) {
            this.certificateBytes = certificateBytes;
            this.nonce = nonce;
            this.ephemeralPublicKey = ephemeralPublicKey;
            this.signature = signature;
            this.signatureAlgorithm = signatureAlgorithm;
        }

        void writeTo(DataOutputStream out) throws IOException{
            writeBytes(out, certificateBytes);
            writeBytes(out, nonce);
            writeBytes(out, ephemeralPublicKey);
            writeBytes(out, signature);
            out.writeUTF(signatureAlgorithm);
        }

        //receives data from the writeTo
        static HandshakeMessage readFrom(DataInputStream in) throws IOException{
            byte[] c = readBytes(in);
            byte[] n = readBytes(in);
            byte[] e = readBytes(in);
            byte[] s = readBytes(in);
            String a = in.readUTF();
            return new HandshakeMessage(c, n, e, s, a);
        }

        private static void  writeBytes(DataOutputStream out, byte[] data) throws IOException {
            out.writeInt(data.length);
            out.write(data);
        }

        private static byte[] readBytes(DataInputStream in) throws IOException{
            int len = in.readInt();
            byte[] b = new byte[len];
            in.readFully(b);
            return b;
        }

        
    }

    // crypto helper methods
    private static byte[] secureRandomBytes(int length) throws NoSuchAlgorithmException{
        byte[] data = new byte[length];
        SecureRandom.getInstanceStrong().nextBytes(data);
        return data;
    }

    private static byte[] concatByteArrays(byte[]... arrays){
        int len = 0;
        for(byte[] arr: arrays){
            len += arr.length;
        }
        byte[] result = new byte[len];
        int pos = 0;
        for(byte[] arr: arrays){
            System.arraycopy(arr, 0, result, pos, arr.length);
            pos+=arr.length;
        }
        return result;
    }

    //TODO update to sha-3 if decently compatible
    private static String signatureAlgFromKey(Key k){
        String alg = k.getAlgorithm();
        if("RSA".equalsIgnoreCase(alg)){
            return "SHA256withRSA";
        }else if("EC".equalsIgnoreCase(alg)){
            return "SHA256withECDSA";
        }
        throw new IllegalArgumentException("[ERROR] unsupported key algorithm:" + alg);
    }

    //HMAC -> for final eDH step
    //HMAC-based Extract-and-Expand Key Derivation standard Function
    private static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int len) throws Exception {
            if (salt == null) {
                salt = new byte[32];
            }
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);

            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            byte[] result = new byte[len];
            byte[] t = new byte[0];
            int pos = 0;
            int counter = 1;
            while (pos < len) {
                mac.reset();
                mac.init(new SecretKeySpec(prk, "HmacSHA256"));
                mac.update(t);
                if (info != null) {
                    mac.update(info);
                }
                mac.update((byte) counter++);
                t = mac.doFinal();
                int copyLen = Math.min(t.length, len - pos);
                System.arraycopy(t, 0, result, pos, copyLen);
                pos += copyLen;
            }
            return result;
        }

}