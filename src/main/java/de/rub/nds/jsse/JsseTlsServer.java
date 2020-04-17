package de.rub.nds.jsse;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import javax.net.ssl.SSLServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.*;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

public class JsseTlsServer {

    private static final Logger LOGGER = LogManager.getLogger(JsseTlsServer.class);
    private String[] cipherSuites = null;
    private final SSLContext sslContext;
    private ServerSocket serverSocket;
    private boolean shutdown;
    boolean closed = true;
    private final int port;

    /**
     * Very dirty but ok for testing purposes
     */
    private volatile boolean initialized;

    public JsseTlsServer(KeyStore serverKeyStore, KeyStore caKeyStore, String password, String protocol, int port) throws KeyStoreException,
            NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException, NoSuchProviderException {

        this.port = port;

        KeyManagerFactory serverKmf = KeyManagerFactory.getInstance("PKIX", "BCJSSE");
        serverKmf.init(serverKeyStore, password.toCharArray());
        KeyManager[] keyManagers = serverKmf.getKeyManagers();

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX", "BCJSSE");
        trustManagerFactory.init(caKeyStore);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

        sslContext = SSLContext.getInstance(protocol, "BCJSSE");
        sslContext.init(keyManagers, trustManagers,  new SecureRandom());

        cipherSuites = sslContext.getServerSocketFactory().getSupportedCipherSuites();

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Provider: " + sslContext.getProvider());
            LOGGER.debug("Supported cipher suites ("
                    + sslContext.getServerSocketFactory().getSupportedCipherSuites().length + ")");
            for (String c : sslContext.getServerSocketFactory().getSupportedCipherSuites()) {
                LOGGER.debug(" " + c);
            }
        }
    }
    
    public static void main(String[] args) throws Exception {
        System.setProperty("java.security.debug", "ssl");
        String serverKsPath, caKsPath = null;
        String password = null;
        int port;
        boolean useBouncyCastleProvider = false;


        switch (args.length) {
            case 5:
            case 4:
                port = Integer.parseInt(args[0]);
                serverKsPath = args[1];
                caKsPath = args[2];
                password = args[3];
                if(args.length == 5 && args[4].equalsIgnoreCase("BC")) {
                    useBouncyCastleProvider = true;
                }
                break;
            default:
                System.out.println("Usage (run with): java -jar [name].jar [port] [server-jks-path] "
                        + "[ca-jks-path] [password]");
                return;
        }

        if(useBouncyCastleProvider) {
            Provider provider = new BouncyCastleJsseProvider();
            Security.addProvider(provider);
        }

        KeyStore serverKs = KeyStore.getInstance("JKS");
        serverKs.load(new FileInputStream(serverKsPath), password.toCharArray());

        KeyStore caKs = KeyStore.getInstance("JKS");
        caKs.load(new FileInputStream(caKsPath), password.toCharArray());

        JsseTlsServer tlsServer = new JsseTlsServer(serverKs, caKs, password, "TLS", port);
        tlsServer.start();
    }

    public void start() {
        try {
            preSetup();
            closed = false;
            ((SSLServerSocket) serverSocket).setNeedClientAuth(true);
            while (!shutdown) {
                try {
                    LOGGER.info("Listening on port " + port + "...\n");
                    final Socket socket = serverSocket.accept();
                    if (socket != null) {
                        ConnectionHandler ch = new ConnectionHandler(socket);
                        Thread t = new Thread(ch);
                        t.start();
                    }

                } catch (IOException ex) {
                    LOGGER.debug(ex.getLocalizedMessage(), ex);
                }
            }
            closed = true;
        } catch (IOException ex) {
            LOGGER.debug(ex.getLocalizedMessage(), ex);
        } finally {
            try {
                if (serverSocket != null && !serverSocket.isClosed()) {
                    serverSocket.close();
                    serverSocket = null;
                }
            } catch (IOException e) {
                LOGGER.debug(e);
            }
            LOGGER.info("Shutdown complete");
        }
    }

    private void preSetup() throws SocketException, IOException {
        SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();

        serverSocket = serverSocketFactory.createServerSocket(port);
        serverSocket.setReuseAddress(true);
        // TODO:
        // if (cipherSuites != null) {
        // ((SSLServerSocket)
        // serverSocket).setEnabledCipherSuites(cipherSuites);
        // }
        LOGGER.debug("Presetup successful");
        initialized = true;
    }

    public void shutdown() {
        this.shutdown = true;
        LOGGER.debug("Shutdown signal received");
        try {
            if (!serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public String[] getCipherSuites() {
        return cipherSuites;
    }

    public boolean isInitialized() {
        return initialized;
    }

    public int getPort() {
        if (serverSocket != null) {
            return serverSocket.getLocalPort();
        } else {
            return port;
        }
    }
}
