// TLS 1.3 server on Bouncy Castle's JSSE (bctls). Isolation control for the
// schannel column: every Phase 2 handshake ran against OpenSSL s_server, so a
// second, unrelated server implementation is required before the ML-DSA
// handshake failure can be attributed to the client. bctls 1.82 carries the
// ML-DSA signature schemes as non-draft constants (mldsa44/65/87 = 0x0904-0x0906).
//
// Server-side failure output is part of the measurement: when a client offers
// no signature scheme compatible with the server key, BCJSSE names that
// condition instead of masking it, and that text lands in the evidence log.
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.OutputStream;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public class Server {
    public static void main(String[] args) throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);
        int port = Integer.parseInt(args[0]);

        PrivateKey key;
        try (PEMParser pem = new PEMParser(new FileReader(args[1]))) {
            key = new JcaPEMKeyConverter().setProvider("BC")
                    .getPrivateKey((PrivateKeyInfo) pem.readObject());
        }
        var certs = new ArrayList<X509Certificate>();
        var cf = CertificateFactory.getInstance("X.509", "BC");
        for (int i = 2; i < args.length; i++) {
            try (var in = new FileInputStream(args[i])) {
                certs.add((X509Certificate) cf.generateCertificate(in));
            }
        }
        var chain = certs.toArray(new X509Certificate[0]);

        SSLContext ctx = SSLContext.getInstance("TLSv1.3", "BCJSSE");
        ctx.init(new KeyManager[]{new FixedKeyManager(key, chain)}, null, new SecureRandom());
        try (SSLServerSocket ss =
                (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(port)) {
            System.out.println("bctls-server: listening :" + port
                    + " key=" + key.getAlgorithm()
                    + " leafSig=" + chain[0].getSigAlgName()
                    + " chainLen=" + chain.length);
            while (true) {
                serve((SSLSocket) ss.accept());
            }
        }
    }

    static void serve(SSLSocket s) {
        String peer = s.getInetAddress().getHostAddress();
        try (s) {
            s.startHandshake();
            var sess = s.getSession();
            System.out.println("handshake OK peer=" + peer
                    + " proto=" + sess.getProtocol() + " cipher=" + sess.getCipherSuite());
            OutputStream out = s.getOutputStream();
            out.write("hello from bctls\n".getBytes());
            out.flush();
        } catch (Exception e) {
            String msg = e.getMessage() == null ? e.toString() : e.getMessage().split("\n")[0];
            System.out.println("handshake FAIL peer=" + peer + " "
                    + e.getClass().getSimpleName() + ": " + msg);
        }
    }

    // In-memory key manager: sidesteps JDK keystores, which cannot encode ML-DSA
    // private keys on JDK 21 (the JDK grows ML-DSA at 24).
    static class FixedKeyManager extends X509ExtendedKeyManager {
        final PrivateKey key;
        final X509Certificate[] chain;
        FixedKeyManager(PrivateKey k, X509Certificate[] c) { key = k; chain = c; }
        public String chooseServerAlias(String kt, Principal[] iss, Socket sock) { return "srv"; }
        public String chooseEngineServerAlias(String kt, Principal[] iss, SSLEngine e) { return "srv"; }
        public String[] getServerAliases(String kt, Principal[] iss) { return new String[]{"srv"}; }
        public X509Certificate[] getCertificateChain(String a) { return chain; }
        public PrivateKey getPrivateKey(String a) { return key; }
        public String chooseClientAlias(String[] kt, Principal[] iss, Socket sock) { return null; }
        public String chooseEngineClientAlias(String[] kt, Principal[] iss, SSLEngine e) { return null; }
        public String[] getClientAliases(String kt, Principal[] iss) { return null; }
    }
}
