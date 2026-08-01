// Test client for the Java runner. One test per invocation; exit 0 ok, 1 fail.
// JSSE + PKIX as shipped in the JDK, so cells measure stock Java behavior.
import java.io.FileInputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

public class Client {
    public static void main(String[] args) {
        try {
            switch (args[0]) {
                case "parse" -> parse(args[1]);
                case "verify" -> verify(args[1], args[2], args[3]);
                case "handshake" -> handshake(args[1], args[2], Integer.parseInt(args[3]));
                default -> throw new IllegalArgumentException("usage: parse|verify|handshake");
            }
        } catch (Exception e) {
            System.out.println(e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(1);
        }
    }

    static X509Certificate load(String p) throws Exception {
        try (var in = new FileInputStream(p)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    static void parse(String leaf) throws Exception {
        var c = load(leaf);
        System.out.println("parsed: sigAlg=" + c.getSigAlgName()
                + " subject=" + c.getSubjectX500Principal());
    }

    static void verify(String root, String intermediate, String leaf) throws Exception {
        var anchor = new TrustAnchor(load(root), null);
        var certs = new ArrayList<X509Certificate>();
        certs.add(load(leaf));
        if (!intermediate.equals("-")) {
            certs.add(load(intermediate));
        }
        var path = CertificateFactory.getInstance("X.509").generateCertPath(certs);
        var params = new PKIXParameters(Set.of(anchor));
        params.setRevocationEnabled(false);
        CertPathValidator.getInstance("PKIX").validate(path, params);
        System.out.println("verify: OK");
    }

    static void handshake(String root, String host, int port) throws Exception {
        var ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setCertificateEntry("root", load(root));
        var tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        var ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        var sock = (SSLSocket) ctx.getSocketFactory()
                .createSocket(new Socket("127.0.0.1", port), host, port, true);
        var sp = sock.getSSLParameters();
        sp.setEndpointIdentificationAlgorithm("HTTPS");
        sp.setServerNames(List.of(new SNIHostName(host)));
        sock.setSSLParameters(sp);
        sock.startHandshake();
        System.out.println("handshake: OK " + sock.getSession().getProtocol()
                + " " + sock.getSession().getCipherSuite());
        sock.close();
    }
}
