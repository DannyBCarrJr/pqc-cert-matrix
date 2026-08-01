// Test client for the Bouncy Castle runner. One test per invocation; exit 0 ok / 1 fail.
//
// Why this column exists: our composite certificates are minted by BC 1.82 using
// its draft-07 composite OIDs. Every other client in the fleet belongs to a
// different OID family (or none), so "composite fails everywhere" was an artifact
// of the fleet composition, not a property of composite. This column puts the
// minting family's own verifier in the matrix, which is the control that makes the
// composite row honest. Cf. IACR ePrint 2026/1416: composite binds structurally
// within a family, but the families do not cross-verify.
//
// BC is registered as a JCA provider and requested by name, so PKIX path
// validation resolves composite and ML-DSA signatures through BC rather than SUN.
import java.io.FileInputStream;
import java.security.Security;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Set;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Client {
    static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            switch (args[0]) {
                case "parse" -> parse(args[1]);
                case "verify" -> verify(args[1], args[2], args[3]);
                // No TLS here: BC's JSSE provider is a separate stack from the
                // certificate-path question this column answers. The handshake
                // cell is reported as skip rather than guessed.
                default -> throw new IllegalArgumentException("usage: parse|verify");
            }
        } catch (Exception e) {
            String msg = e.getMessage() == null ? e.toString() : e.getMessage().split("\n")[0];
            for (Throwable c = e.getCause(); c != null; c = c.getCause()) {
                String m = c.getMessage();
                if (m != null) msg += " <- " + m.split("\n")[0];
            }
            System.out.println(e.getClass().getSimpleName() + ": " + msg);
            System.exit(1);
        }
    }

    static X509Certificate load(String p) throws Exception {
        try (var in = new FileInputStream(p)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509", BC)
                    .generateCertificate(in);
        }
    }

    static void parse(String leaf) throws Exception {
        var c = load(leaf);
        System.out.println("parsed: sigAlg=" + c.getSigAlgName()
                + " sigAlgOID=" + c.getSigAlgOID()
                + " subject=" + c.getSubjectX500Principal());
    }

    static void verify(String root, String intermediate, String leaf) throws Exception {
        var rootCert = load(root);
        var leafCert = load(leaf);

        // Self-signed row: the leaf IS the anchor. PKIX rejects an empty path, so
        // check the signature directly through BC, which is the meaningful test
        // (does BC validate its own composite signature?).
        if (rootCert.getSubjectX500Principal().equals(leafCert.getSubjectX500Principal())
                && intermediate.equals("-")) {
            leafCert.verify(rootCert.getPublicKey(), BC);
            System.out.println("verify: OK (self-signed, direct signature check via BC)");
            return;
        }

        var certs = new ArrayList<X509Certificate>();
        certs.add(leafCert);
        if (!intermediate.equals("-")) certs.add(load(intermediate));
        var path = CertificateFactory.getInstance("X.509", BC).generateCertPath(certs);
        var params = new PKIXParameters(Set.of(new TrustAnchor(rootCert, null)));
        params.setRevocationEnabled(false);
        CertPathValidator.getInstance("PKIX", BC).validate(path, params);
        System.out.println("verify: OK");
    }
}
