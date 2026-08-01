import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CompositeCert {
    static final String ALG = "MLDSA65-ECDSA-P256-SHA512";

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPair kp = KeyPairGenerator.getInstance(ALG, "BC").generateKeyPair();
        X500Principal name = new X500Principal("CN=PQM Matrix Composite Self-Signed");
        long now = 1785542400000L; // 2026-07-31T08:00:00Z, pinned for reproducibility

        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
            name, BigInteger.valueOf(0x504D4D32L),
            new Date(now), new Date(now + 30L * 86400 * 1000),
            name, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder(ALG).setProvider("BC").build(kp.getPrivate());
        X509CertificateHolder holder = b.build(signer);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
        cert.verify(kp.getPublic());
        System.out.println("self-verify with BC: OK");
        System.out.println("signature algorithm OID: " + cert.getSigAlgOID());
        byte[] der = cert.getEncoded();
        System.out.println("composite cert DER size: " + der.length + " bytes");

        try (FileOutputStream f = new FileOutputStream("chains/composite-selfsigned.crt.der")) {
            f.write(der);
        }
    }
}
