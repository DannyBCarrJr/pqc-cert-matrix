import java.security.Provider;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EnumerateBC {
    public static void main(String[] args) {
        Provider bc = new BouncyCastleProvider();
        Security.addProvider(bc);
        bc.getServices().stream()
            .filter(s -> {
                String a = s.getAlgorithm().toUpperCase();
                return a.contains("COMPOSITE") || a.contains("MLDSA") || a.contains("ML-DSA");
            })
            .map(s -> s.getType() + " : " + s.getAlgorithm())
            .sorted()
            .distinct()
            .forEach(System.out::println);
    }
}
