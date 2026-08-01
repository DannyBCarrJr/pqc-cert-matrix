// Test client for the .NET runner. One test per invocation; exit 0 ok, 1 fail.
// .NET's managed X509Chain/SslStream on Linux route to OpenSSL, unlike the
// .NET Framework path on Windows which routes to CNG/schannel. Comparing this
// column against the schannel column isolates the platform, not the language.
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

// X509CertificateLoader is .NET 9+; on .NET 8 the constructor is the API.
static X509Certificate2 Load(string p) => new X509Certificate2(p);

try
{
    switch (args[0])
    {
        case "parse":
        {
            var c = Load(args[1]);
            string pub;
            try { _ = c.PublicKey.Oid.Value; pub = "oid=" + c.PublicKey.Oid.Value; }
            catch (Exception e) { pub = "opaque(" + e.GetType().Name + ")"; }
            Console.WriteLine($"parsed: sigAlgOid={c.SignatureAlgorithm.Value} {pub} subject={c.Subject}");
            break;
        }
        case "verify":
        {
            string root = args[1], inter = args[2], leaf = args[3];
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(Load(root));
            if (inter != "-") chain.ChainPolicy.ExtraStore.Add(Load(inter));
            bool ok = chain.Build(Load(leaf));
            var st = chain.ChainStatus.Select(s => s.Status.ToString()).ToArray();
            Console.WriteLine($"build={ok} chainStatus=[{string.Join(",", st)}]");
            if (!ok) return 1;
            break;
        }
        case "handshake":
        {
            string root = args[1], host = args[2];
            int port = int.Parse(args[3]);
            var trust = new X509Certificate2Collection(Load(root));
            using var tcp = new TcpClient("127.0.0.1", port);
            using var ssl = new SslStream(tcp.GetStream(), false);
            var opts = new SslClientAuthenticationOptions
            {
                TargetHost = host,
                CertificateChainPolicy = new X509ChainPolicy
                {
                    RevocationMode = X509RevocationMode.NoCheck,
                    TrustMode = X509ChainTrustMode.CustomRootTrust,
                },
            };
            opts.CertificateChainPolicy.CustomTrustStore.AddRange(trust);
            ssl.AuthenticateAsClient(opts);
            Console.WriteLine($"handshake: OK {ssl.SslProtocol} {ssl.NegotiatedCipherSuite}");
            break;
        }
        default:
            Console.WriteLine("usage: parse|verify|handshake");
            return 1;
    }
    return 0;
}
catch (Exception e)
{
    var msg = e.Message.Split('\n')[0];
    for (var i = e.InnerException; i is not null; i = i.InnerException)
        msg += " <- " + i.Message.Split('\n')[0];
    Console.WriteLine($"{e.GetType().Name}: {msg}");
    return 1;
}
