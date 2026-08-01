// Test client for the Node runner. One test per invocation; exit 0 ok, 1 fail.
// Public node:crypto / node:tls APIs only. Node has no path-validation API, so
// verify is a manual signature walk via X509Certificate.verify: weaker than
// PKIX (no constraints/validity policy checks) but it is what the platform
// offers, and it exercises the bundled OpenSSL's signature support.
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import tls from 'node:tls';

const [, , cmd, ...a] = process.argv;
const die = (m) => { console.log(m); process.exit(1); };

try {
  if (cmd === 'parse') {
    const c = new X509Certificate(readFileSync(a[0]));
    console.log(`parsed: subject=${c.subject.split('\n').join(',')}`);
  } else if (cmd === 'verify') {
    const [rootP, intP, leafP] = a;
    const root = new X509Certificate(readFileSync(rootP));
    const leaf = new X509Certificate(readFileSync(leafP));
    let ok;
    if (intP === '-') {
      ok = leaf.verify(root.publicKey);
    } else {
      const inter = new X509Certificate(readFileSync(intP));
      ok = leaf.verify(inter.publicKey) && inter.verify(root.publicKey);
    }
    if (!ok) die('verify: signature verification returned false');
    console.log('verify: OK (manual signature chain)');
  } else if (cmd === 'handshake') {
    const [rootP, host, port] = a;
    const s = tls.connect(
      { host: '127.0.0.1', port: +port, servername: host, ca: readFileSync(rootP) },
      () => {
        console.log('handshake: OK', s.getProtocol(), s.getCipher().name);
        s.end();
      },
    );
    s.on('error', (e) => die('handshake: ' + e.message));
  } else {
    die('usage: parse|verify|handshake');
  }
} catch (e) {
  die(`${e.constructor.name}: ${e.message}`);
}
