# schannel / CNG test client (Windows PowerShell 5.1, .NET Framework).
# One test per invocation. Prints a result line, exits 0 ok / 1 fail.
# This is the only runner outside WSL: it measures the Windows crypto stack.
param(
  [Parameter(Mandatory)][string]$Test,
  [string]$Root, [string]$Int = '-', [string]$Leaf,
  [string]$ConnectIp, [string]$Host2, [int]$Port
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security | Out-Null

# Guarantee a result line + nonzero exit even for native method-invocation
# exceptions that -File otherwise swallows (seen with self-signed composite certs).
trap {
  $m = $_.Exception.Message
  if (-not $m) { $m = "HResult 0x" + ('{0:X}' -f $_.Exception.HResult) }
  Write-Output ("trapped " + $_.Exception.GetType().Name + ": " + $m.Split([char]10)[0])
  exit 1
}

function New-Cert([string]$p) {
  New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $p
}

try {
  switch ($Test) {
    'parse' {
      $c = New-Cert $Leaf
      $pub = 'n/a'
      try { $null = $c.PublicKey.Key; $pub = 'accessible' }
      catch { $pub = 'opaque(' + $_.Exception.Message.Split([char]10)[0] + ')' }
      Write-Output ("parsed: sigAlgOid=" + $c.SignatureAlgorithm.Value + " pubkey=" + $pub + " subject=" + $c.Subject)
      exit 0
    }
    'verify' {
      $leafC = New-Cert $Leaf
      $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
      $chain.ChainPolicy.RevocationMode = 'NoCheck'
      # No CustomTrustStore in .NET Framework: seed ExtraStore with our root+int and
      # allow the unknown CA, so UntrustedRoot is the only *expected* status. Any
      # signature/algorithm status (e.g. NotSignatureValid) means CNG could not
      # cryptographically validate the chain.
      $chain.ChainPolicy.VerificationFlags = 'AllowUnknownCertificateAuthority'
      if ($Int -ne '-') { [void]$chain.ChainPolicy.ExtraStore.Add((New-Cert $Int)) }
      [void]$chain.ChainPolicy.ExtraStore.Add((New-Cert $Root))
      $built = $chain.Build($leafC)
      $st = @($chain.ChainStatus | ForEach-Object { $_.Status.ToString() })
      Write-Output ("build=" + $built + " chainStatus=[" + ($st -join ',') + "]")
      $benign = @('UntrustedRoot','OfflineRevocation','RevocationStatusUnknown','NoError')
      $bad = @($st | Where-Object { $benign -notcontains $_ })
      if ($bad.Count -gt 0) { exit 1 } else { exit 0 }
    }
    'handshake' {
      $script:cbInfo = ''
      $cb = [System.Net.Security.RemoteCertificateValidationCallback]{
        param($snd, $cert, $ch, $errors)
        # Accept so private-root trust does not confound the measurement; the
        # protocol-level signature (ML-DSA CertificateVerify) is validated by
        # schannel BEFORE this fires, so a schannel that lacks ML-DSA throws
        # in AuthenticateAsClient and never reaches here.
        $script:cbInfo = 'sslPolicyErrors=' + $errors
        return $true
      }
      $tcp = New-Object System.Net.Sockets.TcpClient
      $tcp.Connect($ConnectIp, $Port)
      $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $cb)
      $ssl.AuthenticateAsClient($Host2)
      Write-Output ("handshake: OK proto=" + $ssl.SslProtocol + " cipher=" + $ssl.CipherAlgorithm + " " + $script:cbInfo)
      $ssl.Close(); $tcp.Close()
      exit 0
    }
    default { Write-Output "usage: -Test parse|verify|handshake"; exit 1 }
  }
} catch {
  $base = $_.Exception.Message
  if (-not $base) { $base = "HResult 0x" + ('{0:X}' -f $_.Exception.HResult) }
  $msg = $base.Split([char]10)[0]
  $inner = $_.Exception.InnerException
  while ($inner) {
    $msg += ' <- ' + $inner.Message.Split([char]10)[0]
    if ($inner -is [System.ComponentModel.Win32Exception]) {
      $msg += ' [Win32 0x' + ('{0:X}' -f $inner.NativeErrorCode) + ']'
    }
    $inner = $inner.InnerException
  }
  Write-Output ($_.Exception.GetType().Name + ": " + $msg)
  exit 1
}
