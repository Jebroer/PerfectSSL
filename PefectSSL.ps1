# Enable PFS by configuring the appropriate cipher suites
$protocols = @("TLS 1.0", "TLS 1.1", "TLS 1.2")
$ciphers = @(
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
)

# Set registry keys to configure the cipher suites
$protocols | ForEach-Object {
    $protocolKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
    $protocolKey = Get-Item -Path $protocolKeyPath -ErrorAction SilentlyContinue

    if ($protocolKey -eq $null) {
        New-Item -Path $protocolKeyPath -Force
    }

    Set-ItemProperty -Path $protocolKeyPath -Name "DefaultSecureProtocols" -Value 0x00000a80
}

# Set the cipher suites
$protocols | ForEach-Object {
    $cipherKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\"
    $cipherKey = Get-Item -Path $cipherKeyPath -ErrorAction SilentlyContinue

    if ($cipherKey -eq $null) {
        New-Item -Path $cipherKeyPath -Force
    }

    Set-ItemProperty -Path $cipherKeyPath -Name "Functions" -Value $ciphers
}

# Disable insecure protocols
$insecureProtocols = @("SSL 2.0", "SSL 3.0")
$insecureProtocols | ForEach-Object {
    $protocolKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$_"
    $protocolKey = Get-Item -Path $protocolKeyPath -ErrorAction SilentlyContinue

    if ($protocolKey -ne $null) {
        Set-ItemProperty -Path $protocolKeyPath -Name "Enabled" -Value 0
    }
}

# Disable insecure cipher suites
$insecureCiphers = @(
    "SSL_RSA_WITH_RC4_128_SHA",
    "SSL_RSA_WITH_RC4_128_MD5",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
)

# Disable insecure cipher suites for each protocol
$protocols | ForEach-Object {
    $cipherKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\$_"
    $cipherKey = Get-Item -Path $cipherKeyPath -ErrorAction SilentlyContinue

    if ($cipherKey -ne $null) {
        $currentCiphers = Get-ItemProperty -Path $cipherKeyPath -Name "Functions"
        $newCiphers = $currentCiphers.Functions | Where-Object { $_ -notin $insecureCiphers }
        Set-ItemProperty -Path $cipherKeyPath -Name "Functions" -Value $newCiphers
    }
}

Write-Host "Perfect Forward Secrecy (PFS) configuration with insecure protocols and ciphers disabled. You may need to restart the system for the changes to take effect."
