# Copyright 2024, Yeorz
# Inspired by Alexander Hass's script: https://www.hass.de/content/setup-microsoft-windows-or-iis-ssl-perfect-forward-secrecy-and-tls-12
#
# After running this script the computer only supports:
# - TLS 1.2
# - TLS 1.3
#
# Version 0.1, use at your own risk.


# Enable PFS by configuring the appropriate cipher suites
$protocols = @("TLS 1.0", "TLS 1.1", "TLS 1.2")
$ciphers = @(
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256',
    # Below are the only AEAD ciphers available on Windows 2012R2 and earlier.
    # - RSA certificates need below ciphers, but ECDSA certificates (EV) may not.
    # - We get penalty for not using AEAD suites with RSA certificates.
    'TLS_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_RSA_WITH_AES_256_CBC_SHA256',
    'TLS_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_RSA_WITH_AES_256_CBC_SHA',
    'TLS_RSA_WITH_AES_128_CBC_SHA'
)

# Disable Multi-Protocol Unified Hello
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'Multi-Protocol Unified Hello has been disabled.'

# Disable PCT 1.0
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'PCT 1.0 has been disabled.'
 
# Disable SSL 2.0 (PCI Compliance)
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'SSL 2.0 has been disabled.'
 
# Disable SSL 3.0 (PCI Compliance) and enable "Poodle" protection
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'SSL 3.0 has been disabled.'

# Disable TLS 1.0 for client and server SCHANNEL communications
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'Enabled' -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.0 has been disabled.'
 
# Add and Disable TLS 1.1 for client and server SCHANNEL communications
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.1 has been disabled.'
 
# Add and Enable TLS 1.2 for client and server SCHANNEL communications
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.2 has been enabled.'

if ([System.Version]$os.Version -lt [System.Version]'10.0.20348') {
  # Microsoft integrated TLS 1.3 as a preview in Windows 10, but this code seems to be unstable and is causing malfunctions.
  Remove-Item -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3' -Recurse -ErrorAction SilentlyContinue
  Write-Host 'TLS 1.3 has been disabled for Windows 10/2016/2019.'
} else {
  # Add and Enable TLS 1.3 for client and server SCHANNEL communications
  New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -name 'Enabled' -value 1 -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
  New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -name 'Enabled' -value 1 -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
  Write-Host 'TLS 1.3 has been enabled for Windows 11/2022 and later.'
}

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



# Disable insecure/weak ciphers.
$insecureCiphers = @(
  'DES 56/56',
  'NULL',
  'RC2 128/128',
  'RC2 40/128',
  'RC2 56/128',
  'RC4 40/128',
  'RC4 56/128',
  'RC4 64/128',
  'RC4 128/128',
  'Triple DES 168'
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

# Enable TLS 1.3 if the OS is Windows Server 2022

#Check the Windows version
$osVersion = [System.Environment]::OSVersion.Version
$isWindows2022 = $osVersion.Major -eq 10 -and $osVersion.Build -eq 20348    

if ($isWindows2022) {
    Write-Host "Windows Server 2022 detected. Enabling TLS 1.3..."
    
    $tls13KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3"
    $tls13Key = Get-Item -Path $tls13KeyPath -ErrorAction SilentlyContinue

    if ($tls13Key -eq $null) {
        New-Item -Path $tls13KeyPath -Force
    }

    Set-ItemProperty -Path $tls13KeyPath -Name "Enabled" -Value 1
}

# Continue with the rest of the script

Write-Host "Perfect Forward Secrecy (PFS) configuration with insecure protocols and ciphers disabled. You may need to restart the system for the changes to take effect."
