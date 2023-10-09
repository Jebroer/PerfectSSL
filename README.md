# PerfectSSL Windows SSL/TLS Configuration Script

This PowerShell script is designed to configure SSL/TLS settings on Windows 11 and Windows Server 2019 for enhanced security, including enabling Perfect Forward Secrecy (PFS), disabling insecure cipher suites and protocols, and optionally enabling TLS 1.3 on Windows Server 2022.

## Usage Instructions

1. **Download the Script**: Download the PowerShell script from this repository [here](https://github.com/yeorz/PerfectSSL/releases/). 

2. **Run as Administrator**: Right-click the script file and choose "Run as Administrator" to ensure proper permissions for modifying the Windows registry.

3. **Configuration Steps**:
   - The script performs the following steps:

     - Enables Perfect Forward Secrecy (PFS) by configuring the appropriate cipher suites.
     - Disables insecure protocols like SSL 2.0 and SSL 3.0.
     - Disables insecure cipher suites such as RC4 and 3DES.
     - Optionally, enables TLS 1.3 if the OS is Windows Server 2022.

4. **Restart Your System**: After running the script, it's recommended to restart your Windows system for the changes to take effect.

## Caution

- Modifying the Windows registry can have a significant impact on system behavior. Use this script in a controlled and tested environment before applying it to a production system.

- Be aware that disabling certain cipher suites and protocols may affect compatibility with older clients. Ensure your environment can handle these changes.

- This script is provided as-is, and the user assumes all responsibility for its use.

- Always maintain backups and snapshots of your system before making registry changes to allow for recovery in case of issues.

## Disclaimer

This script is for educational and informational purposes only. It should not be considered a substitute for professional security advice and best practices. Use it at your own risk and discretion.

If you encounter any issues or have questions, feel free to [open an issue](https://github.com/Yeorz/PerfectSSL/issues) on this GitHub repository for assistance.
