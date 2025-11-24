# windows-system-hardening-script
A fully automated Windows 10/11 Hardening Framework that applies more than 60+ security configurations, enforces strict firewall rules, fixes Microsoft Defender, removes leftover antivirus conflicts, blocks inbound traffic, disables legacy protocols, and creates full registry + system restore backups.
This tool is ideal for:

Cybersecurity professionals

Penetration testers

System administrators

Privacy-focused users

Windows optimization & security enthusiasts

🚀 Features
✔️ Full Windows Hardening Automation

Applies critical hardening controls including:

UAC enforcement

NTLMv2-only authentication

LanMan & plaintext password disablement

Remote Desktop blocking

Guest/anonymous restrictions

Inactivity timeout + secure logon options

✔️ Microsoft Defender Repair & Reactivation

Fixes Defender even after:

Third-party antivirus uninstall (e.g., Malwarebytes leftovers)

Broken or corrupted Defender services

Registry-based Defender disable policies

Signature update failures

Includes:

Service repair

Registry policy cleanup

Signature update

Full system scan trigger

✔️ Firewall Hardening / Zero-Trust Inbound

Enables all firewall profiles

Blocks ALL inbound traffic

Creates a permanent deny-all rule

Ensures the Windows Firewall service cannot be disabled

✔️ Network Attack Surface Reduction

Automatically disables:

SMBv1

IPv6 (optional toggle)

NetBIOS leaks

Anonymous enumeration

Legacy authentication protocols

✔️ System Restore + Registry Backup Safety Net

Before changes:

Creates a System Restore point

Backs up important registry hives

Generates a one-click restore script

Your system is protected even if you want to revert later.

✔️ Auto-Reboot for Complete Application

After applying all checks, the system reboots to finalize the hardening.

🛡️ Why Use This Tool?

This tool is built to make Windows as secure as possible with zero manual configuration.
Perfect for:

Building hardened Windows images

Blue team environments

Secure home labs

Post-malware cleanup

Workstations that require maximum privacy & defense
