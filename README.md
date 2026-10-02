# Windows SMB Administrative Share Investigation Lab

## Overview

This lab investigates the Windows built-in `C$` administrative SMB share from a defensive SOC and DFIR perspective.

The investigation focuses on establishing a Windows host baseline, examining the `C$` share configuration and permissions, checking SMB connections and sessions, reviewing Windows Security event telemetry, validating controlled access through `\\localhost\C$`, and correlating the activity with Wazuh telemetry.

The investigation does not assume that an SMB attack occurred. Instead, it focuses on determining what the available evidence can actually prove and documenting evidence gaps where telemetry is unavailable.

---

## Lab Focus

- Windows SMB administrative share investigation
- `C$` administrative share configuration
- SMB share permissions and access control
- SMB connections, sessions, and open files
- Windows Security Event IDs `4624`, `5140`, and `5145`
- Local administrative-share access
- Evidence collection and preservation
- Wazuh telemetry correlation
- Baseline versus suspicious activity
- Evidence limitations and investigative confidence

---

## Environment

| Component | Details |
|---|---|
| Host | `DESKTOP-9MMM37V` |
| Manufacturer | Dell Inc. |
| Model | Latitude 5420 |
| Operating System | Windows 11 Pro |
| Build | `26200` |
| Domain | `WORKGROUP` |
| User | `desktop-9mmm37v\dell` |
| Wi-Fi IPv4 | `192.168.1.6` |
| VMware VMnet8 | `192.168.203.1` |
| VMware VMnet1 | `192.168.174.1` |
| SMB Share | `C$` |
| SIEM | Wazuh |
| Wazuh Agent | `001` |

---

## Investigation Objectives

- Establish the Windows host and operating-system baseline.
- Document the current user and security-group context.
- Record the available network configuration.
- Identify the configuration of the `C$` administrative share.
- Identify the accounts and groups with access to `C$`.
- Check for active SMB connections, sessions, and open files.
- Query Windows Security logs for SMB-related events.
- Review successful logon events associated with the host.
- Validate controlled local access to `\\localhost\C$`.
- Correlate relevant host activity with Wazuh telemetry.
- Preserve evidence before and after the controlled test.
- Distinguish confirmed observations from assumptions and unknowns.

---

## Investigation Workflow

### 1. Establish Host Baseline

The investigation started by collecting information about the Windows system, including the hostname, manufacturer, model, operating-system version, build number, domain/workgroup status, and last boot time.

The host was identified as a Dell Latitude 5420 running Windows 11 Pro build `26200` in a `WORKGROUP` configuration.

### 2. Establish User Context

The current user and group membership were collected using `whoami`, `$env:USERNAME`, `$env:USERDOMAIN`, and `whoami /groups`.

The current account was:

```text
desktop-9mmm37v\dell
```

The account was also a member of the local Administrators group and other local security groups relevant to administrative access.

### 3. Establish Network Baseline

The available IPv4 configuration was collected using PowerShell networking cmdlets.

The primary Wi-Fi interface had the address:

```text
192.168.1.6/24
```

VMware virtual network interfaces were also present:

```text
192.168.203.1/24
192.168.174.1/24
```

Several other interfaces had APIPA addresses.

This baseline provides context when evaluating possible SMB connections or lateral-movement activity.

### 4. Inspect the Administrative Share

The built-in `C$` administrative share was queried using `Get-SmbShare`.

The share was confirmed to be:

```text
Name          : C$
Path          : C:\
ShareState    : Online
ShareType     : FileSystemDirectory
CurrentUsers  : 0
EncryptData   : False
```

The existence of `C$` was treated as expected Windows administrative functionality rather than automatically considered suspicious.

### 5. Review Share Permissions

`Get-SmbShareAccess -Name C$` was used to identify the principals with access.

The following permissions were observed:

```text
BUILTIN\Administrators     Full
BUILTIN\Backup Operators   Full
NT AUTHORITY\INTERACTIVE   Full
```

These permissions were documented as part of the baseline.

### 6. Check SMB Connections and Sessions

The following commands were executed before and after the controlled activity:

```powershell
Get-SmbConnection
Get-SmbSession
Get-SmbOpenFile
```

No active SMB connection, session, or open-file activity was returned during the observed checks.

This is a point-in-time observation and does not prove that SMB activity never occurred.

### 7. Review Windows Security Events

Windows Security Event ID `5140` was queried for network-share access.

Event ID `5145` was also queried for detailed network-share access checks.

Both queries returned:

```text
No events were found that match the specified selection criteria.
```

Event ID `4624` was present with multiple successful logon events.

However, the available output did not provide sufficient evidence to conclude that those `4624` events represented remote SMB access.

### 8. Validate Local Administrative Share Access

The following path was accessed:

```text
\\localhost\C$
```

Directory enumeration through the administrative share was successful.

The listing included standard Windows directories and files such as:

```text
Windows
Users
Program Files
Program Files (x86)
Tools
CShareLab
ADMINShareLab
```

This demonstrated controlled local access to the administrative share.

It was not treated as evidence of remote lateral movement.

### 9. Establish Controlled Test Timestamp

A timestamp was captured using:

```powershell
Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K"
```

The recorded timestamp was:

```text
2026-10-02 06:35:48.934 +05:30
```

This provides a reference point for correlating the controlled investigation activity with available telemetry.

### 10. Correlate Wazuh Telemetry

Wazuh telemetry showed a registry-integrity alert involving a registry value under:

```text
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\VSS\Diag\Lovelace(C:)\IOCTL_RELEASE
```

The alert reported changes to MD5, SHA1, and SHA256 values.

The rule description was:

```text
Registry Value Integrity Checksum Changed
```

The rule had fired multiple times.

The Wazuh event was documented as host telemetry but was not automatically attributed to SMB activity because no direct evidence connected the registry modification to SMB access.

---

## Key Findings

| Finding | Result |
|---|---|
| `C$` administrative share exists | Confirmed |
| `C$` is online | Confirmed |
| `C$` points to `C:\` | Confirmed |
| Full access permissions identified | Confirmed |
| Active SMB connections observed | No |
| Active SMB sessions observed | No |
| Open SMB files observed | No |
| Event ID `5140` observed | No |
| Event ID `5145` observed | No |
| Event ID `4624` observed | Yes |
| Local `\\localhost\C$` access | Confirmed |
| Remote SMB access confirmed | No |
| SMB attack confirmed | No |
| Wazuh registry-integrity alert | Observed |
| Wazuh alert linked to SMB activity | Not established |

---

## Investigation Conclusion

The investigation confirmed that the Windows host had an enabled `C$` administrative share and that the share was accessible locally through `\\localhost\C$`.

The available evidence did not establish unauthorized remote SMB access or lateral movement. No active SMB sessions, connections, or open files were observed during the checks, and Security Events `5140` and `5145` were not available in the queried event data.

The presence of successful `4624` logons was documented but was not treated as direct proof of SMB activity.

The investigation therefore concludes that the administrative share and local access were confirmed, while remote SMB activity remains unconfirmed based on the available telemetry.

---

## Evidence Collected

- `Host-Baseline.txt`
- `OS-Baseline.txt`
- `User-Context.txt`
- `User-Groups.txt`
- `Network-Baseline.txt`
- `CShare-Configuration.txt`
- `CShare-Permissions.txt`
- `SMB-Connections-Before.txt`
- `SMB-Sessions-Before.txt`
- `SMB-OpenFiles-Before.txt`
- `SMB-Connections-After.txt`
- `SMB-Sessions-After.txt`
- `SMB-OpenFiles-After.txt`
- `Controlled-Test-Timestamp.txt`

---

## Key Lessons Learned

- Administrative shares such as `C$` are normal Windows functionality.
- The presence of `C$` does not by itself indicate compromise.
- Share permissions should be reviewed before interpreting SMB activity.
- `Get-SmbConnection`, `Get-SmbSession`, and `Get-SmbOpenFile` provide useful point-in-time visibility.
- Event ID `4624` alone does not prove SMB access.
- Events `5140` and `5145` can provide stronger network-share evidence when the required auditing is enabled.
- Local access through `\\localhost\C$` should not automatically be interpreted as remote lateral movement.
- Empty SMB session output represents the state observed at collection time.
- Wazuh alerts should be correlated with authentication, process, network, and file-system evidence before attribution.
- Evidence gaps should be documented instead of being filled with assumptions.

---

## Investigation Principle

> Follow the evidence, not the assumption.
