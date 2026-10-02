# windows-smb-administrative-share-investigation-lab
## Overview
C$ is a default Windows administrative share that exposes the root of the system drive (C:\) to authorized administrators. It is commonly used for remote administration, software deployment, troubleshooting, and system management.

From a DFIR perspective, access to C$ is not automatically malicious. The investigation should instead answer:

Who accessed C$, from where, when, and what activity occurred around that access?

The strongest investigation combines:

Share configuration
Share permissions
User/account context
SMB sessions and connections
Windows Security events 5140 and 5145
Authentication events such as 4624
Sysmon process/network telemetry
Wazuh endpoint telemetry
Timestamp correlation

This lab investigates the Windows built-in `C$` administrative SMB share from a defensive SOC and DFIR perspective.

The investigation focuses on establishing a Windows host baseline, examining the `C$` share configuration and permissions, checking SMB connections and sessions, reviewing Windows Security event telemetry, validating controlled access through `\\localhost\C$`, and correlating the activity with Wazuh telemetry.

The investigation does not assume that an SMB attack occurred. Instead, it focuses on determining what the available evidence can actually prove and documenting evidence gaps where telemetry is unavailable.

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

## Lab Objectives

The objectives of this lab are to:

- Understand how Windows SMB administrative shares, particularly `C$`, are configured and exposed on a Windows endpoint.
- Examine the share permissions assigned to `C$` and identify which local security principals have access.
- Establish a baseline of the host, user context, network configuration, and SMB configuration before performing the investigation.
- Check for active SMB connections, sessions, and open files to determine whether SMB activity is present at the time of collection.
- Perform controlled access to the administrative share through `\\localhost\C$` and distinguish local administrative-share activity from remote access.
- Investigate Windows Security event telemetry, including Event IDs `5140`, `5145`, and `4624`, for evidence related to network share access and successful logons.
- Document situations where expected SMB-related events are not available and avoid treating missing telemetry as evidence that no activity occurred.
- Collect and preserve relevant command outputs and timestamps as investigation evidence.
- Correlate available endpoint telemetry with Wazuh alerts while keeping unrelated events separate from the SMB investigation unless supporting evidence establishes a relationship.
- Assess the collected evidence using a structured approach that distinguishes confirmed observations, plausible interpretations, and unknowns.
- Identify the limitations of the investigation, including incomplete SMB telemetry and the absence of direct evidence of remote lateral movement.
- Develop a repeatable investigation methodology for analyzing Windows administrative-share activity in a SOC or DFIR environment.

---

## Lab Scenario

A Windows 11 endpoint is being investigated for potential activity involving the built-in SMB administrative share `C$`. Administrative shares can provide access to sensitive areas of a Windows system, so the SOC analyst needs to determine how the share is configured, who can access it, and whether there is any evidence of SMB activity during the investigation window.

The investigation begins with establishing a baseline of the endpoint and the account performing the investigation. The analyst collects:

- Hostname, operating system, domain/workgroup, and system role.
- Current user identity and local group memberships.
- Network interfaces and assigned IP addresses.
- `C$` share configuration and access permissions.
- Current SMB connections, sessions, and open files.

A controlled local access test is then performed using `\\localhost\C$`. This provides a known activity point that can be compared against available Windows telemetry. The analyst checks Security event IDs `5140` and `5145` for network-share activity and reviews `4624` successful logon events for supporting authentication context.

During the investigation, the expected SMB-specific events are not available in the collected Security log. Successful logon events are present, but the available output does not provide enough information to establish that they were related to SMB access. Therefore, the analyst must avoid treating the `4624` events as proof of remote SMB activity.

Wazuh telemetry is also reviewed to determine whether endpoint alerts provide additional context. A registry integrity alert is observed during the investigation, but there is no direct evidence connecting that event to the SMB activity. It is therefore documented separately rather than being used to establish a false correlation.

The scenario focuses on evidence-based investigation rather than assuming that administrative-share access represents lateral movement. The final assessment should clearly distinguish between:

- **Confirmed:** `C$` exists, its configured permissions, the controlled localhost access, and the observed telemetry.
- **Plausible:** Potential relationships that could explain available events but cannot be established from the collected evidence.
- **Unknown:** Whether any remote system accessed `C$` during the investigation period.

The objective is to demonstrate how a SOC/DFIR analyst can investigate Windows administrative-share activity, preserve evidence, interpret incomplete telemetry, and avoid overstating conclusions when the available data does not prove remote access or lateral movement.

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

