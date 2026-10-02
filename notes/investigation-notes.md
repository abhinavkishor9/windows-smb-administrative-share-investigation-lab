# Investigation Notes

## Windows SMB Administrative Share Investigation

### Investigation Context

This investigation focused on the Windows `C$` administrative SMB share and the evidence available for determining whether SMB activity occurred on the host.

The investigation was performed as a controlled defensive lab. The primary goal was to understand the difference between an administrative share being present, local access occurring, and actual remote SMB activity being demonstrated through security telemetry.

---

## 1. Host Baseline

The host was identified using Windows CIM queries.

Observed system:

```text
Computer Name : DESKTOP-9MMM37V
Manufacturer  : Dell Inc.
Model         : Latitude 5420
Domain        : WORKGROUP
Domain Role   : 0
OS            : Microsoft Windows 11 Pro
Version       : 10.0.26200
Build         : 26200
```

The host was operating as a standalone Windows workstation rather than a domain-joined system.

The last recorded boot time was:

```text
28-09-2026 07:39:52
```

---

## 2. User Context

The current user context was:

```text
desktop-9mmm37v\dell
```

The account belonged to the local Administrators group.

The collected group information also showed membership in:

```text
BUILTIN\Administrators
BUILTIN\Hyper-V Administrators
BUILTIN\Users
```

The account had a high integrity administrative context.

This is important because administrative SMB shares such as `C$` are normally intended for administrative access.

---

## 3. Network Baseline

The host had multiple network interfaces.

Primary Wi-Fi address:

```text
192.168.1.6/24
```

VMware interfaces:

```text
VMnet8  : 192.168.203.1/24
VMnet1  : 192.168.174.1/24
```

Additional interfaces had APIPA addresses in the `169.254.0.0/16` range.

The VMware interfaces were recorded because virtualized environments can create additional network paths that may become relevant during network investigations.

---

## 4. C$ Share Configuration

The built-in administrative share was confirmed:

```text
Name          : C$
Path          : C:\
ShareState    : Online
ShareType     : FileSystemDirectory
CurrentUsers  : 0
EncryptData   : False
```

The share was therefore active at the time of collection.

The value:

```text
CurrentUsers : 0
```

indicated that no current users were reported by the share configuration query at that moment.

---

## 5. C$ Permissions

The following principals had Full access:

```text
BUILTIN\Administrators
BUILTIN\Backup Operators
NT AUTHORITY\INTERACTIVE
```

The permissions were documented as part of the baseline rather than automatically considered malicious.

The presence of administrative access should instead be correlated with authentication, SMB session, process, and network evidence when investigating suspected lateral movement.

---

## 6. SMB Connections Before Test

The following commands were executed:

```powershell
Get-SmbConnection
Get-SmbSession
Get-SmbOpenFile
```

The results did not show active SMB connections, sessions, or open files.

The outputs were preserved as:

- `SMB-Connections-Before.txt`
- `SMB-Sessions-Before.txt`
- `SMB-OpenFiles-Before.txt`

---

## 7. Local Administrative Share Access

The administrative share was accessed through:

```text
\\localhost\C$
```

The directory contents were successfully enumerated.

Examples included:

```text
Windows
Users
Program Files
Program Files (x86)
Tools
CShareLab
ADMINShareLab
```

This demonstrated that the administrative share was reachable from the local host.

This activity was part of the controlled investigation and should not be interpreted as evidence of an external attacker.

---

## 8. Security Event 5140

Event ID `5140` was queried from the Windows Security log.

The query returned:

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

Event ID `5140` would be useful for identifying network-share access when the appropriate auditing and event collection are available.

However, the absence of the event in this dataset means only that no matching event was available through the queried Security log.

It does not prove that no SMB activity ever occurred.

---

## 9. Security Event 5145

Event ID `5145` was also queried.

The result was:

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

This removed an important source of detailed share-access evidence from the investigation.

The missing telemetry therefore became an investigation limitation.

---

## 10. Security Event 4624

Multiple successful logon events were observed:

```text
Event ID : 4624
Description : An account was successfully logged on
```

The events occurred around:

```text
28-09-2026 07:21
```

However, the available output was summarized and did not provide sufficient fields to establish the exact logon type, source network address, or authentication context.

Therefore:

```text
4624 observed
```

does not equal:

```text
SMB access confirmed
```

The events were treated as authentication telemetry requiring additional context.

---

## 11. Controlled Test Timestamp

A controlled timestamp was captured before continuing the investigation:

```text
2026-10-02 06:35:48.934 +05:30
```

The timestamp provides a reference point for correlation with SIEM and endpoint telemetry.

---

## 12. SMB Connections After Test

The same SMB enumeration commands were executed after the controlled activity:

```powershell
Get-SmbConnection
Get-SmbSession
Get-SmbOpenFile
```

No active SMB connection, session, or open-file activity was observed.

The results were saved as:

- `SMB-Connections-After.txt`
- `SMB-Sessions-After.txt`
- `SMB-OpenFiles-After.txt`

---

## 13. Wazuh Telemetry

Wazuh reported a registry integrity alert:

```text
decoder.name:
syscheck_registry_value_modified
```

The affected registry value was:

```text
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\VSS\Diag\Lovelace(C:)\IOCTL_RELEASE
```

The alert reported changes to:

```text
md5
sha1
sha256
```

The rule description was:

```text
Registry Value Integrity Checksum Changed
```

The rule had fired multiple times.

---

## 14. Wazuh and SMB Correlation

The Wazuh registry-integrity alert was not automatically connected to SMB activity.

There was no direct evidence in the collected output showing:

```text
SMB access
    ->
registry modification
```

Therefore, the alert was retained as separate host telemetry.

This is an important investigative distinction.

A SOC analyst should not combine unrelated events simply because they occur on the same host or within a similar investigation period.

---

## 15. Evidence Assessment

### Confirmed

- Windows 11 Pro workstation identified.
- Current administrative user identified.
- `C$` administrative share exists.
- `C$` is online.
- Share permissions were identified.
- Local `\\localhost\C$` access was demonstrated.
- Successful `4624` events exist.
- Wazuh registry-integrity telemetry exists.

### Not Observed

- Active SMB connections during collection.
- Active SMB sessions during collection.
- Open SMB files during collection.
- Security Event `5140`.
- Security Event `5145`.

### Not Established

- Unauthorized remote SMB access.
- SMB-based lateral movement.
- Remote attacker activity.
- Malicious use of `C$`.
- Connection between the Wazuh registry alert and SMB activity.

---

## 16. Investigation Limitations

The investigation had several telemetry limitations.

First, Events `5140` and `5145` were not available in the queried Security log.

Second, the available `4624` output did not contain enough contextual fields to determine the exact authentication mechanism or source.

Third, `Get-SmbConnection`, `Get-SmbSession`, and `Get-SmbOpenFile` provide point-in-time visibility and cannot reconstruct historical SMB activity.

Finally, the Wazuh registry-integrity alert did not contain enough contextual information to connect it directly to the SMB investigation.

---

## 17. Analyst Assessment

The available evidence supports the conclusion that the host had a functioning administrative SMB share and that the share could be accessed locally.

The evidence does not support a conclusion of confirmed remote SMB compromise.

The correct assessment is therefore:

```text
Administrative share present: CONFIRMED
Local administrative-share access: CONFIRMED
Remote SMB access: NOT ESTABLISHED
SMB attack/lateral movement: NOT ESTABLISHED
```

---

## Investigation Principle

The investigation reinforced the importance of separating:

```text
What happened
```

from:

```text
What could have happened
```

and:

```text
What the available telemetry cannot prove
```

The absence of evidence should be recorded as a telemetry limitation rather than converted into an assumption.
