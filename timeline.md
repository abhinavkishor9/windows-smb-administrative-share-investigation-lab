# Investigation Timeline

## Windows SMB Administrative Share Investigation

| Time | Activity | Evidence | Assessment |
|---|---|---|---|
| 28-09-2026 07:21:13–07:21:30 | Multiple Windows successful logons observed | Security Event `4624` | Successful authentication events confirmed |
| 28-09-2026 07:39:52 | Host last boot time | Windows OS baseline | Host baseline |
| 02-10-2026 06:25 | `C:\CShareLab\Evidence` created | PowerShell output | Evidence collection directory established |
| 02-10-2026 06:26:44.027 | Wazuh registry integrity alert observed | Wazuh alert | Registry checksum modification detected |
| 02-10-2026 06:35:36 | Current system time captured | `Get-Date` | Investigation time reference |
| 02-10-2026 06:35:48.934 +05:30 | Controlled-test timestamp recorded | `Controlled-Test-Timestamp.txt` | Correlation reference point |
| 02-10-2026 | Windows host baseline collected | `Host-Baseline.txt`, `OS-Baseline.txt` | Host identity and OS established |
| 02-10-2026 | User context collected | `User-Context.txt`, `User-Groups.txt` | Administrative user context established |
| 02-10-2026 | Network baseline collected | `Network-Baseline.txt` | Network interfaces documented |
| 02-10-2026 | `C$` share configuration collected | `CShare-Configuration.txt` | Administrative share confirmed |
| 02-10-2026 | `C$` permissions collected | `CShare-Permissions.txt` | Share access principals identified |
| 02-10-2026 | SMB connections checked | `SMB-Connections-Before.txt` | No active connections observed |
| 02-10-2026 | SMB sessions checked | `SMB-Sessions-Before.txt` | No active sessions observed |
| 02-10-2026 | SMB open files checked | `SMB-OpenFiles-Before.txt` | No open SMB files observed |
| 02-10-2026 | Security Event `5140` queried | Windows Security log | No matching events found |
| 02-10-2026 | Security Event `5145` queried | Windows Security log | No matching events found |
| 02-10-2026 | `\\localhost\C$` enumerated | PowerShell directory listing | Local administrative-share access confirmed |
| 02-10-2026 | SMB connections checked after test | `SMB-Connections-After.txt` | No active connection observed |
| 02-10-2026 | SMB sessions checked after test | `SMB-Sessions-After.txt` | No active session observed |
| 02-10-2026 | SMB open files checked after test | `SMB-OpenFiles-After.txt` | No open SMB files observed |

---

## Detailed Timeline

### 28-09-2026 — Existing Authentication Activity

Multiple Windows Security Event ID `4624` events were present around:

```text
07:21:13–07:21:30
```

These events confirmed successful logons.

The available output did not contain enough contextual information to associate the events directly with SMB activity.

---

### 28-09-2026 07:39:52 — Host Boot Baseline

The Windows operating-system baseline reported the last boot time as:

```text
28-09-2026 07:39:52
```

This was retained as part of the host baseline.

---

### 02-10-2026 06:25 — Evidence Directory Created

The investigation evidence directory was created:

```text
C:\CShareLab\Evidence
```

This directory was used to store collected baseline and investigation outputs.

---

### 02-10-2026 06:26:44.027 — Wazuh Registry Integrity Alert

Wazuh recorded a registry integrity event at:

```text
Oct 2, 2026 @ 06:26:44.027
```

The alert identified a modification to a registry value associated with the VSS registry path.

The rule description was:

```text
Registry Value Integrity Checksum Changed
```

The event was recorded as host telemetry.

No direct evidence was identified linking this event to SMB activity.

---

### 02-10-2026 06:35:36 — Investigation Time Captured

The current system time was captured:

```text
02 October 2026 06:35:36
```

This established the investigation time reference.

---

### 02-10-2026 06:35:48.934 +05:30 — Controlled Test Timestamp

A precise timestamp was recorded:

```text
2026-10-02 06:35:48.934 +05:30
```

The timestamp was saved to:

```text
Controlled-Test-Timestamp.txt
```

---

### 02-10-2026 — Host and User Baseline

The investigation documented:

```text
Host     : DESKTOP-9MMM37V
OS       : Windows 11 Pro
Build    : 26200
Domain   : WORKGROUP
User     : desktop-9mmm37v\dell
```

The user was confirmed to have local administrative privileges.

---

### 02-10-2026 — Network Baseline

The primary network address was recorded:

```text
192.168.1.6
```

VMware interfaces were also documented:

```text
192.168.203.1
192.168.174.1
```

---

### 02-10-2026 — C$ Share Identified

The Windows administrative share was confirmed:

```text
C$ -> C:\
```

The share was online and reported zero current users at the time of collection.

---

### 02-10-2026 — C$ Permissions Identified

The following principals were observed with Full access:

```text
BUILTIN\Administrators
BUILTIN\Backup Operators
NT AUTHORITY\INTERACTIVE
```

The permissions were recorded as part of the baseline.

---

### 02-10-2026 — SMB Baseline Checked

The following commands were executed:

```powershell
Get-SmbConnection
Get-SmbSession
Get-SmbOpenFile
```

No active SMB connections, sessions, or open files were observed.

The results were stored as before-test evidence.

---

### 02-10-2026 — Security Event 5140 Checked

Event ID `5140` was queried.

Result:

```text
No events were found that match the specified selection criteria.
```

The absence of the event was documented as a telemetry limitation.

---

### 02-10-2026 — Security Event 5145 Checked

Event ID `5145` was queried.

Result:

```text
No events were found that match the specified selection criteria.
```

No detailed network-share access event was available from the queried Security log.

---

### 02-10-2026 — Local C$ Access Tested

The administrative share was accessed through:

```text
\\localhost\C$
```

Directory enumeration succeeded.

This confirmed local access to the administrative share.

It did not establish remote SMB access.

---

### 02-10-2026 — SMB State Checked After Test

The following commands were executed:

```powershell
Get-SmbConnection
Get-SmbSession
Get-SmbOpenFile
```

No persistent SMB connections, sessions, or open files were observed.

The results were stored as after-test evidence.

---

## Final Timeline Assessment

The investigation followed this sequence:

```text
Host baseline
    ↓
User/network baseline
    ↓
C$ configuration and permissions
    ↓
SMB state before test
    ↓
Security event review
    ↓
Controlled localhost C$ access
    ↓
SMB state after test
    ↓
Wazuh correlation
```

The investigation confirmed the existence and local accessibility of the administrative share but did not establish unauthorized remote SMB activity or lateral movement.

The timeline therefore supports a baseline and evidence-validation investigation rather than a confirmed SMB compromise.
