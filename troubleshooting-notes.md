# Troubleshooting Notes

## Windows SMB Administrative Share Investigation

This document records the troubleshooting and validation performed during the SMB investigation, including expected empty results, telemetry limitations, and interpretation of the collected evidence.

---

## 1. SMB Share Exists but No Active Sessions

### Observation

The `C$` share was confirmed to be online:

```powershell
Get-SmbShare -Name C$
```

The result showed:

```text
Name          : C$
Path          : C:\
ShareState    : Online
CurrentUsers  : 0
```

However, the following commands returned no active SMB activity:

```powershell
Get-SmbConnection
Get-SmbSession
Get-SmbOpenFile
```

### Interpretation

This is not necessarily a problem.

`Get-SmbShare` shows the configured share, while the SMB connection and session commands provide point-in-time information about active activity.

Therefore:

```text
Share exists
```

does not imply:

```text
Active SMB session exists
```

The empty results were preserved as valid evidence.

---

## 2. Security Event 5140 Not Available

### Observation

The following query returned no events:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=5140
} -MaxEvents 50
```

Result:

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

### Interpretation

The result does not prove that SMB access never occurred.

Possible explanations include:

- No matching event was generated.
- Required auditing was not enabled.
- The event was not retained.
- The activity occurred outside the available event window.
- The event was collected elsewhere but not present in the local Security log.

The correct investigative conclusion is:

```text
Event 5140 not available in the queried dataset.
```

---

## 3. Security Event 5145 Not Available

### Observation

The following query also returned no results:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=5145
} -MaxEvents 50
```

### Interpretation

Event `5145` can provide detailed information about access checks against network shares when the appropriate auditing is configured.

Its absence created a telemetry gap.

The investigation therefore relied on other available evidence such as:

- SMB configuration
- SMB permissions
- SMB session state
- authentication events
- local share enumeration
- Wazuh telemetry

---

## 4. 4624 Events Were Present

### Observation

Multiple Event ID `4624` records were present.

Example:

```text
28-09-2026 07:21:30 4624 An account was successfully logged on
```

### Investigation Concern

It may be tempting to interpret successful logons as evidence of SMB access.

### Correct Interpretation

A `4624` event confirms successful authentication, but the summarized output collected during this investigation did not provide enough context to prove that the authentication was associated with SMB.

Additional fields such as logon type, source network address, workstation information, and authentication package would be useful.

Therefore:

```text
4624 = successful logon
```

does not automatically mean:

```text
4624 = SMB access
```

---

## 5. Local C$ Access Could Be Misinterpreted

### Observation

The following path was successfully enumerated:

```text
\\localhost\C$
```

### Potential Misinterpretation

An analyst could incorrectly describe this as evidence of lateral movement.

### Correct Interpretation

The path uses `localhost`, meaning the access was performed against the local host.

The activity was intentionally performed as part of the controlled lab.

Therefore, the evidence demonstrates:

```text
Local administrative-share access
```

and not:

```text
Remote lateral movement
```

---

## 6. CurrentUsers Was Zero

### Observation

The share configuration showed:

```text
CurrentUsers : 0
```

### Interpretation

This indicates that the share reported no current users at the time of the query.

It should not be treated as historical evidence.

For example, a previous SMB connection that had already ended would not necessarily appear in this field.

---

## 7. Wazuh Registry Alert Appeared During Investigation

### Observation

Wazuh reported:

```text
Registry Value Integrity Checksum Changed
```

The affected registry value was associated with:

```text
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\VSS\Diag\Lovelace(C:)\IOCTL_RELEASE
```

### Investigation Concern

Because the alert was visible during the same investigation, it could be tempting to associate it with SMB activity.

### Correct Approach

No direct evidence was collected connecting the registry change to SMB access.

The alert was therefore treated as independent host telemetry.

The investigation principle was:

```text
Temporal proximity does not establish causation.
```

---

## 8. Multiple Network Interfaces

### Observation

The system contained:

```text
Wi-Fi                 192.168.1.6
VMware VMnet8         192.168.203.1
VMware VMnet1         192.168.174.1
```

Several other interfaces had APIPA addresses.

### Interpretation

Virtual network adapters are expected in a VMware-based lab environment.

Their presence should not automatically be interpreted as suspicious networking.

However, they should be included in the baseline because they can affect:

- routing
- source addresses
- virtual-machine communication
- SMB connectivity
- network investigation results

---

## 9. Evidence Collection Path

The investigation used:

```text
C:\CShareLab\Evidence
```

The directory was created with:

```powershell
$LabPath = "C:\CShareLab\Evidence"
New-Item -ItemType Directory -Path $LabPath -Force
```

Evidence was then written to individual text files using `Out-File`.

This approach keeps the evidence collection reproducible and makes it easier to compare before-and-after results.

---

## 10. Before and After Comparison

The SMB state was collected before and after the controlled activity.

### Before

- `SMB-Connections-Before.txt`
- `SMB-Sessions-Before.txt`
- `SMB-OpenFiles-Before.txt`

### After

- `SMB-Connections-After.txt`
- `SMB-Sessions-After.txt`
- `SMB-OpenFiles-After.txt`

### Result

No persistent SMB session or connection was identified in the observed output.

The comparison therefore did not provide evidence of an active SMB session remaining after the controlled activity.

---

## 11. Evidence Interpretation Rule

During troubleshooting, the investigation followed a simple evidence classification model.

### Confirmed

Directly demonstrated by collected evidence.

### Plausible

Technically possible but not demonstrated by the available evidence.

### Unknown

The available telemetry is insufficient to determine the answer.

For this lab:

```text
C$ exists              -> Confirmed
Local C$ access        -> Confirmed
Remote SMB access      -> Unknown / Not established
SMB attack             -> Not established
Registry alert         -> Confirmed
Registry alert = SMB   -> Not established
```

---

## 12. Key Troubleshooting Lesson

The most important troubleshooting lesson from this investigation was that an empty query result is still useful evidence.

For example:

```text
Get-SmbSession
```

returning nothing does not mean the command failed.

Similarly:

```text
Event 5140 not found
```

does not mean SMB activity is impossible.

The analyst must determine whether the result represents:

- no activity,
- no retained telemetry,
- insufficient auditing,
- insufficient query scope,
- or a point-in-time limitation.

This prevents false conclusions during SOC investigations.
