# Investigation Timeline

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
