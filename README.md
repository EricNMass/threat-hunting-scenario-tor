# Threat Hunting Lab

<img width="285" height="177" alt="download" src="https://github.com/user-attachments/assets/ba9efa67-6ae3-4b02-84b4-e22d2aaf7155" />

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/EricNMass/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management has raised concerns that employees may be utilizing the TOR Browser to circumvent established network security measures. This concern stems from the observation of unusual encrypted network traffic and connections to infrastructure associated with the Tor network. Additionally, reports have suggested that some employees may be exploring methods to access websites that are normally restricted during business hours.

The objective of this investigation is to identify any instances of TOR Browser usage, analyze related activity, and assess any potential security risks to the organization. If evidence of Tor usage is identified, the findings should be documented and reported to management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for any file containing the string "tor" and discovered evidence indicating that the user "sierra-mojave" downloaded a TOR Browser installer. Subsequent activity suggests that numerous TOR-related files were copied to the desktop, along with the creation of a file named "tor-shopping-list.txt" on the desktop at 2026-06-23T00:05:17.599296Z. The earliest Tor-related file activity was observed at 2026-06-22T23:45:08.473708Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName startswith "tor"
| where DeviceName == "the-real-mass-t"
| where Timestamp >= datetime(2026-06-22T23:45:08.473708Z)
| project Timestamp,
          DeviceName,
          ActionType,
          FileName,
          FolderPath,
          SHA256,
          Account = InitiatingProcessAccountName
| order by Timestamp desc 
```
<img width="1553" height="582" alt="Screenshot 2026-06-23 at 5 14 46 PM" src="https://github.com/user-attachments/assets/3d3e5f3d-002d-47be-bcaa-9bc1015d3636" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine containing the string "tor-browser-windows-x86_64-portable-15.0.16.exe". Log data from 2026-06-22T23:48:01.0869376Z showed that user sierra-mojave on device the-real-mass-t executed the TOR Browser Portable 15.0.16 installer. The process was launched with the /S switch, indicating a silent installation or extraction that bypassed installation prompts and user interaction. Microsoft Defender recorded the process creation event and captured the executable's SHA-256 hash (f3228ceebef9a3fb82e97c41b93e3dde54eb643703781252683ec463f6f626fa) for identification and analysis purposes.
**Query used to locate event:**

```kql

DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.16.exe"
| where DeviceName == "the-real-mass-t"
| project Timestamp, 
          DeviceName,
          AccountName,
          ActionType, 
          FileName, 
          ProcessCommandLine, 
          SHA256, 
          FolderPath
```
<img width="1563" height="670" alt="Screenshot 2026-06-23 at 5 21 48 PM" src="https://github.com/user-attachments/assets/12e0fda6-1d4e-4f93-b8bb-619f2d8d4bfe" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user **“sierra-mojave”** actually opened the tor browser. There was evidence that they did open it at 2026-06-22T23:48:47.3066546Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "the-real-mass-t"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc 
| project Timestamp,
          DeviceName, 
          AccountName, 
          FileName, 
          FolderPath, 
          ActionType, 
          ProcessCommandLine,
          SHA256
```
<img width="1594" height="894" alt="Screenshot 2026-06-23 at 5 28 39 PM" src="https://github.com/user-attachments/assets/2c8fe111-5314-4a74-94ca-33e9c84d02ee" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Search the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. On 2026-06-22T23:49:32.5452036Z, the user **sierra-mojave** on the device **the-real-mass-t** successfully established a network connection using Firefox (firefox.exe) to 127.0.0.1 (the local machine itself) on port 9150. Because 127.0.0.1 is the localhost address and port 9150 is commonly used by the Tor Browser SOCKS proxy, this activity indicates that Firefox was communicating with the local TOR service to route web traffic through the TOR network. This is expected behavior when using TOR Browser and does not represent an external network connection by itself. There were a few other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "the-real-mass-t"
| where InitiatingProcessAccountName == "sierra-mojave"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in (9005, 9001, 8443, 9150, 9151, 443, 80, 123, 53)
| project Timestamp, 
          DeviceName, 
          ActionType, 
          InitiatingProcessAccountName,
          InitiatingProcessFolderPath,
          RemoteIP, 
          RemotePort, 
          RemoteUrl, 
          InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1535" height="881" alt="Screenshot 2026-06-23 at 5 31 39 PM" src="https://github.com/user-attachments/assets/7d8c37a6-d392-44d6-ac10-b5d82fa3defe" />

---

# Detection and Analysis
A threat hunt was conducted on device **the-real-mass-t** to determine whether the user **sierra-mojave** downloaded, installed, launched, and utilized the TOR Browser. Analysis focused exclusively on Tor-related file, process, and network activity observed in Microsoft Defender telemetry.

## Chronological Event Timeline 

### 1. TOR Browser Installer Appears on the System

- **Timestamp:** `2026-06-22T19:45:08.0000000Z`
- **Event:** The user **"sierra-mojave"** downloaded a file named `tor-browser-windows-x86_64-portable-15.0.16.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\sierra-mojave\Downloads\tor-browser-windows-x86_64-portable-15.0.16.exe`

### 2. Silent Installation / Extraction of TOR Browser

- **Timestamp:** `2026-06-22T19:48:01.0000000Z`
- **Event:** The user **"sierra-mojave"** executed the file `tor-browser-windows-x86_64-portable-15.0.16.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.16.exe /S`
- **File Path:** `C:\Users\sierra-mojave\Downloads\tor-browser-windows-x86_64-portable-15.0.16.exe`

### 3. Process Execution - TOR Browser Launched

- **Timestamp:** `2026-06-22T19:48:47.0000000Z`
- **Event:** User **"sierra-mojave"** opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\sierra-mojave\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Initial TOR Network Connectivity Attempts

- **Timestamp:** `2026-06-22T23:49:09.961617Z`
- **Event:** A network connection to IP `127.0.0.1` on port `9150` by user **"sierra-mojave"** was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection Success.
- **Process:** `firefox.exe`
- **File Path:** `c:\users\sierra-mojave\desktop\tor browser\browser\firefox.exe`

### 5. Continued TOR Activity Later in the Session

- **Timestamps:**
  - `2026-06-22T23:49:29.728075Z` - Connected to `64.65.1.116` on port `443`.
  - `2026-06-22T23:49:48.7138102Z` - Local connection to `86.45.51.133` on port `9001`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user **"sierra-mojave"** through the TOR browser.
- **Action:** Multiple successful and failed connections detected.

### 6. Creation of TOR-Related User File

- **Timestamp:** `2026-06-22T20:05:17.0000000Z`
- **Event:** The user **"sierra-mojave"** created a file named **`tor-shopping-list.txt`** on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\sierra-mojave\Desktop\tor-shopping-list.txt`

---

## Summary

Investigation results show that user **sierra-mojave** downloaded and silently installed TOR Browser Portable 15.0.16 on device **the-real-mass-t**. TOR-related processes, including tor.exe and firefox.exe, were successfully launched and established communication with the local TOR SOCKS proxy (127.0.0.1:9150). Network telemetry further showed connection attempts to TOR relay infrastructure and subsequent successful encrypted communications over port 443, confirming connectivity to the Tor network. TOR-related activity persisted for over an hour after installation, indicating active use of the Tor Browser during the investigation period.

---

## Response Taken

TOR usage was confirmed on the endpoint **the-real-mass-t** by the user **`sierra-mojave`**. The device was isolated, and the user's direct manager was notified.

---
