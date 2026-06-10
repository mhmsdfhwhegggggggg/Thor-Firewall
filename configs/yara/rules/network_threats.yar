/*
 * Thor Firewall YARA Network Threat Rules
 * Based on real rules from:
 *   - https://github.com/Yara-Rules/rules (GPL-2.0)
 *   - https://github.com/Neo23x0/signature-base (CC BY-NC 4.0)
 *   - https://github.com/elastic/protections-artifacts (Elastic License v2)
 *   - MISP default feeds
 */

import "pe"
import "math"

/* ──── Mirai Botnet ──────────────────────────────────────────────────────── */
rule Mirai_Botnet_Malware {
    meta:
        description  = "Detects Mirai botnet malware (IoT DDoS botnet)"
        author       = "Yara-Rules Project"
        date         = "2016-10-04"
        severity     = "critical"
        mitre_tactic = "Impact"
        mitre_tech   = "T1498.001"
        reference    = "https://github.com/Yara-Rules/rules"
    strings:
        $mz   = { 7F 45 4C 46 }
        $str1 = "LCOGQJPKFKHOBMMFKJ" ascii
        $str2 = "/proc/net/tcp"       ascii
        $str3 = "/proc/net/tcp6"      ascii
        $str4 = "GET /bins/"          ascii
        $str5 = "POST /report"        ascii
        $str6 = "SCANNER ON"          ascii
        $str7 = "SCANNER OFF"         ascii
    condition:
        $mz at 0 and 3 of ($str*)
}

/* ──── Cobalt Strike ─────────────────────────────────────────────────────── */
rule CobaltStrike_Beacon_Reflective_Loader {
    meta:
        description  = "Detects Cobalt Strike beacon (reflective loader pattern)"
        author       = "Florian Roth (Neo23x0)"
        date         = "2021-03-02"
        severity     = "critical"
        mitre_tactic = "Command-and-Control"
        mitre_tech   = "T1071.001"
    strings:
        $x1 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 }
        $x2 = { FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 }
        $x3 = { FC E8 C8 00 00 00 41 51 41 50 52 51 56 48 31 D2 }
        $s1 = "ReflectiveLoader" fullword ascii
        $s2 = "%s (admin)"       fullword ascii
        $s3 = "beacon.dll"       nocase ascii
        $s4 = "ppid"             fullword ascii
        $s5 = "process-inject"   fullword ascii
    condition:
        any of ($x*) or 3 of ($s*)
}

rule CobaltStrike_Malleable_C2_Profile {
    meta:
        description = "Detects Cobalt Strike malleable C2 profile patterns in HTTP traffic"
        severity    = "high"
        mitre_tech  = "T1071.001"
    strings:
        $a1 = "set useragent"      ascii nocase
        $a2 = "set uri"            ascii nocase
        $a3 = "header \"Accept\""  ascii
        $a4 = "prepend"            ascii
        $a5 = "transform-x86"     ascii
        $a6 = "transform-x64"     ascii
    condition:
        4 of them
}

/* ──── DNS Tunneling ─────────────────────────────────────────────────────── */
rule DNS_Tunneling_Tool_Iodine {
    meta:
        description = "Detects iodine DNS tunnel tool"
        severity    = "high"
        mitre_tech  = "T1071.004"
    strings:
        $a = "iodine"    nocase ascii
        $b = "TUNNEL"    ascii
        $c = { 00 04 54 55 4E 4C }
        $d = "dns2tcp"   nocase ascii
    condition:
        2 of them
}

rule DNS_High_Entropy_Subdomain {
    meta:
        description = "Detects high-entropy subdomains (DNS tunneling indicator)"
        severity    = "medium"
        mitre_tech  = "T1071.004"
    strings:
        /* Long random-looking base32/base64 subdomains */
        $b32_pattern = /[A-Z2-7]{20,}\.[a-z]{2,}/ ascii
        $b64_pattern = /[A-Za-z0-9+\/]{20,}\.[a-z]{2,}/ ascii
        $hex_pattern = /[0-9a-f]{30,}\.[a-z]{2,}/ ascii
    condition:
        any of them
}

/* ──── Webshell ──────────────────────────────────────────────────────────── */
rule Webshell_Generic_PHP {
    meta:
        description = "Generic PHP webshell detection"
        severity    = "high"
        mitre_tech  = "T1505.003"
    strings:
        $p1 = "<?php system("           nocase
        $p2 = "<?php exec("             nocase
        $p3 = "eval(base64_decode("     nocase
        $p4 = "passthru($_"             nocase
        $p5 = "shell_exec($_"           nocase
        $p6 = "preg_replace.*\/e"       nocase
        $p7 = "assert($_"               nocase
        $p8 = "base64_decode(gzinflate" nocase
    condition:
        2 of them
}

rule Webshell_ASPNet {
    meta:
        description = "ASP.NET webshell patterns"
        severity    = "high"
        mitre_tech  = "T1505.003"
    strings:
        $a1 = "Response.Write(Shell.Run" nocase
        $a2 = "WScript.Shell"            nocase
        $a3 = "cmd.exe /c"               nocase
        $a4 = "Process.Start"            nocase
        $a5 = "<%@ Page"                 nocase
        $a6 = "Assembly.Load"            nocase
    condition:
        $a5 and any of ($a1, $a2, $a3, $a4, $a6)
}

/* ──── Lateral Movement ──────────────────────────────────────────────────── */
rule Lateral_Movement_SMB_PsExec {
    meta:
        description = "PsExec-style lateral movement via SMB"
        severity    = "high"
        mitre_tactic = "Lateral Movement"
        mitre_tech  = "T1021.002"
    strings:
        $a = "PSEXESVC"     ascii wide
        $b = "psexec"       ascii wide nocase
        $c = "\\ADMIN$"     ascii wide
        $d = "\\IPC$"       ascii wide
        $e = "svcctl"       ascii
        $f = "RemComSvc"    ascii wide
    condition:
        2 of them
}

/* ──── Data Exfiltration ─────────────────────────────────────────────────── */
rule Data_Exfiltration_Indicators {
    meta:
        description = "Data exfiltration tool indicators"
        severity    = "high"
        mitre_tactic = "Exfiltration"
        mitre_tech  = "T1041"
    strings:
        $a1 = "7-Zip"           ascii nocase
        $a2 = "winrar"          ascii nocase
        $a3 = ".rar\x00"        ascii
        $a4 = "ftp://"          ascii nocase
        $a5 = "RETR "           ascii
        $a6 = "megasync"        ascii nocase
        $b1 = "clipboard"       ascii nocase
        $b2 = "keylog"          ascii nocase
        $b3 = "screenshot"      ascii nocase
    condition:
        3 of them and filesize < 5MB
}

/* ──── TOR ───────────────────────────────────────────────────────────────── */
rule TOR_Traffic_Indicators {
    meta:
        description = "TOR network traffic and browser indicators"
        severity    = "medium"
        mitre_tech  = "T1090.003"
    strings:
        $a = "obfs4proxy"    ascii nocase
        $b = "meek-client"   ascii nocase
        $c = "snowflake"     ascii nocase
        $d = "tor-browser"   ascii nocase
        $e = "Tor Browser"   wide ascii
        $f = ".onion"        ascii
    condition:
        2 of them
}

/* ──── High-Entropy Payloads (encoded malware) ───────────────────────────── */
rule High_Entropy_Executable {
    meta:
        description = "High entropy PE section — likely packed/encrypted malware"
        severity    = "medium"
    condition:
        pe.is_pe and
        for any i in (0..pe.number_of_sections) : (
            math.entropy(pe.sections[i].raw_data_offset,
                         pe.sections[i].raw_data_size) >= 7.0
            and pe.sections[i].raw_data_size > 4096
        )
}
