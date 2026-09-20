"""Built-in signatures for the Top Antywir prototype."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class HashSignature:
    name: str
    sha256: str
    severity: str
    description: str


@dataclass(frozen=True)
class PatternSignature:
    name: str
    pattern: re.Pattern[str]
    severity: str
    description: str


HASH_SIGNATURES: tuple[HashSignature, ...] = (
    HashSignature(
        name="EICAR-Test-File",
        sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        severity="high",
        description="Harmless standard antivirus test file (EICAR).",
    ),
)


PATTERN_SIGNATURES: tuple[PatternSignature, ...] = (
    # ── Download & execute ──────────────────────────────────────────────────────
    PatternSignature(
        name="Suspicious-Curl-Pipe-Shell",
        pattern=re.compile(
            r"(curl|wget)\s+[^|;&]+[|]\s*(sh|bash|zsh|python|python3)\b",
            re.IGNORECASE,
        ),
        severity="medium",
        description="Downloads code and executes it directly through a shell.",
    ),
    PatternSignature(
        name="Suspicious-Base64-Exec",
        pattern=re.compile(
            r"(base64\s+-d|base64\s+--decode).{0,80}[|]\s*(sh|bash|python|python3|perl)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="medium",
        description="Decodes base64 data and pipes it to a shell for execution.",
    ),
    PatternSignature(
        name="Suspicious-PowerShell-DownloadString",
        pattern=re.compile(
            r"(Net\.WebClient|Invoke-WebRequest|iwr)\b.*DownloadString|IEX\s*\(",
            re.IGNORECASE,
        ),
        severity="medium",
        description="PowerShell downloads and potentially executes remote content.",
    ),
    # ── Encoded / obfuscated commands ───────────────────────────────────────────
    PatternSignature(
        name="Suspicious-Encoded-Powershell",
        pattern=re.compile(
            r"powershell(?:\.exe)?\s+.*(-enc|-encodedcommand)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="medium",
        description="Runs an encoded (obfuscated) PowerShell command.",
    ),
    PatternSignature(
        name="Suspicious-Python-Dynamic-Eval",
        pattern=re.compile(
            r"eval\s*\(\s*(?:compile|__import__|base64\.b64decode)\s*\(",
            re.IGNORECASE,
        ),
        severity="medium",
        description="Dynamic Python code evaluation — possible obfuscation or dropper.",
    ),
    # ── Reverse shells ──────────────────────────────────────────────────────────
    PatternSignature(
        name="Reverse-Shell-Bash-TCP",
        pattern=re.compile(
            r"bash\s+-i\s+>&\s*/dev/tcp/",
            re.IGNORECASE,
        ),
        severity="high",
        description="Classic bash reverse shell connecting over /dev/tcp.",
    ),
    PatternSignature(
        name="Reverse-Shell-Netcat",
        pattern=re.compile(
            r"nc(?:at)?\s+.*-e\s+(?:/bin/)?(?:sh|bash|cmd|powershell)",
            re.IGNORECASE,
        ),
        severity="high",
        description="Netcat spawning an interactive shell on a remote connection.",
    ),
    PatternSignature(
        name="Reverse-Shell-Python",
        pattern=re.compile(
            r"socket\.connect\s*\(.*\).*os\.(dup2|execl|execve|system)",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="high",
        description="Python reverse shell using socket and os exec primitives.",
    ),
    PatternSignature(
        name="Reverse-Shell-Perl",
        pattern=re.compile(
            r"perl\s+.*-e\s+.*socket.*connect.*exec",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="high",
        description="Perl one-liner reverse shell.",
    ),
    # ── Process / memory injection ──────────────────────────────────────────────
    PatternSignature(
        name="Suspicious-Process-Injection",
        pattern=re.compile(
            r"VirtualAlloc(?:Ex)?\s*\(|WriteProcessMemory\s*\(|CreateRemoteThread\s*\(",
            re.IGNORECASE,
        ),
        severity="high",
        description="Win32 API calls commonly used for process injection.",
    ),
    # ── Credential access ───────────────────────────────────────────────────────
    PatternSignature(
        name="Credential-Dump-Mimikatz",
        pattern=re.compile(
            r"sekurlsa\s*::\s*logonpasswords|lsadump\s*::\s*(?:sam|dcsync)",
            re.IGNORECASE,
        ),
        severity="high",
        description="Mimikatz credential extraction commands.",
    ),
    PatternSignature(
        name="Suspicious-Shadow-Copy-Delete",
        pattern=re.compile(
            r"vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete",
            re.IGNORECASE,
        ),
        severity="high",
        description="Deletes Volume Shadow Copies — ransomware behaviour.",
    ),
    # ── Defence evasion ─────────────────────────────────────────────────────────
    PatternSignature(
        name="Suspicious-Disable-Defender",
        pattern=re.compile(
            r"Set-MpPreference\s+-Disable(?:Realtime|Behavior|IO)Monitoring\s+\$true",
            re.IGNORECASE,
        ),
        severity="high",
        description="Disables Windows Defender real-time monitoring.",
    ),
    PatternSignature(
        name="Suspicious-UAC-Bypass",
        pattern=re.compile(
            r"eventvwr(?:\.exe)?\b.*reg.*shell|fodhelper(?:\.exe)?\b",
            re.IGNORECASE,
        ),
        severity="high",
        description="Known UAC bypass technique (eventvwr/fodhelper hijack).",
    ),
    # ── Persistence ─────────────────────────────────────────────────────────────
    PatternSignature(
        name="Suspicious-Registry-Run-Key",
        pattern=re.compile(
            r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER)\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            re.IGNORECASE,
        ),
        severity="medium",
        description="Adds or reads a Windows autorun registry key.",
    ),
    PatternSignature(
        name="Suspicious-Cron-Download",
        pattern=re.compile(
            r"\(\s*crontab\b.*\n.*(?:curl|wget)\b|crontab.*-l.*(?:curl|wget)\b",
            re.IGNORECASE,
        ),
        severity="medium",
        description="Cron job that downloads content from the internet.",
    ),
    # ── Privilege escalation ────────────────────────────────────────────────────
    PatternSignature(
        name="Suspicious-Chmod-Execute",
        pattern=re.compile(
            r"chmod\s+[+]?x\s+\S+\s*[;&\n]\s*(?:\./|/tmp/)\S+",
            re.IGNORECASE,
        ),
        severity="medium",
        description="File made executable and immediately run from a suspicious path.",
    ),
    PatternSignature(
        name="Suspicious-SUID-Bit",
        pattern=re.compile(
            r"chmod\s+[u+]*s\s+|chmod\s+[0-9]*[46][0-9]{3}\s+",
            re.IGNORECASE,
        ),
        severity="medium",
        description="Sets the SUID/SGID bit, which can enable privilege escalation.",
    ),
)
