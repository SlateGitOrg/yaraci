rule PUA_PE_Packer_UPX : packer pe
{
    meta:
        author = "yaraci lab"
        description = "PE file packed with UPX (UPX0/UPX1 sections and the UPX! stub marker)"
        date = "2026-10-03"
        reference = "https://upx.github.io/"
        severity = "low"
        score = 30
    strings:
        $s0 = "UPX0"
        $s1 = "UPX1"
        $sig = "UPX!"
    condition:
        INFO_FileType_PE and filesize < 20MB and all of them
}

rule MAL_ELF_CoinMiner_Stratum : miner elf
{
    meta:
        author = "yaraci lab"
        description = "ELF binary embedding a stratum mining-pool URL and miner tuning options"
        date = "2026-10-03"
        reference = "https://attack.mitre.org/techniques/T1496/"
        severity = "high"
        score = 75
    strings:
        $pool = "stratum+tcp://"
        $pool_tls = "stratum+ssl://"
        $opt1 = "--donate-level"
        $opt2 = "randomx" nocase
        $opt3 = "\"max-cpu-usage\""
    condition:
        INFO_FileType_ELF and filesize < 15MB and any of ($pool*) and 1 of ($opt*)
}

rule MAL_Doc_OLE_AutoOpenShell : maldoc office
{
    meta:
        author = "yaraci lab"
        description = "OLE2 document whose macro auto-runs and creates a WScript shell object"
        date = "2026-10-04"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
        severity = "high"
        score = 70
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $exec1 = "WScript.Shell" nocase
        $exec2 = "CreateObject" nocase
        $exec3 = "Shell" fullword
    condition:
        INFO_FileType_OLE and any of ($auto*) and 2 of ($exec*)
}
