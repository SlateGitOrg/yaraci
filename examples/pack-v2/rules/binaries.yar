rule PUA_PE_Packer_UPX : packer pe
{
    meta:
        author = "yaraci lab"
        description = "PE file packed with UPX (UPX0 section, UPX! stub marker and version banner)"
        date = "2026-10-12"
        reference = "https://upx.github.io/"
        severity = "low"
        score = 30
    strings:
        $s0 = "UPX0"
        $sig = "UPX!"
        $ver = /UPX [0-9]\.[0-9]{2}/
    condition:
        INFO_FileType_PE and filesize < 20MB and all of them
}

rule MAL_ELF_Miner_Stratum : miner elf
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
