rule MAL_RansomNote_Generic : ransomware note
{
    meta:
        author = "yaraci lab"
        description = "Ransom-note text: encryption claim plus at least two payment or recovery cues"
        date = "2026-10-05"
        reference = "https://attack.mitre.org/techniques/T1486/"
        severity = "critical"
        score = 90
    strings:
        $claim1 = "your files have been encrypted" nocase
        $claim2 = "do not rename encrypted files" nocase
        $cue1 = "bitcoin" nocase
        $cue2 = "decryptor" nocase
        $cue3 = ".onion" nocase
        $cue4 = "private key" nocase
    condition:
        filesize < 64KB and any of ($claim*) and 2 of ($cue*)
}
