rule SUSP_Generic_LongBase64Blob : obfuscation
{
    meta:
        author = "yaraci lab"
        description = "Very long base64 run, often an embedded encoded payload"
        date = "2026-10-12"
        severity = "low"
    strings:
        $b64 = /[A-Za-z0-9+\/]{300,}={0,2}/
    condition:
        $b64
}

rule test_rule
{
    strings:
        $mz = "MZ"
    condition:
        $mz at 0 and filesize > 2MB and filesize < 1MB
}
