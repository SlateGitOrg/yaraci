rule SUSP_PS_EncodedCommand_Hidden : powershell script
{
    meta:
        author = "yaraci lab"
        description = "PowerShell started with an encoded command and a hidden window, a common loader pattern"
        date = "2026-10-01"
        reference = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe"
        severity = "medium"
        score = 60
    strings:
        $ps = "powershell" nocase
        $enc1 = "-EncodedCommand" nocase
        $enc2 = /-enc?\s+[A-Za-z0-9+\/]{40,400}={0,2}/ nocase
        $hidden = /-w(indowstyle)?\s+hidden/ nocase
    condition:
        filesize < 1MB and $ps and any of ($enc*) and $hidden
}

rule MAL_Webshell_PHP_EvalBase64 : php webshell
{
    meta:
        author = "yaraci lab"
        description = "PHP file that evaluates base64-decoded code, the classic one-line webshell shape"
        date = "2026-10-01"
        reference = "https://www.php.net/manual/en/function.eval.php"
        severity = "high"
        score = 80
    strings:
        $php = "<?php"
        $e1 = /eval\s{0,8}\(\s{0,8}base64_decode\s{0,8}\(/ nocase
        $e2 = /assert\s{0,8}\(\s{0,8}base64_decode\s{0,8}\(/ nocase
        $e3 = /eval\s{0,8}\(\s{0,8}gzinflate\s{0,8}\(\s{0,8}base64_decode/ nocase
    condition:
        filesize < 512KB and $php and any of ($e*)
}

rule SUSP_SH_Dropper_CurlChmodExec : linux script
{
    meta:
        author = "yaraci lab"
        description = "Shell script that downloads to /tmp, marks the file executable and runs it detached"
        date = "2026-10-02"
        reference = "https://attack.mitre.org/techniques/T1105/"
        severity = "medium"
        score = 55
    strings:
        $dl1 = /curl\s+-[A-Za-z]{1,8}\s+https?:\/\/[^\s]{4,200}\s+-o\s+\/tmp\//
        $dl2 = /wget\s+-q\s+https?:\/\/[^\s]{4,200}\s+-O\s+\/tmp\//
        $chmod = /chmod\s+(\+x|7[0-7][0-7])\s+\/tmp\//
        $exec = /nohup\s+\/tmp\//
    condition:
        filesize < 256KB and any of ($dl*) and $chmod and $exec
}
