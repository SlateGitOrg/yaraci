// File-type helper rules. Private: they never alert on their own and are
// referenced by detection rules as cheap, content-based guards.

private rule INFO_FileType_PE
{
    meta:
        author = "yaraci lab"
        description = "Helper: MZ header with a PE signature at e_lfanew"
        date = "2026-10-01"
    condition:
        uint16(0) == 0x5A4D and filesize > 0x40 and uint32(uint32(0x3C)) == 0x00004550
}

private rule INFO_FileType_ELF
{
    meta:
        author = "yaraci lab"
        description = "Helper: ELF magic 7F 45 4C 46 at offset 0"
        date = "2026-10-01"
    condition:
        uint32(0) == 0x464C457F
}

private rule INFO_FileType_OLE
{
    meta:
        author = "yaraci lab"
        description = "Helper: OLE2 compound document signature D0 CF 11 E0 A1 B1 1A E1"
        date = "2026-10-01"
    condition:
        uint32be(0) == 0xD0CF11E0 and uint32be(4) == 0xA1B11AE1
}
