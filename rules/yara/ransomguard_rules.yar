/*
    RansomGuard Standard YARA Rules - Signature Database v2.4
    Includes real rules for EICAR, WannaCry, Generic Ransomware Note Storms, PowerShell Evasion, and Packed PE Binaries.
*/

rule EICAR_Test_File {
    meta:
        description = "Detects EICAR Standard Antivirus Test File"
        author = "RansomGuard Security Research"
        severity = "CRITICAL"
        category = "TEST_SIGNATURE"
    strings:
        $eicar_str = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
    condition:
        $eicar_str
}

rule WannaCry_Ransomware_Strings {
    meta:
        description = "Detects WannaCry / WanaDecryptor ransomware artifacts and string patterns"
        author = "RansomGuard Security Research"
        severity = "CRITICAL"
        category = "RANSOMWARE"
    strings:
        $w1 = "wnry@cl2p" ascii wide
        $w2 = "WanaCrypt0r" ascii wide
        $w3 = "c.wnry" ascii wide
        $w4 = "t.wnry" ascii wide
        $w5 = "taskse.exe" ascii wide
        $w6 = "Please send $300 worth of Bitcoin" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of ($w*)
}

rule Ransomware_Note_Keyword_Storm {
    meta:
        description = "Detects files containing dense ransomware decryption instruction keywords"
        author = "RansomGuard Security Research"
        severity = "HIGH"
        category = "RANSOM_NOTE"
    strings:
        $k1 = "your files have been encrypted" ascii wide nocase
        $k2 = "how to decrypt files" ascii wide nocase
        $k3 = "decryption key" ascii wide nocase
        $k4 = "restore your files" ascii wide nocase
        $k5 = "bitcoin" ascii wide nocase
        $k6 = "tor browser" ascii wide nocase
    condition:
        3 of ($k*)
}

rule Suspicious_PowerShell_Obfuscation {
    meta:
        description = "Detects obfuscated or hidden PowerShell execution commands"
        author = "RansomGuard Security Research"
        severity = "MEDIUM"
        category = "SCRIPT_EVASION"
    strings:
        $ps1 = "Invoke-Expression" ascii wide nocase
        $ps2 = " -WindowStyle Hidden" ascii wide nocase
        $ps3 = " -EncodedCommand" ascii wide nocase
        $ps4 = "[System.Text.Encoding]::UTF8.GetString" ascii wide nocase
        $ps5 = "DownloadString(" ascii wide nocase
    condition:
        2 of ($ps*)
}

rule High_Entropy_Packed_PE {
    meta:
        description = "Detects PE files with suspicious packed/compressed characteristics"
        author = "RansomGuard Security Research"
        severity = "MEDIUM"
        category = "PACKED_BINARY"
    strings:
        $mz = "MZ"
        $pack1 = ".rsrc_pack" ascii
        $pack2 = "UPX0" ascii
        $pack3 = "UPX1" ascii
    condition:
        uint16(0) == 0x5A4D and any of ($pack*)
}
