rule zipExtensionFound{
    strings:
        $link1 = ".zip"
    condition:
        any of them
}

rule PE_FILE_HEADER{
    meta:
        description = "YARA rules for pe detection in the NIDS program"
        author = "cybersecadventures01123"
        reference = "https://www.nextron-systems.com/2018/01/22/write-yara-rules-detect-embedded-exe-files-ole-objects/"
    strings:
        $hex1 = "546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f6465" ascii
        $hex1_txt = "This program cannot be run in DOS mode"
        $hex2 = "4b45524e454c33322e646c6c" ascii
        $hex2_txt = "KERNEL32.dll" nocase
        $hex3 = {4D 5A 40 00} // MZ@
        //$hex3_txt = "MZ@"    
    condition:
        any of them
}