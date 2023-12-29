Option Explicit

REM Microsoft Corporation
REM (c) 2005 All rights reserved
REM
REM Test-signed private detection script
REM 
REM Also supported is the detection, addition,
REM     and removal of the test certificate

const HKEY_LOCAL_MACHINE = &H80000002

const PRIVATEPKGKEY = "SOFTWARE\Microsoft\Windows\CurrentVersion\PackagesForTestingPurposesOnly"
REM This is the SHA1 test root
const TESTCERTKEY =   "SOFTWARE\Microsoft\SystemCertificates\Root\Certificates\2BD63D28D7BCD0E251195AEB519243C13142EBC3"
const SNSIGNKEY =     "SOFTWARE\Microsoft\StrongName\Verification\*,31bf3856ad364e35"
REM This is the SHA1 test root name
const CERTNAME     = "Microsoft Test Root Authority"
REM This is the SHA2 test root and name
REM Both SHA1 and SHA2 test root are defined in %sdxroot%\ds\security\cryptoapi\pki\manifests\CAPI2_test_root.man
const SHA2_TESTCERTKEY = "SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\8A334AA8052DD244A647306A76B8178FA215F344"
const SHA2_CERTNAME     = "Microsoft Testing Root Certificate Authority 2010"

const BLOB     = "Blob"
const COMMENTS = "Comments"
const DONOTREMOVE = "DoNotRemove"
const TESTSTRING  = " (For testing purposes only)"

const COMPUTER = "."

const HELP_ARGUMENT   = "help"
const HELP_ARGUMENT_2 = "?"
const HELP_ARGUMENT_3 = "h"
const ADD_ARGUMENT    = "a"
const DELETE_ARGUMENT = "d"
const INSTALL_ARGUMENT   = "i"
const UNINSTALL_ARGUMENT = "u"

const DEBUG_MODE = FALSE

dim StdOut

Main
'--------------------------------------------------------------------------
public sub Main
    Set StdOut = WScript.StdOut

    dim errorCode
    dim Action
    Action = ProcessArguments()

    select case Action
    case 0:
        ' Detect privates and test root certificate
        dim testFix, testCert
        testFix = FindTestHotfixes()
        testCert = FindTestCert()

        if (testFix and testCert) then 
            errorCode = 1
        elseif (testFix and not testCert) then
            StdOut.WriteLine "WARNING: Test certificate not installed, but test hotfixes detected"
            errorCode = 2
        elseif (testCert and not testFix) then
            if FindDNRFlag() then
                StdOut.WriteLine "Test certificate is installed and protected"
                errorCode = 1
            else
                StdOut.WriteLine "WARNING: Test certificate is installed, but it may no longer be needed"
                StdOut.WriteLine "         and may be removed as no test hotfixes were detected"
                errorCode = 3
            end if
        else
            StdOut.WriteLine "No test certificate detected"
            StdOut.WriteLine "No test hotfixes found"
            errorCode = 0
        end if
    case 1:
        ' Delete test root certificate
        dim DelCert
        DelCert = DelTestRoot()
        if DelCert = 0 then
            StdOut.WriteLine "Certificate [ " & CERTNAME & " ] already deleted or has been removed"
            errorCode = 0
        else
            StdOut.WriteLine "Unable to remove certificate [ " & CERTNAME & " ]"
            errorCode = 1
        end if

        DelCert = DelSHA2TestRoot()
        if DelCert = 0 then
            StdOut.WriteLine "Certificate [ " & SHA2_CERTNAME & " ] already deleted or has been removed"
            errorCode = 0
        else
            StdOut.WriteLine "Unable to remove certificate [ " & SHA2_CERTNAME & " ]"
            errorCode = 1
        end if

        ' Delete SN signed key
        dim DelSnSign
        DelSnSign = DelSnSignKey() 
        if DelSnSign = 0 then
            StdOut.WriteLine "Registry entry for SN signed binaries already deleted or has been removed"
            errorCode = 0
        else
            StdOut.WriteLine "Unable to remove registry entry for SN signed binaries"
            errorCode = 1
        end if

    case 2:
        ' Add test root certificate
        dim AddCert
        AddCert = AddTestRoot()
        if AddCert = 0 then
            StdOut.WriteLine "Certificate [ " & CERTNAME & " ] already existed or has been added"
            errorCode = 0
        else
            StdOut.WriteLine "Unable to add certificate [ " & CERTNAME & " ]"
            errorCode = 1
        end if

        AddCert = AddSHA2TestRoot()
        if AddCert = 0 then
            StdOut.WriteLine "Certificate [ " & SHA2_CERTNAME & " ] already existed or has been added"
            errorCode = 0
        else
            StdOut.WriteLine "Unable to add certificate [ " & SHA2_CERTNAME & " ]"
            errorCode = 1
        end if

        ' Add SN sign key
        dim AddSnSign
        AddSnSign = AddSnSignKey() 
        if AddSnSign = 0 then
            StdOut.WriteLine "Registry entry for SN signed binary already existed or has been added"
            errorCode = 0
        else
            StdOut.WriteLine "Unable to add registry entry for SN signed binaries"
            errorCode = 1
        end if

    case 3:
        ' INSTALL-time scenario
        errorCode = 0

        ' detect test certificate
        if FindTestCert() then
            ' detect test-signed privates
            ' if no test-signed fixes exist...
            if not FindTestHotfixes() then
                ' set global do not remove flag,
                '   because of the test cert
                if SetDNRFlag() <> 0 then
                    StdOut.WriteLine "Unable to set protect bit on [ " & CERTNAME & " ]"
                    errorCode = 1
                end if
            end if
        end if

        'install test cert
        if AddTestRoot() <> 0 then
            StdOut.WriteLine "Unable to add certificate [ " & CERTNAME & " ]"
            errorCode = 1
        end if

        'install sha2 test cert
        if AddSHA2TestRoot() <> 0 then
            StdOut.WriteLine "Unable to add certificate [ " & SHA2_CERTNAME & " ]"
            errorCode = 1
        end if

        'add sn sign key
        if AddSnSignKey() <> 0 then
            StdOut.WriteLine "Unable to add registry entries for SN Signed binaries"
            errorCode = 1
        end if

    case 4:
        ' UNINSTALL-time scenario
        errorCode = 0

        'remove the test cert
        ' if global do not remove flag set
        if FindDNRFlag() then
            ' ...nothing to do!
        else
            ' if no test-signed fixes remain, remove test cert
            if not FindTestHotfixes() then
                if DelTestRoot() <> 0 then
                    StdOut.WriteLine "Unable to remove certificate [ " & CERTNAME & " ]"
                    errorCode = 1
                end if

                if DelSHA2TestRoot() <> 0 then
                    StdOut.WriteLine "Unable to remove certificate [ " & SHA2_CERTNAME & " ]"
                    errorCode = 1
                end if
            end if
        end if

        'remove SN signed key
        if not FindTestHotfixes() then
            if DelSnSignKey() <> 0 then
               StdOut.WriteLine "Unable to remove registry entries for SN signed binaries"
               errorCode = 1
            end if
        end if

    case 5:
        Usage
    end select

    if DEBUG_MODE then StdOut.WriteLine "Exiting with code " & errorCode
    Set StdOut = Nothing
    WScript.Quit errorCode
end sub

public sub Usage
    StdOut.WriteLine WScript.ScriptName & " - Test hotfix and test certificate detection tool" & vbCrLf
    StdOut.WriteLine "Usage: " & WScript.ScriptName & " : to find and list any test hotfixes"
    StdOut.WriteLine "       " & Space(Len(WScript.ScriptName)) & "   along with detecting test certificate"
    StdOut.WriteLine "    or " & WScript.ScriptName & " [/" & ADD_ARGUMENT & "] [/" & DELETE_ARGUMENT & "] [/" & INSTALL_ARGUMENT & "] [/" & UNINSTALL_ARGUMENT & "]"
    StdOut.WriteLine "         /" & ADD_ARGUMENT & " : Add the test certificate if not found"
    StdOut.WriteLine "         /" & DELETE_ARGUMENT & " : Delete the test certificate if found"
    StdOut.WriteLine "         /" & INSTALL_ARGUMENT & " : Perform operations for a hotfix install"
    StdOut.WriteLine "         /" & UNINSTALL_ARGUMENT & " : Perform operations for a hotfix uninstall"
    StdOut.WriteLine "         /" & HELP_ARGUMENT & " or /" & HELP_ARGUMENT_2 & " or /" & HELP_ARGUMENT_3 & " : displays usage"
end sub

private function ProcessArguments() 
    dim ArgNamed, ArgUnnamed
    Set ArgNamed = WScript.Arguments.Named
    Set ArgUnnamed = WScript.Arguments.Unnamed

    if DEBUG_MODE then StdOut.WriteLine "There are " & ArgNamed.length & " named arguments."
    if DEBUG_MODE then StdOut.WriteLine "There are " & ArgUnnamed.length & " unnamed arguments."

    if (ArgNamed.Exists(HELP_ARGUMENT) OR ArgNamed.Exists(HELP_ARGUMENT_2) OR ArgNamed.Exists(HELP_ARGUMENT_3)) then
        set ArgNamed = Nothing
        set ArgUnnamed = Nothing
        ProcessArguments = 5
        if DEBUG_MODE then StdOut.WriteLine "Help requested"        
        Exit function
    end if

    if ArgUnnamed.Count > 0 then
        if DEBUG_MODE then StdOut.WriteLine "Unnamed arguments found"
        StdOut.WriteLine "Unsupported arguments provided."
        ProcessArguments = 3
    else
        if ArgNamed.Count > 0 then
            if ArgNamed.Exists(DELETE_ARGUMENT) then
                ProcessArguments = 1
            elseif ArgNamed.Exists(ADD_ARGUMENT) then
                ProcessArguments = 2
            elseif ArgNamed.Exists(INSTALL_ARGUMENT) then
                ProcessArguments = 3
            elseif ArgNamed.Exists(UNINSTALL_ARGUMENT) then
                ProcessArguments = 4
            else
                StdOut.WriteLine "Ignoring unknown arguments."
            end if 
        else
            ' No arguments provided, do detection
            ProcessArguments = 0
        end if
    end if

    set ArgNamed = Nothing
    set ArgUnnamed = Nothing
end function

REM Returns true if the test certificate is installed
REM Returns false if test cert is not installed
public function FindTestCert
    dim strKeyPath
    dim oReg

    dim FoundTest
    FoundTest = false

    Set oReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & COMPUTER & "\root\default:StdRegProv")

    dim bytes()
    redim bytes(0)

    strKeyPath = TESTCERTKEY
    oReg.GetBinaryValue HKEY_LOCAL_MACHINE,strKeyPath,BLOB,bytes

    dim ErrTest
    On Error Resume Next
    ErrTest = UBound(bytes)
    if Err.Number > 0 then 
        FoundTest = false
    else
        FoundTest = true
        'ErrTest should be one of the sizes below... the warning below could cause confusion
        'ErrTest = 4124 or ErrTest = 4212 or ErrTest = 4240 or ErrTest = 4260
        'StdOut.WriteLine "WARNING: Test certificate key found, but test certificate size doesn't match an expected value.  Byte count: " & ErrTest
    end if
    On Error Goto 0
    
    if FoundTest then
        StdOut.WriteLine "DETECTED: certificate [" & CERTNAME & "]"
    end if

    ' Find the SHA2 test root
    strKeyPath = SHA2_TESTCERTKEY
    oReg.GetBinaryValue HKEY_LOCAL_MACHINE,strKeyPath,BLOB,bytes

    On Error Resume Next
    ErrTest = UBound(bytes)
    if Err.Number > 0 then 
        FoundTest = false
    else
        FoundTest = true
        'ErrTest should be one of the sizes below... the warning below could cause confusion
        'ErrTest = 4124 or ErrTest = 4212 or ErrTest = 4240 or ErrTest = 4260
        'StdOut.WriteLine "WARNING: Test certificate key found, but test certificate size doesn't match an expected value.  Byte count: " & ErrTest
    end if
    On Error Goto 0
    
    if FoundTest then
        StdOut.WriteLine "DETECTED: certificate [" & SHA2_CERTNAME & "]"
    end if


    FindTestCert = FoundTest
end function

REM Returns true if there are 0 or more test hotfixes installed
REM Returns false otherwise
public function FindTestHotfixes
    dim strKeyPath, strValuePath, strValue, subKey
    dim oReg
    dim arrSubKeys()

    dim FoundTest
    FoundTest = false

    Set oReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & COMPUTER & "\root\default:StdRegProv")

    strKeyPath = PRIVATEPKGKEY
    oReg.EnumKey HKEY_LOCAL_MACHINE, strKeyPath, arrSubKeys

    For Each subkey In arrSubKeys
            FoundTest = true
            if DEBUG_MODE then StdOut.WriteLine "DETECTED: Test hotfix " & subkey 
    Next
    FindTestHotfixes = FoundTest
end function

REM Returns 0 if uninstallation succeeded
REM Returns 1 if uninstallation failed
REM Any other return value indicates an error in the script
public function DelTestRoot
    dim Return
    Return = 2
    
    dim oReg
    Set oReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & COMPUTER & "\root\default:StdRegProv")

    'Delete test root certificate key
    'NOTE: this will remove the DoNotRemove bit
    Return = oReg.DeleteKey(HKEY_LOCAL_MACHINE, TESTCERTKEY)
    if Err.Number = 0 then
        if Return = 0 then
            if DEBUG_MODE then StdOut.WriteLine "[ " & CERTNAME & " ] successfully deleted"
        else
            if DEBUG_MODE then StdOut.WriteLine "[ " & CERTNAME & " ] was already deleted"
            Return = 0
        end if
    else
        StdOut.WriteLine "Failed trying to remove SHA1 test certificate with error number " & Err.Number
        Return = 1
    end if

    DelTestRoot = Return
end function

REM Returns 0 if uninstallation succeeded
REM Returns 1 if uninstallation failed
REM Any other return value indicates an error in the script
public function DelSHA2TestRoot
    dim Return
    Return = 2
    
    dim oReg
    Set oReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & COMPUTER & "\root\default:StdRegProv")

    'Delete the SHA2 test root key
    Return = oReg.DeleteKey(HKEY_LOCAL_MACHINE, SHA2_TESTCERTKEY)
    if Err.Number = 0 then
        if Return = 0 then
            if DEBUG_MODE then StdOut.WriteLine "[ " & SHA2_CERTNAME & " ] successfully deleted"
        else
            if DEBUG_MODE then StdOut.WriteLine "[ " & SHA2_CERTNAME & " ] was already deleted"
            Return = 0
        end if
    else
        StdOut.WriteLine "Failed trying to remove SHA2 test certificate with error number " & Err.Number
        Return = 1
    end if

    DelSHA2TestRoot = Return
end function

REM Returns 0 if uninstallation succeeded
REM Returns 1 if uninstallation failed
REM Any other return value indicates an error in the script
public function DelSnSignKey
    dim Return
    Return = 2

    dim oReg
    Set oReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & COMPUTER & "\root\default:StdRegProv")
    Return = oReg.DeleteKey(HKEY_LOCAL_MACHINE, SNSIGNKEY)
    
    if Err.Number = 0 then
        if Return = 0 then
            if DEBUG_MODE then StdOut.WriteLine "SN sign key successfully deleted"
        else
            if DEBUG_MODE then StdOut.WriteLine "SN sign key was already deleted"
            Return = 0
        end if
    else
        StdOut.WriteLine "Failed trying to remove SN sign key with error number " & Err.Number
        Return = 1
    end if

    DelSnSignKey = Return
end function

REM Returns 0 if installation succeeded
REM Returns 1 if installation failed
REM Any other return value indicates an error in the script
public function AddTestRoot
    dim Return
    Return = 2
    
    dim oReg
    Set oReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & COMPUTER & "\root\default:StdRegProv")

    'Create test root key
    Return = oReg.CreateKey(HKEY_LOCAL_MACHINE, TESTCERTKEY)
    if Err.Number = 0 then
        if DEBUG_MODE then StdOut.WriteLine "Test cert key successfully created or already existed"
        Return = 0
    else
        if DEBUG_MODE then StdOut.WriteLine "Failed creating test cert key with error number " & Err.Number
        Return = 1
    end if
    if Return > 0 then 
        AddTestRoot = Return
        exit function
    end if

    'Add test root certificate
    dim Cert
    Cert = Array(&H03,&H00,&H00,&H00,&H01,&H00,&H00,&H00,&H14,&H00,&H00,&H00,&H2b,&Hd6,&H3d,&H28,&Hd7,&Hbc,&Hd0,&He2,&H51,&H19,&H5a,&Heb,&H51,&H92,&H43,&Hc1,&H31,&H42,&Heb,&Hc3,&H20,&H00,&H00,&H00,&H01,&H00,&H00,&H00,&Hf1,&H0f,&H00,&H00,&H30,&H82,&H0f,&Hed,&H30,&H82,&H0f,&H16,&Ha0,&H03,&H02,&H01,&H02,&H02,&H10,&H5f,&Hea,&H4f,&Hd2,&Hf2,&H1d,&H43,&H10,&Hb6,&He8,&H54,&H3e,&Hd8,&H95,&H26,&H18,&H30,&H0d,&H06,&H09,&H2a,&H86,&H48,&H86,&Hf7,&H0d,&H01,&H01,&H04,&H05,&H00,&H30,&H75,&H31,&H2b,&H30,&H29,&H06,&H03,&H55,&H04,&H0b,&H13,&H22,&H43,&H6f,&H70,&H79,&H72,&H69,&H67,&H68,&H74,&H20,&H28,&H63,&H29,&H20,&H31,&H39,&H39,&H39,&H20,&H4d,&H69,&H63,&H72,&H6f,&H73,&H6f,&H66,&H74,&H20,&H43,&H6f,&H72,&H70,&H2e,&H31,&H1e,&H30,&H1c,&H06,&H03,&H55,&H04,&H0b,&H13,&H15,&H4d,&H69,&H63,&H72,&H6f,&H73,&H6f,&H66,&H74,&H20,&H43,&H6f,&H72,&H70,&H6f,&H72,&H61,&H74,&H69,&H6f,&H6e,&H31,&H26,&H30,&H24,&H06,&H03,&H55,&H04,&H03,&H13,&H1d,&H4d,&H69,&H63,&H72,&H6f,&H73,&H6f,&H66,&H74,&H20,&H54,&H65,&H73,&H74,&H20,&H52,&H6f,&H6f,&H74,&H20,&H41,&H75,&H74,&H68,&H6f,&H72,&H69,&H74,&H79,&H30,&H1e,&H17,&H0d,&H39,&H39,&H30,&H31,&H31,&H30,&H30,&H37,&H30,&H30,&H30,&H30,&H5a,&H17,&H0d,&H32,&H30,&H31,&H32,&H33,&H31,&H30,&H37,&H30,&H30,&H30,&H30,&H5a,&H30,&H75,&H31,&H2b,&H30,&H29,&H06,&H03,&H55,&H04,&H0b,&H13,&H22,&H43,&H6f,&H70,&H79,&H72,&H69,&H67,&H68,&H74,&H20,&H28,&H63,&H29,&H20,&H31,&H39,&H39,&H39,&H20,&H4d,&H69,&H63,&H72,&H6f,&H73,&H6f,&H66,&H74,&H20,&H43,&H6f,&H72,&H70,&H2e,&H31,&H1e,&H30,&H1c,&H06,&H03,&H55,&H04,&H0b,&H13,&H15,&H4d,&H69,&H63,&H72,&H6f,&H73,&H6f,&H66,&H74,&H20,&H43,&H6f,&H72,&H70,&H6f,&H72,&H61,&H74,&H69,&H6f,&H6e,&H31,&H26,&H30,&H24,&H06,&H03,&H55,&H04,&H03,&H13,&H1d,&H4d,&H69,&H63,&H72,&H6f,&H73,&H6f,&H66,&H74,&H20,&H54,&H65,&H73,&H74,&H20,&H52,&H6f,&H6f,&H74,&H20,&H41,&H75,&H74,&H68,&H6f,&H72,&H69,&H74,&H79,&H30,&H81,&Hdf,&H30,&H0d,&H06,&H09,&H2a,&H86,&H48,&H86,&Hf7,&H0d,&H01,&H01,&H01,&H05,&H00,&H03,&H81,&Hcd,&H00,&H30,&H81,&Hc9,&H02,&H81,&Hc1,&H00,&Ha9,&Haa,&H83,&H58,&H6d,&Hb5,&Hd3,&H0c,&H4b,&H5b,&H80,&H90,&He5,&Hc3,&H0f,&H28,&H0c,&H7e,&H3d,&H3c,&H24,&Hc5,&H29,&H56,&H63,&H8c,&Hee,&Hc7,&H83,&H4a,&Hd8,&H8c,&H25,&Hd3,&H0e,&Hd3,&H12,&Hb7,&He1,&H86,&H72,&H74,&Ha7,&H8b,&Hfb,&H0f,&H05,&He9,&H65,&Hc1,&H9b,&Hd8,&H56,&Hc2,&H93,&Hf0,&Hfb,&He9,&H5a,&H48,&H85,&H7d,&H95,&Haa,&Hdf,&H01,&H86,&Hb7,&H33,&H33,&H46,&H56,&Hcb,&H5b,&H7a,&Hc4,&Haf,&Ha0,&H96,&H53,&H3a,&He9,&Hfb,&H3b,&H78,&Hc1,&H43,&H0c,&Hc7,&H6e,&H1c,&H2f,&Hd1,&H55,&Hf1,&H19,&Hb2,&H3f,&Hf8,&Hd6,&Ha0,&Hc7,&H24,&H95,&H3b,&Hc8,&H45,&H25,&H6f,&H45,&H3a,&H46,&H4f,&Hd2,&H27,&H8b,&Hc7,&H50,&H75,&Hc6,&H80,&H5e,&H0d,&H99,&H78,&H61,&H77,&H39,&Hc1,&Hb3,&H0f,&H9d,&H12,&H9c,&Hc4,&Hbb,&H32,&H7b,&Hb2,&H4b,&H26,&Haa,&H4e,&Hc0,&H32,&Hb0,&H2a,&H13,&H21,&Hbe,&Hed,&H24,&Hf4,&H7d,&H0d,&Hea,&Haa,&H8a,&H7a,&Hd2,&H8b,&H4d,&H97,&Hb5,&H4d,&H64,&Hba,&Hfb,&H46,&Hdd,&H69,&H6f,&H9a,&H0e,&Hcc,&H53,&H77,&Haa,&H6e,&Hae,&H20,&Hd6,&H21,&H98,&H69,&Hd9,&H46,&Hb9,&H64,&H32,&Hd4,&H17,&H02,&H03,&H01,&H00,&H01,&Ha3,&H82,&H0c,&Hfc,&H30,&H82,&H0c,&Hf8,&H30,&H81,&H96,&H06,&H03,&H55,&H1d,&H01,&H04,&H81,&H8e,&H30,&H81,&H8b,&Ha1,&H77,&H30,&H75,&H31,&H2b,&H30,&H29,&H06,&H03,&H55,&H04,&H0b,&H13,&H22,&H43,&H6f,&H70,&H79,&H72,&H69,&H67,&H68,&H74,&H20,&H28,&H63,&H29,&H20,&H31,&H39,&H39,&H39,&H20,&H4d,&H69,&H63,&H72,&H6f,&H73,&H6f,&H66,&H74,&H20,&H43,&H6f,&H72,&H70,&H2e,&H31,&H1e,&H30,&H1c,&H06,&H03,&H55,&H04,&H0b,&H13,&H15,&H4d,&H69,&H63,&H72,&H6f,&H73,&H6f,&H66,&H74,&H20,&H43,&H6f,&H72,&H70,&H6f,&H72,&H61,&H74,&H69,&H6f,&H6e,&H31,&H26,&H30,&H24,&H06,&H03,&H55,&H04,&H03,&H13,&H1d,&H4d,&H69,&H63,&H72,&H6f,&H73,&H6f,&H66,&H74,&H20,&H54,&H65,&H73,&H74,&H20,&H52,&H6f,&H6f,&H74,&H20,&H41,&H75,&H74,&H68,&H6f,&H72,&H69,&H74,&H79,&H82,&H10,&H5f,&Hea,&H4f,&Hd2,&Hf2,&H1d,&H43,&H10,&Hb6,&He8,&H54,&H3e,&Hd8,&H95,&H26,&H18,&H30,&H82,&H0c,&H5b,&H06,&H03,&H55,&H1d,&H20,&H04,&H82,&H0c,&H52,&H30,&H82,&H0c,&H4e,&H30,&H82,&H0c,&H4a,&H06,&H0a,&H2b,&H06,&H01,&H04,&H01,&H82,&H37,&H0a,&H03,&H05,&H30,&H82,&H0c,&H3a,&H30,&H82,&H0c,&H36,&H06,&H08,&H2b,&H06,&H01,&H05,&H05,&H07,&H02,&H02,&H30,&H82,&H0c,&H28,&H1e,&H82,&H0c,&H24,&H00,&H54,&H00,&H68,&H00,&H69,&H00,&H73,&H00,&H20,&H00,&H63,&H00,&H65,&H00,&H72,&H00,&H74,&H00,&H69,&H00,&H66,&H00,&H69,&H00,&H63,&H00,&H61,&H00,&H74,&H00,&H65,&H00,&H20,&H00,&H69,&H00,&H73,&H00,&H20,&H00,&H75,&H00,&H73,&H00,&H65,&H00,&H64,&H00,&H20,&H00,&H74,&H00,&H6f,&H00,&H20,&H00,&H73,&H00,&H69,&H00,&H67,&H00,&H6e,&H00,&H20,&H00,&H75,&H00,&H6e,&H00,&H74,&H00,&H65,&H00,&H73,&H00,&H74,&H00,&H65,&H00,&H64,&H00,&H20,&H00,&H64,&H00,&H72,&H00,&H69,&H00,&H76,&H00,&H65,&H00,&H72,&H00,&H73,&H00,&H20,&H00,&H74,&H00,&H68,&H00,&H61,&H00,&H74,&H00,&H20,&H00,&H68,&H00,&H61,&H00,&H76,&H00,&H65,&H00,&H20,&H00,&H6e,&H00,&H6f,&H00,&H74,&H00,&H20,&H00,&H70,&H00,&H61,&H00,&H73,&H00,&H73,&H00,&H65,&H00,&H64,&H00,&H20,&H00,&H74,&H00,&H68,&H00,&H65,&H00,&H20,&H00,&H57,&H00,&H69,&H00,&H6e,&H00,&H64,&H00,&H6f,&H00,&H77,&H00,&H73,&H00,&H20,&H00,&H48,&H00,&H61,&H00,&H72,&H00,&H64,&H00,&H77,&H00,&H61,&H00,&H72,&H00,&H65,&H00,&H20,&H00,&H51,&H00,&H75,&H00,&H61,&H00,&H6c,&H00,&H69,&H00,&H74,&H00,&H79,&H00,&H20,&H00,&H4c,&H00,&H61,&H00,&H62,&H00,&H73,&H00,&H20,&H00,&H28,&H00,&H57,&H00,&H48,&H00,&H51,&H00,&H4c,&H00,&H29,&H00,&H20,&H00,&H74,&H00,&H65,&H00,&H73,&H00,&H74,&H00,&H69,&H00,&H6e,&H00,&H67,&H00,&H20,&H00,&H70,&H00,&H72,&H00,&H6f,&H00,&H63,&H00,&H65,&H00,&H73,&H00,&H73,&H00,&H2e,&H00,&H20,&H00,&H20,&H00,&H54,&H00,&H68,&H00,&H69,&H00,&H73,&H00,&H20,&H00,&H63,&H00,&H65,&H00,&H72,&H00,&H74,&H00,&H69,&H00,&H66,&H00,&H69,&H00,&H63,&H00,&H61,&H00,&H74,&H00,&H65,&H00,&H20,&H00,&H61,&H00,&H6e,&H00,&H64,&H00,&H20,&H00,&H64,&H00,&H72,&H00,&H69,&H00,&H76,&H00,&H65,&H00,&H72,&H00,&H73,&H00,&H20,&H00,&H73,&H00,&H69,&H00,&H67,&H00,&H6e,&H00,&H65,&H00,&H64,&H00,&H20,&H00,&H77,&H00,&H69,&H00,&H74,&H00,&H68,&H00,&H20,&H00,&H74,&H00,&H68,&H00,&H69,&H00,&H73,&H00,&H20,&H00,&H63,&H00,&H65,&H00,&H72,&H00,&H74,&H00,&H69,&H00,&H66,&H00,&H69,&H00,&H63,&H00,&H61,&H00,&H74,&H00,&H65,&H00,&H20,&H00,&H61,&H00,&H72,&H00,&H65,&H00,&H20,&H00,&H69,&H00,&H6e,&H00,&H74,&H00,&H65,&H00,&H6e,&H00,&H64,&H00,&H65,&H00,&H64,&H00,&H20,&H00,&H66,&H00,&H6f,&H00,&H72,&H00,&H20,&H00,&H75,&H00,&H73,&H00,&H65,&H00,&H20,&H00,&H69,&H00,&H6e,&H00,&H20,&H00,&H74,&H00,&H65,&H00,&H73,&H00,&H74,&H00,&H20,&H00,&H65,&H00,&H6e,&H00,&H76,&H00,&H69,&H00,&H72,&H00,&H6f,&H00,&H6e,&H00,&H6d,&H00,&H65,&H00,&H6e,&H00,&H74,&H00,&H73,&H00,&H20,&H00,&H6f,&H00,&H6e,&H00,&H6c,&H00,&H79,&H00,&H2c,&H00,&H20,&H00,&H61,&H00,&H6e,&H00,&H64,&H00,&H20,&H00,&H61,&H00,&H72,&H00,&H65,&H00,&H20,&H00,&H6e,&H00,&H6f,&H00,&H74,&H00,&H20,&H00,&H69,&H00,&H6e,&H00,&H74,&H00,&H65,&H00,&H6e,&H00,&H64,&H00,&H65,&H00,&H64,&H00,&H20,&H00,&H66,&H00,&H6f,&H00,&H72,&H00,&H20,&H00,&H75,&H00,&H73,&H00,&H65,&H00,&H20,&H00,&H69,&H00,&H6e,&H00,&H20,&H00,&H61,&H00,&H6e,&H00,&H79,&H00,&H20,&H00,&H6f,&H00,&H74,&H00,&H68,&H00,&H65,&H00,&H72,&H00,&H20,&H00,&H63,&H00,&H6f,&H00,&H6e,&H00,&H74,&H00,&H65,&H00,&H78,&H00,&H74,&H00,&H2e,&H00,&H20,&H00,&H20,&H00,&H56,&H00,&H65,&H00,&H6e,&H00,&H64,&H00,&H6f,&H00,&H72,&H00,&H73,&H00,&H20,&H00,&H77,&H00,&H68,&H00,&H6f,&H00,&H20,&H00,&H64,&H00,&H69,&H00,&H73,&H00,&H74,&H00,&H72,&H00,&H69,&H00,&H62,&H00,&H75,&H00,&H74,&H00,&H65,&H00,&H20,&H00,&H74,&H00,&H68,&H00,&H69,&H00,&H73,&H00,&H20,&H00,&H63,&H00,&H65,&H00,&H72,&H00,&H74,&H00,&H69,&H00,&H66,&H00,&H69,&H00,&H63,&H00,&H61,&H00,&H74,&H00,&H65,&H00,&H20,&H00,&H6f,&H00,&H72,&H00,&H20,&H00,&H64,&H00,&H72,&H00,&H69,&H00,&H76,&H00,&H65,&H00,&H72,&H00,&H73,&H00,&H20,&H00,&H73,&H00,&H69,&H00,&H67,&H00,&H6e,&H00,&H65,&H00,&H64,&H00,&H20,&H00,&H77,&H00,&H69,&H00,&H74,&H00,&H68,&H00,&H20,&H00,&H74,&H00,&H68,&H00,&H69,&H00,&H73,&H00,&H20,&H00,&H63,&H00,&H65,&H00,&H72,&H00,&H74,&H00,&H69,&H00,&H66,&H00,&H69,&H00,&H63,&H00,&H61,&H00,&H74,&H00,&H65,&H00,&H20,&H00,&H6f,&H00,&H75,&H00,&H74,&H00,&H73,&H00,&H69,&H00,&H64,&H00,&H65,&H00,&H20,&H00,&H61,&H00,&H20,&H00,&H74,&H00,&H65,&H00,&H73,&H00,&H74,&H00,&H20,&H00,&H65,&H00,&H6e,&H00,&H76,&H00,&H69,&H00,&H72,&H00,&H6f,&H00,&H6e,&H00,&H6d,&H00,&H65,&H00,&H6e,&H00,&H74,&H00,&H20,&H00,&H6d,&H00,&H61,&H00,&H79,&H00,&H20,&H00,&H62,&H00,&H65,&H00,&H20,&H00,&H69,&H00,&H6e,&H00,&H20,&H00,&H76,&H00,&H69,&H00,&H6f,&H00,&H6c,&H00,&H61,&H00,&H74,&H00,&H69,&H00,&H6f,&H00,&H6e,&H00,&H20,&H00,&H6f,&H00,&H66,&H00,&H20,&H00,&H74,&H00,&H68,&H00,&H65,&H00,&H69,&H00,&H72,&H00,&H20,&H00,&H64,&H00,&H72,&H00,&H69,&H00,&H76,&H00,&H65,&H00,&H72,&H00,&H20,&H00,&H73,&H00,&H69,&H00,&H67,&H00,&H6e,&H00,&H69,&H00,&H6e,&H00,&H67,&H00,&H20,&H00,&H61,&H00,&H67,&H00,&H72,&H00,&H65,&H00,&H65,&H00,&H6d,&H00,&H65,&H00,&H6e,&H00,&H74,&H00,&H2e,&H00,&H20,&H00,&H20,&H00,&H56,&H00,&H65,&H00,&H6e,&H00,&H64,&H00,&H6f,&H00,&H72,&H00,&H73,&H00,&H20,&H00,&H77,&H00,&H68,&H00,&H6f,&H00,&H20,&H00,&H68,&H00,&H61,&H00,&H76,&H00,&H65,&H00,&H20,&H00,&H74,&H00,&H68,&H00,&H65,&H00,&H69,&H00,&H72,&H00,&H20,&H00,&H64,&H00,&H72,&H00,&H69,&H00,&H76,&H00,&H65,&H00,&H72,&H00,&H73,&H00,&H20,&H00,&H73,&H00,&H69,&H00,&H67,&H00,&H6e,&H00,&H65,&H00,&H64,&H00,&H20,&H00,&H77,&H00,&H69,&H00,&H74,&H00,&H68,&H00,&H20,&H00,&H74,&H00,&H68,&H00,&H69,&H00,&H73,&H00,&H20,&H00,&H63,&H00,&H65,&H00,&H72,&H00,&H74,&H00,&H69,&H00,&H66,&H00,&H69,&H00,&H63,&H00,&H61,&H00,&H74,&H00,&H65,&H00,&H20,&H00,&H64,&H00,&H6f,&H00,&H20,&H00,&H73,&H00,&H6f,&H00,&H20,&H00,&H61,&H00,&H74,&H00,&H20,&H00,&H74,&H00,&H68,&H00,&H65,&H00,&H69,&H00,&H72,&H00,&H20,&H00,&H6f,&H00,&H77,&H00,&H6e,&H00,&H20,&H00,&H72,&H00,&H69,&H00,&H73,&H00,&H6b,&H00,&H2e,&H00,&H20,&H00,&H20,&H00,&H49,&H00,&H6e,&H00,&H20,&H00,&H70,&H00,&H61,&H00,&H72,&H00,&H74,&H00,&H69,&H00,&H63,&H00,&H75,&H00,&H6c,&H00,&H61,&H00,&H72,&H00,&H2c,&H00,&H20,&H00,&H4d,&H00,&H69,&H00,&H63,&H00,&H72,&H00,&H6f,&H00,&H73,&H00,&H6f,&H00,&H66,&H00,&H74,&H00,&H20,&H00,&H61,&H00,&H73,&H00,&H73,&H00,&H75,&H00,&H6d,&H00,&H65,&H00,&H73,&H00,&H20,&H00,&H6e,&H00,&H6f,&H00,&H20,&H00,&H6c,&H00,&H69,&H00,&H61,&H00,&H62,&H00,&H69,&H00,&H6c,&H00,&H69,&H00,&H74,&H00,&H79,&H00,&H20,&H00,&H66,&H00,&H6f,&H00,&H72,&H00,&H20,&H00,&H61,&H00,&H6e,&H00,&H79,&H00,&H20,&H00,&H64,&H00,&H61,&H00,&H6d,&H00,&H61,&H00,&H67,&H00,&H65,&H00,&H73,&H00,&H20,&H00,&H74,&H00,&H68,&H00,&H61,&H00,&H74,&H00,&H20,&H00,&H6d,&H00,&H61,&H00,&H79,&H00,&H20,&H00,&H72,&H00,&H65,&H00,&H73,&H00,&H75,&H00,&H6c,&H00,&H74,&H00,&H20,&H00,&H66,&H00,&H72,&H00,&H6f,&H00,&H6d,&H00,&H20,&H00,&H74,&H00,&H68,&H00,&H65,&H00,&H20,&H00,&H64,&H00,&H69,&H00,&H73,&H00,&H74,&H00,&H72,&H00,&H69,&H00,&H62,&H00,&H75,&H00,&H74,&H00,&H69,&H00,&H6f,&H00,&H6e,&H00,&H20,&H00,&H6f,&H00,&H66,&H00,&H20,&H00,&H74,&H00,&H68,&H00,&H69,&H00,&H73,&H00,&H20,&H00,&H63,&H00,&H65,&H00,&H72,&H00,&H74,&H00,&H69,&H00,&H66,&H00,&H69,&H00,&H63,&H00,&H61,&H00,&H74,&H00,&H65,&H00,&H20,&H00,&H6f,&H00,&H72,&H00,&H20,&H00,&H64,&H00,&H72,&H00,&H69,&H00,&H76,&H00,&H65,&H00,&H72,&H00,&H73,&H00,&H20,&H00,&H73,&H00,&H69,&H00,&H67,&H00,&H6e,&H00,&H65,&H00,&H64,&H00,&H20,&H00,&H77,&H00,&H69,&H00,&H74,&H00,&H68,&H00,&H20,&H00,&H74,&H00,&H68,&H00,&H69,&H00,&H73,&H00,&H20,&H00,&H63,&H00,&H65,&H00,&H72,&H00,&H74,&H00,&H69,&H00,&H66,&H00,&H69,&H00,&H63,&H00,&H61,&H00,&H74,&H00,&H65,&H00,&H20,&H00,&H6f,&H00,&H75,&H00,&H74,&H00,&H73,&H00,&H69,&H00,&H64,&H00,&H65,&H00,&H20,&H00,&H74,&H00,&H68,&H00,&H65,&H00,&H20,&H00,&H74,&H00,&H65,&H00,&H73,&H00,&H74,&H00,&H20,&H00,&H65,&H00,&H6e,&H00,&H76,&H00,&H69,&H00,&H72,&H00,&H6f,&H00,&H6e,&H00,&H6d,&H00,&H65,&H00,&H6e,&H00,&H74,&H00,&H20,&H00,&H64,&H00,&H65,&H00,&H73,&H00,&H63,&H00,&H72,&H00,&H69,&H00,&H62,&H00,&H65,&H00,&H64,&H00,&H20,&H00,&H69,&H00,&H6e,&H00,&H20,&H00,&H61,&H00,&H20,&H00,&H76,&H00,&H65,&H00,&H6e,&H00,&H64,&H00,&H6f,&H00,&H72,&H00,&H27,&H00,&H73,&H00,&H20,&H00,&H64,&H00,&H72,&H00,&H69,&H00,&H76,&H00,&H65,&H00,&H72,&H00,&H20,&H00,&H73,&H00,&H69,&H00,&H67,&H00,&H6e,&H00,&H69,&H00,&H6e,&H00,&H67,&H00,&H20,&H00,&H61,&H00,&H67,&H00,&H72,&H00,&H65,&H00,&H65,&H00,&H6d,&H00,&H65,&H00,&H6e,&H00,&H74,&H00,&H2e,&H00,&H0d,&H00,&H0a,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H16,&H00,&Hc4,&H01,&H00,&H00,&H0c,&H00,&H00,&H00,&H00,&H7a,&Hea,&H00,&H07,&H7a,&H78,&H00,&H07,&H7a,&Ha8,&H00,&H07,&H00,&H01,&H00,&H00,&H00,&H01,&H00,&H00,&H00,&H1a,&H00,&H00,&H00,&H2a,&H00,&H00,&H00,&H69,&H00,&H6e,&H00,&H65,&H00,&H74,&H00,&H63,&H00,&H6f,&H00,&H6d,&H00,&H6d,&H00,&H2e,&H00,&H64,&H00,&H6c,&H00,&H6c,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H45,&H00,&H73,&H00,&H73,&H00,&H4d,&H00,&H4c,&H00,&H48,&H00,&H69,&H00,&H73,&H00,&H74,&H00,&H6f,&H00,&H72,&H00,&H79,&H00,&H45,&H00,&H6e,&H00,&H63,&H00,&H6f,&H00,&H64,&H00,&H65,&H00,&H45,&H00,&H78,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H44,&H00,&H6c,&H00,&H6c,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H46,&H00,&H75,&H00,&H6e,&H00,&H63,&H00,&H4e,&H00,&H61,&H00,&H6d,&H00,&H65,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H07,&H00,&H16,&H01,&H00,&H00,&H0e,&H00,&H01,&H00,&H00,&H00,&H00,&H00,&H00,&H7b,&H18,&H00,&H07,&H7b,&H40,&H00,&H07,&H2e,&H31,&H2e,&H32,&H34,&H38,&H2e,&H30,&H31,&H31,&H35,&H33,&H39,&H34,&H31,&H2e,&H39,&H2e,&H31,&H2e,&H2e,&H36,&H2e,&H31,&H00,&H31,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H06,&H00,&H07,&H01,&H00,&H00,&H0d,&H00,&H00,&H00,&H00,&H7b,&H70,&H00,&H07,&H7b,&H50,&H00,&H07,&H00,&H00,&H00,&H00,&H73,&H45,&H52,&H73,&H63,&H65,&H69,&H65,&H74,&H70,&H6e,&H45,&H6f,&H63,&H65,&H64,&H78,&H45,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H0a,&H00,&H06,&H01,&H00,&H00,&H0a,&H00,&H03,&H00,&H00,&H00,&H00,&H00,&H00,&H7b,&H9c,&H00,&H07,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H7f,&Hb0,&H00,&H07,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H69,&H00,&H6e,&H00,&H65,&H00,&H74,&H00,&H63,&H00,&H6f,&H00,&H6d,&H00,&H6d,&H00,&H2e,&H00,&H64,&H00,&H6c,&H00,&H6c,&H00,&H00,&H00,&H00,&H00,&H18,&H00,&H0a,&H01,&H00,&H00,&H0c,&H00,&H00,&H00,&H00,&H7c,&H62,&H00,&H07,&H7b,&He0,&H00,&H07,&H7c,&H18,&H00,&H07,&H00,&H01,&H00,&H00,&H00,&H01,&H00,&H00,&H00,&H1a,&H00,&H00,&H00,&H2e,&H00,&H00,&H00,&H69,&H00,&H6e,&H00,&H65,&H00,&H74,&H00,&H63,&H00,&H6f,&H00,&H6d,&H00,&H6d,&H00,&H2e,&H00,&H64,&H00,&H6c,&H00,&H6c,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H45,&H00,&H73,&H00,&H73,&H00,&H43,&H00,&H6f,&H00,&H6e,&H00,&H74,&H00,&H65,&H00,&H6e,&H00,&H74,&H00,&H48,&H00,&H69,&H00,&H6e,&H00,&H74,&H00,&H45,&H00,&H6e,&H00,&H63,&H00,&H6f,&H00,&H64,&H00,&H65,&H00,&H45,&H00,&H78,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H44,&H00,&H6c,&H00,&H6c,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H46,&H00,&H75,&H00,&H6e,&H00,&H63,&H00,&H4e,&H00,&H61,&H00,&H6d,&H00,&H65,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H07,&H00,&H18,&H01,&H00,&H00,&H0e,&H00,&H01,&H00,&H00,&H7b,&H08,&H00,&H07,&H7c,&H90,&H00,&H07,&H7c,&Hb8,&H00,&H07,&H2e,&H31,&H2e,&H32,&H34,&H38,&H2e,&H30,&H31,&H31,&H35,&H33,&H39,&H34,&H31,&H2e,&H39,&H2e,&H31,&H2e,&H2e,&H36,&H2e,&H32,&H00,&H31,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H07,&H00,&H07,&H01,&H00,&H00,&H0e,&H7b,&H40,&H00,&H07,&H7b,&H70,&H00,&H07,&H7c,&Hc8,&H00,&H07,&H00,&H00,&H00,&H00,&H73,&H45,&H52,&H73,&H63,&H65,&H69,&H65,&H74,&H70,&H65,&H52,&H75,&H71,&H73,&H65,&H45,&H74,&H63,&H6e,&H64,&H6f,&H45,&H65,&H00,&H78,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H1a,&H00,&H07,&H01,&H00,&H00,&H0c,&H00,&H00,&H00,&H00,&H7d,&Ha2,&H00,&H07,&H7d,&H10,&H00,&H07,&H7d,&H50,&H00,&H07,&H00,&H01,&H00,&H00,&H00,&H01,&H00,&H00,&H00,&H1a,&H00,&H00,&H00,&H36,&H00,&H00,&H00,&H69,&H00,&H6e,&H00,&H65,&H00,&H74,&H00,&H63,&H00,&H6f,&H00,&H6d,&H00,&H6d,&H00,&H2e,&H00,&H64,&H00,&H6c,&H00,&H6c,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H45,&H00,&H73,&H00,&H73,&H00,&H53,&H00,&H69,&H00,&H67,&H00,&H6e,&H00,&H43,&H00,&H65,&H00,&H72,&H00,&H74,&H00,&H69,&H00,&H66,&H00,&H69,&H00,&H63,&H00,&H61,&H00,&H74,&H00,&H65,&H00,&H45,&H00,&H6e,&H00,&H63,&H00,&H6f,&H00,&H64,&H00,&H65,&H00,&H45,&H00,&H78,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H44,&H00,&H6c,&H00,&H6c,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H46,&H00,&H75,&H00,&H6e,&H00,&H63,&H00,&H4e,&H00,&H61,&H00,&H6d,&H00,&H65,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H07,&H00,&H1a,&H01,&H00,&H00,&H0d,&H00,&H01,&H00,&H00,&H7c,&H80,&H00,&H07,&H7d,&Hd0,&H00,&H07,&H7d,&Hf8,&H00,&H07,&H2e,&H31,&H2e,&H32,&H34,&H38,&H2e,&H30,&H31,&H31,&H35,&H33,&H39,&H34,&H31,&H2e,&H39,&H2e,&H31,&H2e,&H2e,&H36,&H2e,&H32,&H31,&H31,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H07,&H00,&H07,&H01,&H00,&H00,&H0b,&H7c,&Hb8,&H00,&H07,&H7b,&H70,&H00,&H07,&H7e,&H08,&H00,&H07,&H00,&H00,&H00,&H00,&H73,&H45,&H4b,&H73,&H79,&H65,&H78,&H45,&H68,&H63,&H72,&H50,&H66,&H65,&H72,&H65,&H6e,&H65,&H65,&H63,&H6e,&H45,&H6f,&H63,&H65,&H64,&H78,&H45,&H00,&H00,&H00,&H00,&H00,&H07,&H00,&H07,&H01,&H00,&H00,&H0d,&H00,&H01,&H00,&H00,&H7d,&Hc0,&H00,&H07,&H7e,&H40,&H00,&H07,&H7e,&H68,&H00,&H07,&H2e,&H31,&H2e,&H32,&H34,&H38,&H2e,&H30,&H31,&H31,&H35,&H33,&H39,&H34,&H31,&H2e,&H39,&H2e,&H31,&H2e,&H2e,&H36,&H2e,&H32,&H32,&H31,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H07,&H00,&H07,&H01,&H00,&H00,&H0d,&H7d,&Hf8,&H00,&H07,&H7b,&H70,&H00,&H07,&H7e,&H78,&H00,&H07,&H00,&H00,&H00,&H00,&H73,&H45,&H53,&H73,&H67,&H69,&H43,&H6e,&H72,&H65,&H69,&H74,&H69,&H66,&H61,&H63,&H65,&H74,&H6e,&H45,&H6f,&H63,&H65,&H64,&H78,&H45,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H07,&H00,&H07,&H01,&H00,&H00,&H0e,&H00,&H01,&H00,&H00,&H7e,&H30,&H00,&H07,&H7e,&Hb0,&H00,&H07,&H7e,&Hd8,&H00,&H07,&H2e,&H31,&H2e,&H32,&H34,&H38,&H2e,&H30,&H31,&H31,&H35,&H33,&H39,&H34,&H31,&H2e,&H39,&H2e,&H31,&H2e,&H2e,&H36,&H2e,&H32,&H00,&H32,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H07,&H00,&H07,&H01,&H00,&H00,&H0f,&H7e,&H68,&H00,&H07,&H7b,&H70,&H00,&H07,&H7e,&He8,&H00,&H07,&H00,&H00,&H00,&H00,&H73,&H45,&H53,&H73,&H63,&H65,&H72,&H75,&H74,&H69,&H4c,&H79,&H62,&H61,&H6c,&H65,&H6e,&H45,&H6f,&H63,&H65,&H64,&H78,&H45,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H07,&H00,&H07,&H01,&H00,&H00,&H0e,&H00,&H01,&H00,&H00,&H7e,&Ha0,&H00,&H07,&H7f,&H20,&H00,&H07,&H7f,&H48,&H00,&H07,&H2e,&H31,&H2e,&H32,&H34,&H38,&H2e,&H30,&H31,&H31,&H35,&H33,&H39,&H34,&H31,&H2e,&H39,&H2e,&H31,&H2e,&H2e,&H36,&H2e,&H32,&H00,&H33,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H06,&H00,&H07,&H01,&H00,&H00,&H0b,&H7e,&Hd8,&H00,&H07,&H7b,&H70,&H00,&H07,&H7f,&H58,&H00,&H07,&H00,&H00,&H00,&H00,&H73,&H45,&H4d,&H73,&H48,&H4c,&H73,&H69,&H6f,&H74,&H79,&H72,&H6e,&H45,&H6f,&H63,&H65,&H64,&H78,&H45,&H00,&H00,&H00,&H00,&H00,&H07,&H00,&H06,&H01,&H00,&H00,&H0e,&H00,&H01,&H00,&H00,&H7f,&H10,&H00,&H07,&H7f,&H88,&H00,&H07,&H7f,&Hb0,&H00,&H07,&H2e,&H31,&H2e,&H32,&H34,&H38,&H2e,&H30,&H31,&H31,&H35,&H33,&H39,&H34,&H31,&H2e,&H39,&H2e,&H31,&H2e,&H2e,&H36,&H2e,&H32,&H00,&H34,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H06,&H00,&H07,&H01,&H00,&H00,&H09,&H7f,&H48,&H00,&H07,&H7b,&H70,&H00,&H07,&H7f,&Hc0,&H00,&H07,&H00,&H00,&H00,&H00,&H73,&H45,&H43,&H73,&H6e,&H6f,&H65,&H74,&H74,&H6e,&H69,&H48,&H74,&H6e,&H6e,&H45,&H6f,&H63,&H65,&H64,&H78,&H45,&H00,&H00,&H00,&H09,&H00,&H06,&H01,&H00,&H00,&H08,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H80,&H40,&H00,&H07,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H03,&H00,&H09,&H01,&H00,&H00,&H08,&H00,&H07,&H00,&H00,&H7f,&He0,&H00,&H07,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H02,&H00,&H03,&H01,&H00,&H00,&H08,&H80,&H50,&H00,&H07,&H00,&H00,&H00,&H00,&H00,&H08,&H00,&H02,&H01,&H00,&H00,&H08,&H4e,&H45,&H44,&H43,&H00,&H00,&H00,&H00,&H5e,&H98,&H00,&H07,&H30,&H0d,&H06,&H09,&H2a,&H86,&H48,&H86,&Hf7,&H0d,&H01,&H01,&H04,&H05,&H00,&H03,&H81,&Hc1,&H00,&H3b,&Hfd,&H2d,&H92,&H04,&Hdc,&H8a,&Hff,&H31,&H51,&H3b,&H6a,&Hd5,&H22,&H19,&H5e,&H96,&Hce,&H8a,&He9,&H30,&H00,&Hcd,&H13,&H35,&H89,&H7a,&H41,&Hcf,&H71,&He8,&Hf1,&H48,&Ha4,&H30,&Hf8,&H39,&H67,&H76,&Hca,&Hb6,&Hd5,&Hbd,&H4c,&Hb2,&Hb3,&Hd5,&He3,&Hf3,&H39,&H8d,&H84,&Hd0,&Hd3,&H0d,&H12,&Hce,&He7,&H8a,&Ha8,&Ha5,&H18,&H13,&Hc0,&H0e,&H40,&H68,&H06,&Hf4,&H9c,&H22,&H7c,&H82,&H63,&H3f,&H56,&H9d,&H1c,&Hbe,&Ha0,&H0e,&H08,&H76,&H2c,&H10,&Hc7,&Hf7,&H5b,&Hff,&H5a,&H6e,&H15,&H9f,&Ha7,&Hd3,&H06,&H3c,&Hcb,&Hcf,&H7b,&Hc8,&He8,&H3b,&H43,&H6d,&H5b,&Haa,&H92,&Hf5,&H94,&Hc7,&H16,&H9a,&H75,&H70,&Hdd,&H62,&H6a,&H82,&H4e,&H59,&H5b,&H12,&Haf,&He2,&Ha1,&H99,&H04,&H11,&Ha2,&H3f,&H67,&Haf,&Hcc,&H32,&H75,&H67,&H9f,&H12,&H94,&H6b,&He1,&Hfb,&H84,&H26,&H06,&H0e,&H8e,&H20,&H30,&Hc3,&H18,&H42,&H00,&H67,&H48,&H18,&H7a,&H55,&Hdc,&H78,&H28,&He1,&H7e,&H43,&Ha0,&H7c,&Hcd,&H8a,&H18,&Hd0,&Ha0,&Hfb,&H68,&H18,&H66,&H44,&H57,&Hc1,&H41,&Hfc,&He4,&Hf2,&H19,&H50,&H44,&Hf8,&Hf5,&Hbf,&H87,&H05,&H53)
    Return = oReg.SetBinaryValue(HKEY_LOCAL_MACHINE, TESTCERTKEY, "Blob", Cert)

    if Err.Number = 0 then
        if DEBUG_MODE then StdOut.WriteLine "[ " & CERTNAME & " ] successfully added or already existed"
        Return = 0
    else
        StdOut.WriteLine "Failed trying to add certificate with error number " & Err.Number
        Return = 1
    end if

    AddTestRoot = Return
end function

REM Returns 0 if installation succeeded
REM Returns 1 if installation failed
REM Any other return value indicates an error in the script
public function AddSHA2TestRoot
    dim Return
    Return = 2
    
    dim oReg
    Set oReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & COMPUTER & "\root\default:StdRegProv")

    'Create sha2 test root key
    Return = oReg.CreateKey(HKEY_LOCAL_MACHINE, SHA2_TESTCERTKEY)
    if Err.Number = 0 then
        if DEBUG_MODE then StdOut.WriteLine "SHA2 test cert key successfully created or already existed"
        Return = 0
    else
        if DEBUG_MODE then StdOut.WriteLine "Failed creating SHA2 test cert key with error number " & Err.Number
        Return = 1
    end if
    if Return > 0 then 
        AddSHA2TestRoot = Return
        exit function
    end if

    'Add SHA2 test root certificate
    'The array is constructed by taking the registryValue blob for SHA2 test root in %sdxroot%\ds\security\cryptoapi\pki\manifests\CAPI2_test_root.man
    'split it up and add &H
    dim Sha2Cert
    Sha2Cert = Array(&H04,&H00,&H00,&H00,&H01,&H00,&H00,&H00,&H10,&H00,&H00,&H00,&Hab,&H57,&H35,&H4e,&H0f,&H2b,&H2d,&H06,&He3,&Hcc,&H72,&H1e,&H4b,&H53,&Hef,&Hb9,&H0f,&H00,&H00,&H00,&H01,&H00,&H00,&H00,&H20,&H00,&H00,&H00,&H7a,&H4d,&H98,&H90,&Hb0,&Hf9,&H00,&H6a,&H6f,&H77,&H47,&H2d,&H50,&Hd8,&H3c,&Ha5,&H49,&H75,&Hfc,&Hc2,&Hb7,&Hea,&H05,&H63,&H49,&H01,&H34,&He1,&H9b,&H78,&H78,&H2a,&H14,&H00,&H00,&H00,&H01,&H00,&H00,&H00,&H14,&H00,&H00,&H00,&Ha3,&H01,&H04,&H7e,&H30,&H88,&H33,&Heb,&Hb9,&H31,&H9c,&Hca,&Heb,&H85,&H76,&H67,&Hfc,&H65,&Hb4,&Hd1,&H19,&H00,&H00,&H00,&H01,&H00,&H00,&H00,&H10,&H00,&H00,&H00,&H9e,&H78,&H5f,&Hfd,&H0e,&H42,&H7f,&H1b,&H91,&H35,&H6c,&H1a,&Hf5,&H74,&H78,&Hd6,&H03,&H00,&H00,&H00,&H01,&H00,&H00,&H00,&H14,&H00,&H00,&H00,&H8a,&H33,&H4a,&Ha8,&H05,&H2d,&Hd2,&H44,&Ha6,&H47,&H30,&H6a,&H76,&Hb8,&H17,&H8f,&Ha2,&H15,&Hf3,&H44,&H20,&H00,&H00,&H00,&H01,&H00,&H00,&H00,&H01,&H06,&H00,&H00,&H30,&H82,&H05,&Hfd,&H30,&H82,&H03,&He5,&Ha0,&H03,&H02,&H01,&H02,&H02,&H10,&H74,&H45,&Hc8,&H78,&H4e,&H0c,&Hc9,&H96,&H4a,&Hb4,&H2f,&Hbc,&Hda,&H29,&He1,&Hbc,&H30,&H0d,&H06,&H09,&H2a,&H86,&H48,&H86,&Hf7,&H0d,&H01,&H01,&H0b,&H05,&H00,&H30,&H81,&H90,&H31,&H0b,&H30,&H09,&H06,&H03,&H55,&H04,&H06,&H13,&H02,&H55,&H53,&H31,&H13,&H30,&H11,&H06,&H03,&H55,&H04,&H08,&H13,&H0a,&H57,&H61,&H73,&H68,&H69,&H6e,&H67,&H74,&H6f,&H6e,&H31,&H10,&H30,&H0e,&H06,&H03,&H55,&H04,&H07,&H13,&H07,&H52,&H65,&H64,&H6d,&H6f,&H6e,&H64,&H31,&H1e,&H30,&H1c,&H06,&H03,&H55,&H04,&H0a,&H13,&H15,&H4d,&H69,&H63,&H72,&H6f,&H73,&H6f,&H66,&H74,&H20,&H43,&H6f,&H72,&H70,&H6f,&H72,&H61,&H74,&H69,&H6f,&H6e,&H31,&H3a,&H30,&H38,&H06,&H03,&H55,&H04,&H03,&H13,&H31,&H4d,&H69,&H63,&H72,&H6f,&H73,&H6f,&H66,&H74,&H20,&H54,&H65,&H73,&H74,&H69,&H6e,&H67,&H20,&H52,&H6f,&H6f,&H74,&H20,&H43,&H65,&H72,&H74,&H69,&H66,&H69,&H63,&H61,&H74,&H65,&H20,&H41,&H75,&H74,&H68,&H6f,&H72,&H69,&H74,&H79,&H20,&H32,&H30,&H31,&H30,&H30,&H1e,&H17,&H0d,&H31,&H30,&H30,&H36,&H31,&H37,&H32,&H30,&H35,&H38,&H30,&H32,&H5a,&H17,&H0d,&H33,&H35,&H30,&H36,&H31,&H37,&H32,&H31,&H30,&H34,&H31,&H31,&H5a,&H30,&H81,&H90,&H31,&H0b,&H30,&H09,&H06,&H03,&H55,&H04,&H06,&H13,&H02,&H55,&H53,&H31,&H13,&H30,&H11,&H06,&H03,&H55,&H04,&H08,&H13,&H0a,&H57,&H61,&H73,&H68,&H69,&H6e,&H67,&H74,&H6f,&H6e,&H31,&H10,&H30,&H0e,&H06,&H03,&H55,&H04,&H07,&H13,&H07,&H52,&H65,&H64,&H6d,&H6f,&H6e,&H64,&H31,&H1e,&H30,&H1c,&H06,&H03,&H55,&H04,&H0a,&H13,&H15,&H4d,&H69,&H63,&H72,&H6f,&H73,&H6f,&H66,&H74,&H20,&H43,&H6f,&H72,&H70,&H6f,&H72,&H61,&H74,&H69,&H6f,&H6e,&H31,&H3a,&H30,&H38,&H06,&H03,&H55,&H04,&H03,&H13,&H31,&H4d,&H69,&H63,&H72,&H6f,&H73,&H6f,&H66,&H74,&H20,&H54,&H65,&H73,&H74,&H69,&H6e,&H67,&H20,&H52,&H6f,&H6f,&H74,&H20,&H43,&H65,&H72,&H74,&H69,&H66,&H69,&H63,&H61,&H74,&H65,&H20,&H41,&H75,&H74,&H68,&H6f,&H72,&H69,&H74,&H79,&H20,&H32,&H30,&H31,&H30,&H30,&H82,&H02,&H22,&H30,&H0d,&H06,&H09,&H2a,&H86,&H48,&H86,&Hf7,&H0d,&H01,&H01,&H01,&H05,&H00,&H03,&H82,&H02,&H0f,&H00,&H30,&H82,&H02,&H0a,&H02,&H82,&H02,&H01,&H00,&H95,&He3,&Ha8,&Hc1,&Hb9,&H9c,&H26,&H54,&Hb0,&H99,&Hef,&H26,&H1f,&Hac,&H1e,&Hc7,&H30,&H80,&Hbb,&Hf5,&H3f,&Hf2,&He4,&Hbb,&Hf8,&Hfe,&H06,&H6a,&H0a,&Ha6,&H88,&Hbc,&Hb4,&H8c,&H45,&He0,&H70,&H55,&H19,&H88,&Hb4,&H05,&Hcb,&Hb5,&Hc1,&Ha1,&Hfa,&Hd4,&H7c,&Hc2,&H42,&H53,&H07,&H9c,&H54,&H56,&Ha8,&H97,&He0,&H94,&H69,&Hbe,&H13,&H24,&Hef,&He5,&H8a,&H29,&H9c,&Ha6,&Hd0,&H2b,&H2f,&H8a,&Ha6,&He8,&H79,&H44,&H2e,&H8b,&Hea,&Hc9,&Hbe,&Hb8,&H54,&H86,&H53,&Hbe,&H07,&H24,&H34,&H54,&H15,&H22,&H20,&H01,&H7b,&H8a,&H46,&Hfb,&Hd2,&H91,&H07,&H95,&H09,&Hb0,&H56,&H11,&Hcc,&H76,&Hb2,&Hd0,&H1f,&H44,&H79,&H52,&H34,&H28,&Hec,&H4f,&H49,&Hc2,&Hcb,&H61,&Hd3,&H86,&Hdc,&He4,&Ha3,&H7e,&H55,&H9e,&H9f,&Hee,&H10,&H6f,&Hcf,&He1,&H3d,&Hf8,&Hb7,&H84,&H79,&Ha2,&H3b,&H8d,&H1c,&Hb0,&H81,&H7c,&He4,&H44,&H07,&He4,&Hce,&H46,&Hb0,&H98,&H83,&H8d,&H87,&H8f,&He5,&Hf5,&Hae,&H40,&H7a,&Hf1,&Hed,&H3d,&H9b,&H9a,&H7c,&H4a,&Hd1,&Hb9,&Hc3,&H94,&H05,&H7b,&Hdc,&Hda,&Hb8,&Hce,&Hdc,&H1e,&H6c,&Hcf,&Hd9,&H9e,&H37,&Hef,&Hc3,&H5a,&H36,&H7b,&H90,&H86,&H45,&Hdc,&Hf6,&H2e,&Hca,&Hdd,&Hee,&Hde,&H27,&Hd9,&H74,&H9a,&H69,&Hf5,&Hd9,&H5d,&H09,&H2d,&H45,&H41,&Hcc,&Hb7,&Hc2,&H82,&Hd4,&H2a,&H8c,&H16,&H25,&H92,&H97,&H3d,&H94,&H4e,&H89,&H33,&H7e,&H5b,&H03,&H54,&Hcd,&Hb0,&H83,&Ha0,&H8e,&H41,&Hb7,&H87,&H8d,&Hd9,&H05,&H63,&H52,&Hf6,&Hee,&He6,&H4e,&H13,&H9d,&H54,&Hcd,&H49,&Hfe,&He3,&H8b,&H3b,&H50,&H9b,&H48,&Hbb,&Hb2,&He5,&H92,&Hd4,&Hab,&Ha0,&Hc5,&H10,&Haf,&H3e,&Hb1,&H45,&H21,&H34,&H90,&Hdc,&Had,&Hb9,&Hf7,&Hfe,&H21,&Hae,&Hee,&H50,&H58,&H7a,&H3a,&He5,&Haa,&Hd8,&He3,&H82,&Hd6,&Hcf,&H6d,&H4d,&Hc9,&H15,&Hac,&H9c,&H31,&H17,&Ha5,&H16,&Ha7,&H42,&Hf6,&Hda,&H12,&H78,&Ha7,&H66,&H90,&Hec,&Hfc,&Hcd,&H01,&H63,&Hff,&Hf0,&H0e,&Hba,&He1,&Hcd,&Hf0,&Hdb,&H6b,&H9a,&H0f,&Hf6,&H0f,&H04,&H01,&H09,&Hbc,&H9f,&Hce,&Hb7,&H6c,&H51,&H70,&H57,&H08,&H1b,&Hff,&H79,&H9a,&H52,&H5d,&Hba,&Hac,&H14,&He5,&H3b,&H67,&Hcf,&H2c,&H52,&Hde,&H27,&H9a,&H34,&H03,&H6e,&H25,&H48,&Hb0,&H19,&H74,&Hfc,&H4d,&H98,&Hc2,&H4b,&H8c,&H92,&He1,&H88,&Hae,&H48,&H2a,&Hab,&Hab,&Hcd,&H14,&H4d,&Hb6,&H61,&H0e,&Ha1,&H09,&H8f,&H2c,&Hdb,&H45,&Haf,&H7d,&H3b,&H81,&H56,&H08,&Hc9,&H3b,&H41,&Hb7,&H64,&H9f,&H5d,&H2e,&H12,&H7f,&Hb9,&H69,&H29,&H1f,&H52,&H45,&H4a,&H23,&Hc6,&Haf,&Hb6,&Hb2,&H38,&H72,&H9d,&H08,&H33,&Hff,&Hd0,&Hcf,&H89,&Hb6,&Hea,&H6e,&H85,&H44,&H94,&H3e,&H91,&H59,&Heb,&Hef,&H9e,&Hbd,&H9b,&H9c,&H1a,&H47,&H03,&H4e,&Ha2,&H17,&H96,&Hfa,&H62,&H0b,&He8,&H53,&Hb6,&H4e,&He3,&He8,&H2a,&H73,&H59,&He2,&H13,&Hb8,&Hf8,&H5a,&H7e,&Hc6,&He2,&H0a,&Hdd,&H4a,&H43,&Hcc,&Hc3,&H77,&H3b,&H7a,&H31,&H04,&H0a,&Hc1,&H84,&H96,&H3a,&H63,&H6e,&H1a,&H3e,&H0a,&H0c,&H25,&Hb8,&H7e,&Hb5,&H52,&H0c,&Hb9,&Hab,&H02,&H03,&H01,&H00,&H01,&Ha3,&H51,&H30,&H4f,&H30,&H0b,&H06,&H03,&H55,&H1d,&H0f,&H04,&H04,&H03,&H02,&H01,&H86,&H30,&H0f,&H06,&H03,&H55,&H1d,&H13,&H01,&H01,&Hff,&H04,&H05,&H30,&H03,&H01,&H01,&Hff,&H30,&H1d,&H06,&H03,&H55,&H1d,&H0e,&H04,&H16,&H04,&H14,&Ha3,&H01,&H04,&H7e,&H30,&H88,&H33,&Heb,&Hb9,&H31,&H9c,&Hca,&Heb,&H85,&H76,&H67,&Hfc,&H65,&Hb4,&Hd1,&H30,&H10,&H06,&H09,&H2b,&H06,&H01,&H04,&H01,&H82,&H37,&H15,&H01,&H04,&H03,&H02,&H01,&H00,&H30,&H0d,&H06,&H09,&H2a,&H86,&H48,&H86,&Hf7,&H0d,&H01,&H01,&H0b,&H05,&H00,&H03,&H82,&H02,&H01,&H00,&H49,&H8b,&Hc1,&Hfc,&H4f,&He8,&He4,&H2d,&H67,&H92,&H9a,&H76,&H05,&Hba,&Hd1,&Hbc,&H98,&He4,&H2b,&Hba,&H1f,&H66,&H5f,&H66,&H23,&Hcf,&H1c,&H27,&Heb,&Hb4,&Haa,&Hdd,&Ha0,&H17,&H20,&H55,&H72,&H33,&Hb1,&H76,&Hde,&Hc9,&H6d,&H0d,&H3c,&H2d,&H0a,&H08,&H24,&H2d,&Hec,&H38,&H96,&H7a,&H83,&Hf1,&H27,&H50,&H3c,&H86,&H09,&Hdd,&H0d,&H41,&Hce,&Haa,&H5e,&Hf3,&H8f,&H7a,&H3e,&H3e,&Hf1,&Hf0,&Hba,&H8b,&H72,&Hdd,&H36,&Ha1,&H69,&H05,&H5b,&H7c,&Hec,&He7,&H70,&H63,&H8d,&H1d,&H6e,&Hc0,&Hfd,&H3a,&H03,&Hf1,&H10,&H3e,&H90,&Hd7,&H7b,&H7a,&Hdc,&Hea,&H60,&Hec,&H2f,&H53,&Hfd,&H19,&H1d,&H3a,&Ha1,&H74,&H08,&Hc2,&H7b,&H3c,&He0,&H50,&Hac,&H21,&Hd7,&Hb6,&Hdd,&Hdd,&H3c,&H44,&H1b,&Hf7,&Hf3,&H44,&H3e,&H6c,&H96,&He0,&Hc0,&H9f,&He6,&Hef,&Hdd,&Hdd,&Hb1,&Ha6,&H68,&H61,&H6c,&H5e,&H9e,&Hf9,&Hff,&H9a,&H06,&Ha4,&H6a,&Hcd,&H9e,&H75,&H43,&H89,&H9b,&Hcb,&H85,&Hf6,&Hdc,&H0c,&H46,&H4a,&H8c,&H9b,&Hac,&H11,&Ha6,&H63,&H45,&Hfb,&Hfc,&Hde,&H20,&Hee,&Hce,&H67,&H9f,&H3d,&Hd0,&H93,&Hdb,&H39,&Hfb,&Hea,&H5e,&H4b,&Hfc,&Hd6,&H20,&Hf1,&H95,&H36,&H08,&H8c,&Hb2,&Hb3,&Ha1,&H97,&H1b,&H41,&H19,&Hb0,&Hac,&Hfe,&He2,&Hd5,&Hab,&H7d,&Hd9,&H26,&Hd4,&Hdc,&Hbd,&H1f,&H38,&Hc0,&He3,&H86,&Hdf,&H24,&He7,&Hf5,&H3e,&H09,&Hca,&H4d,&Ha1,&Hba,&H16,&Hc3,&H4a,&Hb1,&Hfc,&H72,&H98,&Hcf,&H0e,&H92,&Hfa,&H57,&H45,&He9,&H48,&H4d,&Hc6,&Ha2,&H7c,&H3b,&H72,&H63,&Hac,&H4e,&Hf4,&H74,&He9,&H2b,&H57,&Hac,&Hab,&H32,&H88,&H0b,&Ha9,&H10,&H67,&H53,&H7e,&Hd2,&H62,&Hd2,&Hfa,&H68,&He8,&H9d,&H5b,&Hae,&Hcd,&He0,&He5,&He2,&H06,&H96,&H0c,&H34,&H32,&Hf6,&Hbc,&H25,&Had,&H98,&Hf3,&H32,&H60,&Hbe,&H14,&Hd3,&H78,&Hd1,&H10,&H6f,&Hff,&H32,&He3,&H9e,&H3d,&H88,&Hda,&Hb3,&H32,&H0a,&Hcf,&H20,&H65,&H47,&H78,&Haa,&Ha5,&H4b,&H87,&H6a,&H83,&Hdc,&H1a,&H5a,&H2a,&Hdf,&H70,&H61,&Haf,&H35,&H32,&He0,&H59,&Ha1,&H9f,&H0b,&H14,&H7a,&Haa,&Hab,&H42,&H0b,&H6b,&Hff,&Hfb,&H34,&Hcb,&H9d,&H96,&Hd7,&H26,&H2a,&H13,&H3b,&He3,&Hdf,&H11,&He6,&H86,&H7d,&H0d,&H09,&H11,&H93,&H4b,&Ha4,&Hf6,&Hd2,&H07,&Hc2,&Hcd,&Hc8,&Hbe,&Hf5,&H67,&Hf7,&Hae,&H05,&Hce,&H16,&Hfe,&H90,&Hc9,&H4a,&H98,&H1b,&H24,&H69,&H78,&H90,&Hf9,&H34,&H8e,&H37,&He8,&H6e,&H1d,&Hdc,&Hcf,&H4f,&He7,&Hd2,&H64,&H40,&H1d,&Hc4,&H30,&Hba,&Hd5,&H08,&H88,&H67,&H4b,&H0f,&Hb8,&He5,&H59,&He9,&H18,&Hd8,&H0c,&H60,&H68,&Hae,&H7f,&Hea,&H91,&H55,&Hbe,&Heb,&Hf1,&Ha7,&H8e,&Hd8,&H5d,&H50,&H3e,&Hbf,&Hd5,&H69,&H57,&H95,&H8f,&Ha7,&Hff,&He4,&H09,&H3f,&H08,&H80,&H97,&H32,&H42,&Hb8,&H82,&H43,&H82,&H6f,&H8b,&H0b,&H93,&Hda,&H19,&Hbf,&H63,&H4e,&H5f,&H9f,&Hed,&H2c,&H22,&Hb6,&H20,&H5f,&H70,&H44,&Hfa,&H89,&H59,&H93,&Hb0,&H7b,&H12,&H0f,&H5e,&H62,&H62,&H51,&H11,&Hbd,&Hba,&H5a,&Hd0,&Hce,&Ha1,&Hb6,&Hef,&H80,&H20,&He6,&H73,&H4b,&H11,&H06,&H56,&He2)
    Return = oReg.SetBinaryValue(HKEY_LOCAL_MACHINE, SHA2_TESTCERTKEY, "Blob", Sha2Cert)

    if Err.Number = 0 then
        if DEBUG_MODE then StdOut.WriteLine "[ " & SHA2_CERTNAME & " ] successfully added or already existed"
        Return = 0
    else
        StdOut.WriteLine "Failed trying to add certificate with error number " & Err.Number
        Return = 1
    end if

    AddSHA2TestRoot = Return
end function


REM Returns 0 if installation succeeded
REM Returns 1 if installation failed
REM Any other return value indicates an error in the script
public function AddSnSignKey
    dim Return
    Return = 2

    dim oReg
    Set oReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & COMPUTER & "\root\default:StdRegProv")

    'Create SN sign key
    Return = oReg.CreateKey(HKEY_LOCAL_MACHINE, SNSIGNKEY)
 
    if Err.Number = 0 then
        if DEBUG_MODE then StdOut.WriteLine "SN sign key successfully created or already existed"
        Return = 0
    else
        if DEBUG_MODE then StdOut.WriteLine "Failed creating SN sign key with error number " & Err.Number
        Return = 1
    end if
    if Return > 0 then 
        AddTestRoot = Return
        exit function
    end if

    'Add SN sign key
    dim stringValueName, stringValue
    stringValueName = "TestPublicKey"
    stringValue = "00240000048000009400000006020000002400005253413100040000010001003f8c902c8fe7ac83af7401b14c1bd103973b26dfafb2b77eda478a2539b979b56ce47f36336741b4ec52bbc51fecd51ba23810cec47070f3e29a2261a2d1d08e4b2b4b457beaa91460055f78cc89f21cd028377af0cc5e6c04699b6856a1e49d5fad3ef16d3c3d6010f40df0a7d6cc2ee11744b5cfb42e0f19a52b8a29dc31b0"
    Return = oReg.SetStringValue(HKEY_LOCAL_MACHINE, SNSIGNKEY, stringValueName, stringValue)

    if Err.Number = 0 then
        if DEBUG_MODE then StdOut.WriteLine "String value, " & stringValueName & " under SN sign key successfully added or already existed"
        Return = 0
    else
        StdOut.WriteLine "Failed trying to add string value, " & stringValueName & " under SN sign key " & Err.Number
        Return = 1
    end if

    AddSnSignKey = Return
end function

REM Returns true if the test certificate is installed
REM Returns false if test cert is not installed
public function FindDNRFlag
    dim strKeyPath, strValueName, dwValue
    dim oReg
    dim arrSubKeys()

    dim FoundTest
    FoundTest = false

    Set oReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & COMPUTER & "\root\default:StdRegProv")

    dim bytes()
    redim bytes(0)

    strKeyPath = TESTCERTKEY
    strValueName = DONOTREMOVE

    ' read protect bit
    oReg.GetDWORDValue HKEY_LOCAL_MACHINE,strKeyPath,strValueName,dwValue

    if (dwValue AND 1) = 1 then 
        FoundTest = true
    else
        FoundTest = false
    end if

    strKeyPath = SHA2_TESTCERTKEY
    strValueName = DONOTREMOVE

    ' read protect bit
    oReg.GetDWORDValue HKEY_LOCAL_MACHINE,strKeyPath,strValueName,dwValue

    if (dwValue AND 1) = 1 then 
        FoundTest = true
    else
        FoundTest = false
    end if

    FindDNRFlag = FoundTest
end function

REM Returns 0 if flag could be set (or already set)
REM Returns 1 if flag could not be set
REM Any other return value indicates an error in the script
REM
REM Assumes test certificate key already exists
public function SetDNRFlag
    dim Return
    Return = 2
    
    dim oReg
    Set oReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & COMPUTER & "\root\default:StdRegProv")

    ' set protect bit
    Return = oReg.SetDWORDValue(HKEY_LOCAL_MACHINE, TESTCERTKEY, DONOTREMOVE, 1)

    if Err.Number = 0 then
        if DEBUG_MODE then StdOut.WriteLine "[ " & DONOTREMOVE & " ] successfully set or already existed"
        Return = 0
    else
        StdOut.WriteLine "Failed trying to set protect bit on SHA1 test certificate with error number " & Err.Number
        Return = 1
    end if

    Return = oReg.SetDWORDValue(HKEY_LOCAL_MACHINE, SHA2_TESTCERTKEY, DONOTREMOVE, 1)

    if Err.Number = 0 then
        if DEBUG_MODE then StdOut.WriteLine "[ " & DONOTREMOVE & " ] successfully set or already existed"
        Return = 0
    else
        StdOut.WriteLine "Failed trying to set protect bit on SHA2 test certificate with error number " & Err.Number
        Return = 1
    end if


    SetDNRFlag = Return
end function

'' SIG '' Begin signature block
'' SIG '' MIIO6wYJKoZIhvcNAQcCoIIO3DCCDtgCAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' hyQSu3c20zncZJiKNcRr8nh4zaTRNI9aF9L6/MKQ7TOg
'' SIG '' ggwJMIIF5TCCA82gAwIBAgIKYQNfCQAAAAAAAjANBgkq
'' SIG '' hkiG9w0BAQsFADCBkDELMAkGA1UEBhMCVVMxEzARBgNV
'' SIG '' BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
'' SIG '' HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE6
'' SIG '' MDgGA1UEAxMxTWljcm9zb2Z0IFRlc3RpbmcgUm9vdCBD
'' SIG '' ZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA2
'' SIG '' MjEyMjU1MDFaFw0xNDA2MjEyMzA1MDFaMIGBMRMwEQYK
'' SIG '' CZImiZPyLGQBGRYDY29tMRkwFwYKCZImiZPyLGQBGRYJ
'' SIG '' bWljcm9zb2Z0MRQwEgYKCZImiZPyLGQBGRYEY29ycDEX
'' SIG '' MBUGCgmSJomT8ixkARkWB3JlZG1vbmQxIDAeBgNVBAMT
'' SIG '' F01TSVQgVGVzdCBDb2RlU2lnbiBDQSAzMIIBIjANBgkq
'' SIG '' hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm3HdDTItCOgt
'' SIG '' AZCc358yWItH0P6aa0BedqIQAA7Sj86hX0KnC16DwukG
'' SIG '' pgq0PTBQ2zVDLNPDxjzJtYj8C+ajcUfO/YhipCXiTht5
'' SIG '' PeO/i4QtZCWl+o4wruM0fSfzXvQFYMYPGhueryE3qdm2
'' SIG '' t2pUS16gdbWaxLa+KOM791oId9k5Sip6+PT+6BJUQRFV
'' SIG '' yMeYPmSlu9prpKopjJ8nVSXn/TFwYB3TxPK575JKn8hM
'' SIG '' k+cZqE6842L04G7sRW5hTq1Y4PDq93Qs3xv2QzyEwowL
'' SIG '' tL1KV6YMTp5zQ18tryL0pv1ah7m+b54dmcjflcICrX1K
'' SIG '' 87pd6HtuV+U6AvjTARWuTwIDAQABo4IBTDCCAUgwEAYJ
'' SIG '' KwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFE7+YTlvysVk
'' SIG '' 4CC22sG5Ug7K347+MBkGCSsGAQQBgjcUAgQMHgoAUwB1
'' SIG '' AGIAQwBBMAsGA1UdDwQEAwIBhjASBgNVHRMBAf8ECDAG
'' SIG '' AQH/AgEAMB8GA1UdIwQYMBaAFKMBBH4wiDPruTGcyuuF
'' SIG '' dmf8ZbTRMFkGA1UdHwRSMFAwTqBMoEqGSGh0dHA6Ly9j
'' SIG '' cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
'' SIG '' L01pY1Rlc1Jvb0NlckF1dF8yMDEwLTA2LTE3LmNybDBd
'' SIG '' BggrBgEFBQcBAQRRME8wTQYIKwYBBQUHMAKGQWh0dHA6
'' SIG '' Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWlj
'' SIG '' VGVzUm9vQ2VyQXV0XzIwMTAtMDYtMTcuY3J0MA0GCSqG
'' SIG '' SIb3DQEBCwUAA4ICAQCRLRE20SxeIXdiGqHPmn5iLcmQ
'' SIG '' uQ49cQ2gSkit4dawc0pRS0yya4gKWrfpVWdDi/GdzFID
'' SIG '' r6yF6dN1zuVvizyAgavR0XMNa7BRuKJeDAnlprxUSeVU
'' SIG '' OFq3Q9J1NFLdNXmVmNU8xtpGstigp8wwMQ9L67cCqys4
'' SIG '' 0rcnwscNYqTASPQaSHl94TGkXRnQGBcAyuNdC8GFf/G+
'' SIG '' 08uX9BtiD9cUOI2yLpjUQWqwtYTu2CwtE/xQHZpvMYcc
'' SIG '' 4NDQ0yRS3xKN+/d/MwQXeovjvXweoiqRdtn8QxenCqHZ
'' SIG '' xjw6Qu23Es2e3f6RnZi1NeiU3ZrO1PSsyqbNWT3eRL8O
'' SIG '' guXfXONJywGgf3viJSGrlVAen+p3Vkd0c/IlGw42uaJX
'' SIG '' vyxXvOT7iLGDVtg84Hz9EZ/e4bfUxiOvrsdeT8UjdJg4
'' SIG '' dJ0NDW303ihEQdgiaOdXp2Z0tcMxJOJ81VJditJOFLsI
'' SIG '' 0xoxEgRYmzqZeJNRPwuFzt4JWPmWG5ERoGhTM8u+CInM
'' SIG '' lVWuBngnmaJW766VCn8N60MMxp4/gLvEdAOduBqqvMse
'' SIG '' A/vYSYmdIKolS0dn9KcNjXYwxkjO3Y36vtq06z3YDDsV
'' SIG '' mtGDheXjkqo7rTQMOfF/da7ocLD98o4p2twJT4p7Y74e
'' SIG '' isNY0QO+N+ntMiaoDP7tEqdjBLOSl9lGozMznFu8VDCC
'' SIG '' BhwwggUEoAMCAQICCk1y2zgAAAASbWIwDQYJKoZIhvcN
'' SIG '' AQELBQAwgYExEzARBgoJkiaJk/IsZAEZFgNjb20xGTAX
'' SIG '' BgoJkiaJk/IsZAEZFgltaWNyb3NvZnQxFDASBgoJkiaJ
'' SIG '' k/IsZAEZFgRjb3JwMRcwFQYKCZImiZPyLGQBGRYHcmVk
'' SIG '' bW9uZDEgMB4GA1UEAxMXTVNJVCBUZXN0IENvZGVTaWdu
'' SIG '' IENBIDMwHhcNMTEwNDIxMDAwNjMxWhcNMTMwNDIwMDAw
'' SIG '' NjMxWjBwMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
'' SIG '' aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
'' SIG '' ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMRowGAYDVQQD
'' SIG '' ExFNaWNyb3NvZnQgV2luZG93czCCASIwDQYJKoZIhvcN
'' SIG '' AQEBBQADggEPADCCAQoCggEBAKmzzsfa9/m/vPwCgDWs
'' SIG '' xSt3jf3ySZNC6GyuJFn7Uu+nyprdf97wqy8LEv0KqSxt
'' SIG '' 66jT7EKyF55fDlH7hecq9WGz7IfMTVffeq+pWKL+J125
'' SIG '' beifBJY2Ts6Mi5rAhC0G3b7lw4sppaKDom6D9no0zumb
'' SIG '' 4EPwVxuFEnW5mtRaz4Ky2NImZq4wAOhVxwnoKnAlHL+a
'' SIG '' YlBe7J2TYwRnj7WjzTOCxvCpqM66s8jxFsrFa02uhRtt
'' SIG '' USTYZTqgEiF4hcVws3IG7izpFlzixeKwrn27pJ5fzxNN
'' SIG '' kCnXIwK83oa+mGBXWLnnwVoJIfWoc9OOrRkI3H2c737Z
'' SIG '' 5WdHB0t1OPEY3wsCAwEAAaOCAqQwggKgMD0GCSsGAQQB
'' SIG '' gjcVBwQwMC4GJisGAQQBgjcVCIPPiU2t8gKFoZ8MgvrK
'' SIG '' fYHh+3SBT4Sa8WmFoa0dAgFkAgENMAsGA1UdDwQEAwIH
'' SIG '' gDApBgkrBgEEAYI3FQoEHDAaMAwGCisGAQQBgjcKAwYw
'' SIG '' CgYIKwYBBQUHAwMwHwYDVR0lBBgwFgYKKwYBBAGCNwoD
'' SIG '' BgYIKwYBBQUHAwMwHQYDVR0OBBYEFC3CGiGniLv40OFB
'' SIG '' kuyL1X6qs/EqMC8GA1UdEQQoMCagJAYKKwYBBAGCNxQC
'' SIG '' A6AWDBRkYW1pdHNAbWljcm9zb2Z0LmNvbTAfBgNVHSME
'' SIG '' GDAWgBRO/mE5b8rFZOAgttrBuVIOyt+O/jCB6AYDVR0f
'' SIG '' BIHgMIHdMIHaoIHXoIHUhjZodHRwOi8vY29ycHBraS9j
'' SIG '' cmwvTVNJVCUyMFRlc3QlMjBDb2RlU2lnbiUyMENBJTIw
'' SIG '' My5jcmyGTWh0dHA6Ly9tc2NybC5taWNyb3NvZnQuY29t
'' SIG '' L3BraS9tc2NvcnAvY3JsL01TSVQlMjBUZXN0JTIwQ29k
'' SIG '' ZVNpZ24lMjBDQSUyMDMuY3JshktodHRwOi8vY3JsLm1p
'' SIG '' Y3Jvc29mdC5jb20vcGtpL21zY29ycC9jcmwvTVNJVCUy
'' SIG '' MFRlc3QlMjBDb2RlU2lnbiUyMENBJTIwMy5jcmwwgakG
'' SIG '' CCsGAQUFBwEBBIGcMIGZMEIGCCsGAQUFBzAChjZodHRw
'' SIG '' Oi8vY29ycHBraS9haWEvTVNJVCUyMFRlc3QlMjBDb2Rl
'' SIG '' U2lnbiUyMENBJTIwMy5jcnQwUwYIKwYBBQUHMAKGR2h0
'' SIG '' dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvbXNjb3Jw
'' SIG '' L01TSVQlMjBUZXN0JTIwQ29kZVNpZ24lMjBDQSUyMDMu
'' SIG '' Y3J0MA0GCSqGSIb3DQEBCwUAA4IBAQAkfL/XjG8s/yIK
'' SIG '' PMrAP0Q7kTibhHf7NzKclLU9sqYWcSYliweijHLDfQVa
'' SIG '' pU5lDOVpBYWL/dD9eV5sPKSZFV54u/yOcIyz2NZnyGt6
'' SIG '' 3YhZsmpwEzs7rr+EC3kqjPxr3yTPnzPYVbdIE0p8BQ58
'' SIG '' ApYRirpaGIau7Acj0FLyxNPQPLig/qtebgJmRwD4sSSS
'' SIG '' CmzbwQ1Ax51a19g2WNLEMe2a5o8h3BZPP9lhBjFj0XFI
'' SIG '' aaqbRBVGQrYoRAbgBfQx01cic/VXyLMv9DxskgjLOfVC
'' SIG '' PJt9T/QELbjXqFAGs2GPEfLgJm9qyK9RHOid/P7KeekX
'' SIG '' dannPKv82JUWIDxGodNlMYICOjCCAjYCAQEwgZAwgYEx
'' SIG '' EzARBgoJkiaJk/IsZAEZFgNjb20xGTAXBgoJkiaJk/Is
'' SIG '' ZAEZFgltaWNyb3NvZnQxFDASBgoJkiaJk/IsZAEZFgRj
'' SIG '' b3JwMRcwFQYKCZImiZPyLGQBGRYHcmVkbW9uZDEgMB4G
'' SIG '' A1UEAxMXTVNJVCBUZXN0IENvZGVTaWduIENBIDMCCk1y
'' SIG '' 2zgAAAASbWIwDQYJYIZIAWUDBAIBBQCgfDAQBgorBgEE
'' SIG '' AYI3AgEMMQIwADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
'' SIG '' NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
'' SIG '' FTAvBgkqhkiG9w0BCQQxIgQgUrqxV2hMwzDBg/O4JPMV
'' SIG '' qL5Ym4Z9lEzQiFKVv5AIBzowDQYJKoZIhvcNAQEBBQAE
'' SIG '' ggEAEUnzDWxDEYUt1VuBKMQ9Wo3G8mzLDcTHepSpsH4o
'' SIG '' hGvzGqbsvxZGvDFlinJjyR22FPq4nr0mMlK86aXmDLRg
'' SIG '' zKOlQVR3FNgxL/Er+Uf6ZmwdKZtC69aD3kNdIbkjExhN
'' SIG '' 9Rzmhji6Z63zWpz+BU+ONqrhPpBD0GnGhwJyI/DurKTl
'' SIG '' P23Ckx/kJuAx40Vl7Gpkoucvhf5Lq//7wdl35lYbUaty
'' SIG '' VNgIimjnEZlhZQtgEln9mRWRn1V8/WlU4DsjcFOx/jtj
'' SIG '' V2uV1RBsaELyOfDS22yGAk8BWUGxL6hlFzukogFrk+H/
'' SIG '' /M3aoI5FnkhPHiuPyaD//m1zc3jAXYsh9kmFkA==
'' SIG '' End signature block
