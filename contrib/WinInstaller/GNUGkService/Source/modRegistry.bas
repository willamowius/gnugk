Attribute VB_Name = "modRegistry"
Option Explicit

Private Declare Function RegCreateKey Lib "advapi32.dll" Alias "RegCreateKeyA" (ByVal hKey As Long, ByVal lpSubKey As String, phkResult As Long) As Long
Private Declare Function RegSetValueEx Lib "advapi32.dll" Alias "RegSetValueExA" (ByVal hKey As Long, ByVal lpValueName As String, ByVal Reserved As Long, ByVal dwType As Long, lpData As Any, ByVal cbData As Long) As Long
Private Declare Function RegCloseKey Lib "advapi32.dll" (ByVal hKey As Long) As Long
Private Declare Function RegOpenKey Lib "advapi32.dll" Alias "RegOpenKeyA" (ByVal hKey As Long, ByVal lpSubKey As String, phkResult As Long) As Long
Private Declare Function RegQueryValueEx Lib "advapi32.dll" Alias "RegQueryValueExA" (ByVal hKey As Long, ByVal lpValueName As String, ByVal lpReserved As Long, lpType As Long, lpData As Any, lpcbData As Long) As Long

Private Const REG_DWORD = 4
Private Const REG_SZ = 1
Private Const REG_EXPAND_SZ = 2
Private Const REG_MULTI_SZ = 7                   ' Cadenas múltiples Unicode

Private Const HKEY_LOCAL_MACHINE = &H80000002
Private Const DLL_REG_LOCATION = "SYSTEM\CurrentControlSet\Services\"
                            
Private Function RegQueryStringValue(ByVal hKey As Long, ByVal strValueName As String) As String
    Dim lResult As Long, lValueType As Long, strBuf As String, lDataBufSize As Long
    'retrieve nformation about the key
    lResult = RegQueryValueEx(hKey, strValueName, 0, lValueType, ByVal 0, lDataBufSize)
    If lResult = 0 Then
        If lValueType = REG_EXPAND_SZ Or lValueType = REG_SZ Or lValueType = REG_MULTI_SZ Then
            'Create a buffer
            strBuf = String(lDataBufSize, Chr$(0))
            'retrieve the key's content
            lResult = RegQueryValueEx(hKey, strValueName, 0, 0, ByVal strBuf, lDataBufSize)
            If lResult = 0 Then
                'Remove the unnecessary chr$(0)'s
                RegQueryStringValue = Left$(strBuf, InStr(1, strBuf, Chr$(0)) - 1)
            End If
        End If
    End If
End Function
Function GetLong(hKey As Long, strPath As String, strValueName As String)
    Dim Ret As Long, lResult As Long, lValueType As Long, lDataBufSize As Long
    Dim lngData As Long
    
    'Open the key
    RegOpenKey hKey, strPath, Ret
    'Get the key's content
    lResult = RegQueryValueEx(Ret, strValueName, 0, lValueType, ByVal 0, lDataBufSize)
    
    If lResult = 0 Then
        If lValueType = REG_DWORD Then
            'retrieve the key's content
            lResult = RegQueryValueEx(Ret, strValueName, 0, 4, lngData, lDataBufSize)
            If lResult = 0 Then
                GetLong = lngData
            End If
        End If
    End If
    
    'Close the key
    RegCloseKey Ret
End Function
Function GetString(hKey As Long, strPath As String, strValue As String)
    Dim Ret
    'Open the key
    RegOpenKey hKey, strPath, Ret
    'Get the key's content
    GetString = RegQueryStringValue(Ret, strValue)
    'Close the key
    RegCloseKey Ret
End Function

Sub SaveString(hKey As Long, strPath As String, strValue As String, strData As String, Optional nType As Integer = REG_EXPAND_SZ)
    Dim Ret
    'Create a new key
    RegCreateKey hKey, strPath, Ret
    'Save a string to the key
    If nType = REG_SZ Then
        RegSetValueEx Ret, strValue, 0, nType, ByVal strData, Len(strData)
    Else
        RegSetValueEx Ret, CStr(strValue), 0, nType, ByVal CStr(strData), CLng(LenB(StrConv(strData, vbFromUnicode)) + 1)
    End If
    'close the key
    RegCloseKey Ret
End Sub
Sub SaveLong(hKey As Long, strPath As String, strValue As String, lngData As Long)
    Dim Ret
    'Create a new key
    RegCreateKey hKey, strPath, Ret
    'Save a string to the key
    RegSetValueEx Ret, strValue, 0, REG_DWORD, lngData, Len(lngData)
    'close the key
    RegCloseKey Ret
End Sub
Public Sub CompleteRegistryData(strServiceName As String, Optional strDependencies As String = "")
    '*** Purpose    :
    '*** Parameters :
    '*** Comments   :
    Dim strTemp As String
    Dim lngData As Long
        

    strTemp = GetString(HKEY_LOCAL_MACHINE, DLL_REG_LOCATION & strServiceName, "ImagePath")
    
    'If empty, create it.
    If strTemp <> "" Then
        'Check if it's a correct value
        If InStr(strTemp, "-start") = 0 Then
            'Append the value
            Call SaveString(HKEY_LOCAL_MACHINE, DLL_REG_LOCATION & strServiceName, "ImagePath", strTemp & " -start -sname=" & strServiceName)
        End If
    End If
    
    If strDependencies <> "" Then
        strTemp = GetString(HKEY_LOCAL_MACHINE, DLL_REG_LOCATION & strServiceName, "DependOnService")
        
        'If empty, create it.
        If strTemp = "" Then
            'Append the value
            Call SaveString(HKEY_LOCAL_MACHINE, DLL_REG_LOCATION & strServiceName, "DependOnService", Replace(strDependencies, "|", Chr(0)), REG_MULTI_SZ)
        End If
    End If
End Sub
