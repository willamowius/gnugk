Attribute VB_Name = "modShellOps"
Option Explicit

Public Declare Sub DebugBreak Lib "kernel32" ()

Private Type STARTUPINFO
    cb As Long
    lpReserved As String
    lpDesktop As String
    lpTitle As String
    dwX As Long
    dwY As Long
    dwXSize As Long
    dwYSize As Long
    dwXCountChars As Long
    dwYCountChars As Long
    dwFillAttribute As Long
    dwFlags As Long
    wShowWindow As Integer
    cbReserved2 As Integer
    lpReserved2 As Long
    hStdInput As Long
    hStdOutput As Long
    hStdError As Long
End Type

Private Type PROCESS_INFORMATION
    hProcess As Long
    hThread As Long
    dwProcessId As Long
    dwThreadID As Long
End Type

Private Declare Function WaitForSingleObject Lib "kernel32" (ByVal hHandle As Long, ByVal dwMilliseconds As Long) As Long
Private Declare Function CreateProcessA Lib "kernel32" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, ByVal lpProcessAttributes As Long, ByVal lpThreadAttributes As Long, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, ByVal lpEnvironment As Long, ByVal lpCurrentDirectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
Private Declare Function CloseHandle Lib "kernel32" (ByVal hObject As Long) As Long
Private Declare Function GetExitCodeProcess Lib "kernel32" (ByVal hProcess As Long, lpExitCode As Long) As Long
Private Declare Function SendMessage Lib "user32" Alias "SendMessageA" (ByVal hwnd As Long, ByVal wMsg As Long, ByVal wParam As Long, lParam As Long) As Long
Private Declare Function FindWindow Lib "user32" Alias "FindWindowA" (ByVal lpClassName As Long, ByVal lpWindowName As Long) As Long
Private Declare Function GetParent Lib "user32" (ByVal hwnd As Long) As Long
Private Declare Function GetWindowThreadProcessId Lib "user32" (ByVal hwnd As Long, lpdwProcessId As Long) As Long
Private Declare Function GetWindow Lib "user32" (ByVal hwnd As Long, ByVal wCmd As Long) As Long
Const PROCESS_QUERY_INFORMATION As Long = &H400
Const PROCESS_TERMINATE As Long = &H1
Private Declare Function OpenProcess Lib "kernel32.dll" (ByVal dwDesiredAccess As Long, ByVal bInheritHandle As Boolean, ByVal dwProcessId As Long) As Long
Private Declare Function TerminateProcess Lib "kernel32.dll" (ByVal hProcess As Long, ByVal uExitCode As Long) As Boolean


Private Const NILL = 0&
Private Const WM_SYSCOMMAND = &H112
Private Const SC_CLOSE = &HF060&

Private Const NORMAL_PRIORITY_CLASS = &H20&
Private Const INFINITE = -1&

Private Const STARTF_USESHOWWINDOW = &H1
Private Const SW_HIDE = 0
Private Const SW_MINIMIZE = 6
Private Const SW_NORMAL = 1
Private Const SW_MAXIMIZE = 3

Private Const GW_HWNDNEXT = 2
Function InstanceToWnd(ByVal target_pid As Long) As Long
    '*** Purpose    :
    '*** Parameters :
    '*** Comments   :

    Dim test_hwnd As Long, test_pid As Long, test_thread_id As Long
    'Find the first window
    test_hwnd = FindWindow(ByVal 0&, ByVal 0&)
    Do While test_hwnd <> 0
        'Check if the window isn't a child
        If GetParent(test_hwnd) = 0 Then
            'Get the window's thread
            test_thread_id = GetWindowThreadProcessId(test_hwnd, test_pid)
            If test_pid = target_pid Then
                InstanceToWnd = test_hwnd
                Exit Do
            End If
        End If
        'retrieve the next window
        test_hwnd = GetWindow(test_hwnd, GW_HWNDNEXT)
    Loop

End Function

Public Function ExecCmd(cmdline As String, strVisible As String, Optional strCurDir As String = "", Optional intWaitSeconds As Integer = -1) As Long
    '*** Purpose    : Execute a shelled process.
    '*** Parameters : cmdline       : Program to run.
    '                 intWaitSeconds: Optional. Seconds to wait until program ends.
    '*** Comments   :

    Dim proc As PROCESS_INFORMATION, Ret As Long
    Dim start As STARTUPINFO, dwMilliseconds As Long
    
    If intWaitSeconds = -1 Then
        dwMilliseconds = INFINITE
    Else
        dwMilliseconds = 1000& * intWaitSeconds
    End If
    If strCurDir = "" Then
        strCurDir = App.Path
    End If
    
    ' Initialize the STARTUPINFO structure:
    With start
        .cb = Len(start)
        .dwFlags = STARTF_USESHOWWINDOW
        If LCase(strVisible) = "yes" Then
            .wShowWindow = SW_NORMAL '  SW_HIDE
        Else
            .wShowWindow = SW_HIDE
        End If
    End With
    
    ' Start the shelled application:
    Ret = CreateProcessA(vbNullString, cmdline, 0&, 0&, 1&, _
    NORMAL_PRIORITY_CLASS, 0&, strCurDir, start, proc)
    
    ' Wait for the shelled application to finish:
    Ret = WaitForSingleObject(proc.hProcess, dwMilliseconds)
    Call GetExitCodeProcess(proc.hProcess, Ret)
    
    Call CloseHandle(proc.hThread)
    Call CloseHandle(proc.hProcess)
    'ExecCmd = Ret
    
    If Ret <> 0 Then
        ExecCmd = proc.dwProcessId
    Else
        ExecCmd = 0
    End If
End Function

Public Function KillProcess(nProdID As Long) As Long
    Dim hProcess As Long
    Dim lExitCode As Long
    
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION Or PROCESS_TERMINATE, False, nProdID)
    
    If GetExitCodeProcess(hProcess, lExitCode) Then
        TerminateProcess hProcess, lExitCode
    End If
    
    CloseHandle hProcess
End Function

Public Function ProcessIsLoaded(nProdID As Long) As Boolean
    ProcessIsLoaded = (InstanceToWnd(nProdID) <> 0)
End Function
