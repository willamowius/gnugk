VERSION 5.00
Object = "{E7BC34A0-BA86-11CF-84B1-CBC2DA68BF6C}#1.0#0"; "NTSVC.ocx"
Begin VB.Form frmWrapper 
   BorderStyle     =   1  'Fixed Single
   Caption         =   "PacGnuGK NT Services Wrapper"
   ClientHeight    =   945
   ClientLeft      =   45
   ClientTop       =   330
   ClientWidth     =   4200
   ControlBox      =   0   'False
   Icon            =   "frmWrapper.frx":0000
   LinkTopic       =   "Form1"
   MaxButton       =   0   'False
   MinButton       =   0   'False
   ScaleHeight     =   945
   ScaleWidth      =   4200
   StartUpPosition =   2  'CenterScreen
   Visible         =   0   'False
   Begin NTService.NTService NTService1 
      Left            =   135
      Top             =   15
      _Version        =   65536
      _ExtentX        =   741
      _ExtentY        =   741
      _StockProps     =   0
      ServiceName     =   "Simple"
      StartMode       =   3
   End
   Begin VB.Timer Timer 
      Enabled         =   0   'False
      Left            =   660
      Top             =   15
   End
   Begin VB.Label Label1 
      Caption         =   "This form is not visible at runtime. It is only to configure service and launch program."
      Height          =   435
      Left            =   135
      TabIndex        =   0
      Top             =   495
      Width           =   3615
   End
End
Attribute VB_Name = "frmWrapper"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Option Explicit


Dim strAction As String

'*******************************
'* Data to configurate service *
'*******************************
Dim strAccount As String
Dim strPassword As String
Dim strDependencies As String
Dim strDisplayName As String
Dim strServiceName As String
Dim strStartMode As String
Dim strCommandLine As String
Dim strTimeOut As String
Dim strVisible As String
Dim strProcess As String
Dim cmdstr As String
Dim strsvcstart As String

Private Function RetrieveParams() As Boolean
    '*** Purpose    : Take command line parameters, and store values
    '*** Parameters :
    '*** Comments   : If it is any error, an Error Message will be showed.
 
    Dim sTemp As String
    Dim aValues() As String, intCount As Integer
    Dim strKey As String, strValue As String
    Dim strHelp As String
    
    cmdstr = Command
    sTemp = cmdstr
        
    'Help to error message
    strHelp = "Sintax: " & App.EXEName & " [Action] -SName={Service Name} -Command={command line} [-option1=value] [-option2=value] [-optionN=value]" & vbCrLf & vbCrLf
    strHelp = strHelp & "Action must be -install or -uninstall" & vbCrLf & vbCrLf
    strHelp = strHelp & "-SName: Name of the service." & vbCrLf
    strHelp = strHelp & "-Command: Pathname of command to execute." & vbCrLf
    strHelp = strHelp & "-Process: Name of the process to check." & vbCrLf & vbCrLf
    strHelp = strHelp & "Options:" & vbCrLf
    strHelp = strHelp & "-Timeout: Seconds to wait until command return control to service. Default=60." & vbCrLf
    strHelp = strHelp & "-Visible: Indicates if command will be visible or not when it runs. Default=Yes." & vbCrLf
    strHelp = strHelp & "-DisplayName: Display name of the service. Default=" & App.EXEName & vbCrLf
    strHelp = strHelp & "-Account: Assign a logon account to a service. Default=Local account." & vbCrLf
    strHelp = strHelp & "-Password: Password for the user account. Default=(Empty)" & vbCrLf
    strHelp = strHelp & "-Dependencies: List of services that this service depend on. Default=(Empty)" & vbCrLf
    strHelp = strHelp & "-Start: Start Mode: Automatic or Manual. Default=Automatic." & vbCrLf
    
    'First, asume default values
    strAction = ""
    strAccount = ""
    strPassword = ""
    strDependencies = ""
    strDisplayName = App.EXEName
    strServiceName = "" ' No default
    strStartMode = "auto"
    strVisible = "yes"
    
    'Get params
    aValues = Split(sTemp, " -")
    
    RetrieveParams = True
    
    'Scan array
    For intCount = 0 To UBound(aValues)
        If InStr(aValues(intCount), "=") <> 0 Then
            strKey = Split(aValues(intCount), "=")(0)
            strValue = Split(aValues(intCount), "=")(1)
            strValue = Replace(strValue, Chr(34), "")
        Else
            strKey = aValues(intCount)
            strValue = ""
        End If
        
        strKey = Trim(LCase(strKey))
        strValue = Trim(strValue)
        
        'Is it a valid param ?
        Select Case LCase(strKey)
            Case "-install", "-uninstall", "-service"
                strAction = LCase(strKey)
            Case "account"
                strAccount = strValue
            Case "password"
                strPassword = strValue
            Case "dependencies"
                strDependencies = strValue
            Case "displayname"
                strDisplayName = strValue
            Case "sname"
                strServiceName = strValue
            Case "start"
                strStartMode = LCase(strValue)
            Case "command"
                strCommandLine = strValue
            Case "process"
                strProcess = strValue
            Case "timeout"
                strTimeOut = strValue
            Case "visible"
                strVisible = strValue
            Case "svcstart"
                strsvcstart = strValue
        End Select
    Next
    
    'Validate params
    If sTemp <> "" Then
        If strServiceName = "" Then
            RetrieveParams = False
        Else
            If strAction = "-install" Then
                If strStartMode <> "" Then
                    If InStr("auto|manual|automatic", LCase(strStartMode)) = 0 Then
                        RetrieveParams = False
                    End If
                End If
                
                If strVisible <> "" Then
                    If InStr("yes|no", LCase(strVisible)) = 0 Then
                        RetrieveParams = False
                    End If
                End If
                
                If strCommandLine = "" Or strProcess = "" Then
                    RetrieveParams = False
                End If
                
                If strDependencies <> "" Then
                    strDependencies = strDependencies & "||"
                End If
            End If
        End If
        
        If Not RetrieveParams Then
            MsgBox strHelp, vbCritical, Me.Caption
        End If
    End If
End Function

Private Sub Form_Load()
    '*** Purpose    : Main Sub
    '*** Parameters : None
    '*** Comments   : This procedure will be called when the service is installed, uninstalled,
    '                 when is started and stopped.
 
    If RetrieveParams Then
    
        'Try to Install Service
        If strAction = "-install" Then
        
            'Configure Control.
            With Me.NTService1
                .Account = strAccount
                .Password = strPassword
                .Dependencies = Replace(strDependencies, "|", Chr(0))
                .DisplayName = strDisplayName
                If strAccount = "" Then
                    .Interactive = True
                End If
                .ServiceName = strServiceName
                If strStartMode = "manual" Then
                    .StartMode = svcStartManual
                Else
                    .StartMode = svcStartAutomatic
                End If
            End With
            
            If NTService1.Install Then
                'If it was installed, save some data.
                Call NTService1.SaveSetting("Parameters", "DisplayName", strDisplayName)
                Call NTService1.SaveSetting("Parameters", "TimerInterval", "1000")
                Call NTService1.SaveSetting("Parameters", "Command", strCommandLine)
                Call NTService1.SaveSetting("Parameters", "Visible", strVisible)
                Call NTService1.SaveSetting("Parameters", "Timeout", strTimeOut)
                Call NTService1.SaveSetting("Parameters", "Process", strProcess)
                
                
                'Make a little change into reg, to append parameters to exe call.
                Call CompleteRegistryData(strServiceName, strDependencies)
                
                MsgBox strDisplayName & " installed successfully!", vbInformation, Me.Caption
            Else
                MsgBox strDisplayName & " failed to install!", vbCritical, Me.Caption
            End If
            
        End If
        
        If strAction = "-service" Then
                If strsvcstart <> "" Then
                    If InStr("yes|no", LCase(strsvcstart)) <> 0 Then
                      With Me.NTService1
                      .ServiceName = strServiceName
                      .DisplayName = strDisplayName

                      If strsvcstart = "yes" Then
                        .Interactive = True
                        If .Running = True Then
                            'do nothing since already running
                            MsgBox "Already running!", vbOKOnly + vbExclamation, vbInformation, Me.Caption
                            Unload Me
                            End
                        Else
                           'start it
                           If .StartService Then
                               MsgBox strDisplayName & " started successfully", vbInformation, Me.Caption
                           Else
                               MsgBox strDisplayName & " failed to start", vbInformation, Me.Caption
                           End If

                           .ControlsAccepted = svcCtrlPauseContinue
                       End If
                      Else
                           .StopService
                            MsgBox strDisplayName & " stopped successfully", vbInformation, Me.Caption
                            Unload Me
                            End
                      End If
                      End With
                    End If
                End If
                End
        End If
        
        'Try to uninstall service.
        If strAction = "-uninstall" Then
            Me.NTService1.ServiceName = strServiceName
            strDisplayName = NTService1.GetSetting("Parameters", "DisplayName", "")
            With Me.NTService1
                .DisplayName = strDisplayName
                .ServiceName = strServiceName
            End With
            
            If NTService1.Uninstall Then
                MsgBox strDisplayName & " uninstalled successfully!", vbInformation, Me.Caption
            Else
                MsgBox strDisplayName & " failed to uninstall!", vbCritical, Me.Caption
            End If
            End
        End If
    Else
        End
    End If
    
    'start service.
    Me.NTService1.ServiceName = strServiceName
    
    Dim parmInterval As String
    parmInterval = NTService1.GetSetting("Parameters", "TimerInterval", "1000")
    strDisplayName = NTService1.GetSetting("Parameters", "DisplayName", "")
    strCommandLine = NTService1.GetSetting("Parameters", "Command", "")
    strTimeOut = NTService1.GetSetting("Parameters", "Timeout", "60")
    strVisible = NTService1.GetSetting("Parameters", "Visible", "yes")
    strProcess = NTService1.GetSetting("Parameters", "Process", "")
    Me.NTService1.DisplayName = strDisplayName
    
   
    'Timer is used to check if shelled process is running or not.
    Timer.Interval = CInt(parmInterval)
    
    ' enable Pause/Continue. Must be set before StartService
    ' is called or in design mode
    NTService1.ControlsAccepted = svcCtrlPauseContinue
    
    ' connect service to Windows NT services controller
    NTService1.StartService
    Me.Timer.Enabled = True
End Sub

Private Sub Form_QueryUnload(Cancel As Integer, UnloadMode As Integer)
 Timer.Enabled = False
End Sub

Private Sub NTService1_Continue(success As Boolean)
    '*** Purpose    : Continue, after a pause.
    '*** Parameters : Sucess: Set to True to confirm event.
    '*** Comments   :
    
    On Error GoTo Err_Continue
    
    Me.Timer.Enabled = True
    success = True
    Call NTService1.LogEvent(svcEventInformation, svcMessageInfo, "Service continued")
    Exit Sub
Err_Continue:
    Call NTService1.LogEvent(svcMessageError, svcEventError, "[" & Err.Number & "] " & Err.Description)
End Sub


Private Sub NTService1_Pause(success As Boolean)
    '*** Purpose    : Pause the service.
    '*** Parameters : Sucess: Set to True to confirm event.
    '*** Comments   :
    
    On Error GoTo Err_Pause
    
    Timer.Enabled = False
    Call NTService1.LogEvent(svcEventError, svcMessageError, "Service paused")
    success = True
    Exit Sub
Err_Pause:
    Call NTService1.LogEvent(svcMessageError, svcEventError, "[" & Err.Number & "] " & Err.Description)
End Sub


Private Sub NTService1_Start(success As Boolean)
    '*** Purpose    : Start the service.
    '*** Parameters : Sucess: Set to True to confirm event.
    '*** Comments   : In this procedure is called the desired program.
    Dim lngProcessHandle As Long    ' Handle to Shelled process.
    
    On Error GoTo Err_Start
    
    lngProcessHandle = ExecCmd(strCommandLine, strVisible, , Val(strTimeOut))
    If lngProcessHandle <> 0 Then
        success = True
    Else
        success = False
    End If
    Exit Sub
Err_Start:
    Call NTService1.LogEvent(svcMessageError, svcEventError, "[" & Err.Number & "] " & Err.Description)
End Sub

Private Sub NTService1_Stop()
    '*** Purpose    : Stop service.
    '*** Parameters :
    '*** Comments   :
    
    Dim lngError As Long, lngProcessHandle As Long
    
    On Error GoTo Err_Stop
    
    'Unload process
    lngProcessHandle = GetPIDFromProcess(strProcess)
    lngError = KillProcess(lngProcessHandle)
    
    lngProcessHandle = GetPIDFromProcess(App.EXEName)
    lngError = KillProcess(lngProcessHandle)
    
    Exit Sub
Err_Stop:
    Call NTService1.LogEvent(svcMessageError, svcEventError, "[" & Err.Number & "] " & Err.Description)
End Sub

Private Sub Timer_Timer()
    '*** Purpose    : Check if shelled process is running.
    '*** Parameters :
    '*** Comments   :
    Static bCanCheck As Boolean
    Dim success As Boolean
    Dim visible As Long
    
    
   On Error GoTo Err_Timer
    If bCanCheck Then
        If Not IsProcessRunning(strProcess) And NTService1.Running Then
            NTService1_Start success
        End If
    End If
    bCanCheck = True
    Exit Sub
Err_Timer:
    Call NTService1.LogEvent(svcMessageError, svcEventError, "[" & Err.Number & "] " & Err.Description)
    Unload Me
End Sub



