Attribute VB_Name = "mnuWait"

Private Type FILETIME
    dwLowDateTime As Long
    dwHighDateTime As Long
End Type

Private Const WAIT_ABANDONED& = &H80&
Private Const WAIT_ABANDONED_0& = &H80&
Private Const WAIT_FAILED& = -1&
Private Const WAIT_IO_COMPLETION& = &HC0&
Private Const WAIT_OBJECT_0& = 0
Private Const WAIT_OBJECT_1& = 1
Private Const WAIT_TIMEOUT& = &H102&

Private Const INFINITE = &HFFFF
Private Const ERROR_ALREADY_EXISTS = 183&

Private Const QS_HOTKEY& = &H80
Private Const QS_KEY& = &H1
Private Const QS_MOUSEBUTTON& = &H4
Private Const QS_MOUSEMOVE& = &H2
Private Const QS_PAINT& = &H20
Private Const QS_POSTMESSAGE& = &H8
Private Const QS_SENDMESSAGE& = &H40
Private Const QS_TIMER& = &H10
Private Const QS_MOUSE& = (QS_MOUSEMOVE _
                            Or QS_MOUSEBUTTON)
Private Const QS_INPUT& = (QS_MOUSE _
                            Or QS_KEY)
Private Const QS_ALLEVENTS& = (QS_INPUT _
                            Or QS_POSTMESSAGE _
                            Or QS_TIMER _
                            Or QS_PAINT _
                            Or QS_HOTKEY)
Private Const QS_ALLINPUT& = (QS_SENDMESSAGE _
                            Or QS_PAINT _
                            Or QS_TIMER _
                            Or QS_POSTMESSAGE _
                            Or QS_MOUSEBUTTON _
                            Or QS_MOUSEMOVE _
                            Or QS_HOTKEY _
                            Or QS_KEY)

Private Declare Function CreateWaitableTimer Lib "kernel32" _
    Alias "CreateWaitableTimerA" ( _
    ByVal lpSemaphoreAttributes As Long, _
    ByVal bManualReset As Long, _
    ByVal lpName As String) As Long

Private Declare Function OpenWaitableTimer Lib "kernel32" _
    Alias "OpenWaitableTimerA" ( _
    ByVal dwDesiredAccess As Long, _
    ByVal bInheritHandle As Long, _
    ByVal lpName As String) As Long

Private Declare Function SetWaitableTimer Lib "kernel32" ( _
    ByVal hTimer As Long, _
    lpDueTime As FILETIME, _
    ByVal lPeriod As Long, _
    ByVal pfnCompletionRoutine As Long, _
    ByVal lpArgToCompletionRoutine As Long, _
    ByVal fResume As Long) As Long

Private Declare Function CancelWaitableTimer Lib "kernel32" ( _
    ByVal hTimer As Long)

Private Declare Function CloseHandle Lib "kernel32" ( _
    ByVal hObject As Long) As Long

Private Declare Function WaitForSingleObject Lib "kernel32" ( _
    ByVal hHandle As Long, _
    ByVal dwMilliseconds As Long) As Long

Private Declare Function MsgWaitForMultipleObjects Lib "user32" ( _
    ByVal nCount As Long, _
    pHandles As Long, _
    ByVal fWaitAll As Long, _
    ByVal dwMilliseconds As Long, _
    ByVal dwWakeMask As Long) As Long

Public Sub Wait(lNumberOfSeconds As Long)
    Dim ft As FILETIME
    Dim lBusy As Long
    Dim lRet As Long
    Dim dblDelay As Double
    Dim dblDelayLow As Double
    Dim dblUnits As Double
    Dim hTimer As Long

    hTimer = CreateWaitableTimer(0, True, App.EXEName & "Timer")

    If Err.LastDllError = ERROR_ALREADY_EXISTS Then
        ' If the timer already exists, it does not hurt to open it
        ' as long as the person who is trying to open it has the
        ' proper access rights.
    Else
        ft.dwLowDateTime = -1
        ft.dwHighDateTime = -1
        lRet = SetWaitableTimer(hTimer, ft, 0, 0, 0, 0)
    End If

    ' Convert the Units to nanoseconds.
    dblUnits = CDbl(&H10000) * CDbl(&H10000)
    dblDelay = CDbl(lNumberOfSeconds) * 1000 * 10000

    ' By setting the high/low time to a negative number, it tells
    ' the Wait (in SetWaitableTimer) to use an offset time as
    ' opposed to a hardcoded time. If it were positive, it would
    ' try to convert the value to GMT.
    ft.dwHighDateTime = -CLng(dblDelay / dblUnits) - 1
    dblDelayLow = -dblUnits * (dblDelay / dblUnits - _
        Fix(dblDelay / dblUnits))

    If dblDelayLow < CDbl(&H80000000) Then
        ' &H80000000 is MAX_LONG, so you are just making sure
        ' that you don't overflow when you try to stick it into
        ' the FILETIME structure.
        dblDelayLow = dblUnits + dblDelayLow
        ft.dwHighDateTime = ft.dwHighDateTime + 1
    End If

    ft.dwLowDateTime = CLng(dblDelayLow)
    lRet = SetWaitableTimer(hTimer, ft, 0, 0, 0, False)

    Do
        ' QS_ALLINPUT means that MsgWaitForMultipleObjects will
        ' return every time the thread in which it is running gets
        ' a message. If you wanted to handle messages in here you could,
        ' but by calling Doevents you are letting DefWindowProc
        ' do its normal windows message handling---Like DDE, etc.
        lBusy = MsgWaitForMultipleObjects(1, hTimer, False, _
            INFINITE, QS_ALLINPUT&)
        DoEvents
    Loop Until lBusy = WAIT_OBJECT_0

    ' Close the handles when you are done with them.
    CloseHandle hTimer

End Sub



