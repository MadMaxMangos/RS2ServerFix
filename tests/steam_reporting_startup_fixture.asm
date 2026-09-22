option casemap:none

EXTERN __imp_SteamGameServer_RunCallbacks:QWORD
EXTERN __imp_SetLastError:QWORD
EXTERN __imp_GetLastError:QWORD
EXTERN __imp_QueryPerformanceCounter:QWORD
EXTERN FixtureReportNativeBuild:PROC
EXTERN FixtureReportNativeProduce:PROC
EXTERN FixtureReportTickableObject:QWORD
EXTERN FixtureReportTaskPool:BYTE
EXTERN FixtureReportCallbackErrors:DWORD
EXTERN FixtureReportBuilderErrors:DWORD
EXTERN FixtureReportLastBuilderResult:DWORD
EXTERN FixtureReportSkipBuilder:DWORD
EXTERN FixtureReportPumpBefore:QWORD
EXTERN FixtureReportPumpAfter:QWORD
EXTERN FixtureReportBuilderBefore:QWORD
EXTERN FixtureReportBuilderAfter:QWORD
EXTERN FixtureReportTimingClockErrors:DWORD

.const
ALIGN 8
PUBLIC FixtureReportObjectVtable, FixtureReportMetadataVtable
FixtureReportObjectVtable QWORD FixtureReportObjectNoop
; Own inert metadata, not a copied engine vtable. Only required typed slots
; have distinct targets; no entry is invoked as an SDK/game object method.
FixtureReportMetadataVtable QWORD 13 DUP (FixtureReportObjectNoop)
    QWORD FixtureReportAdapter
    QWORD FixtureReportObjectNoop
    QWORD 5 DUP (FixtureReportObjectNoop)
    QWORD FixtureReportObjectNoop

.code
PUBLIC FixtureReportObjectNoop, FixtureReportObjectNoopEnd
FixtureReportObjectNoop PROC
    ret
FixtureReportObjectNoopEnd LABEL BYTE
FixtureReportObjectNoop ENDP

PUBLIC FixtureReportBuilder, FixtureReportBuilderEnd
FixtureReportBuilder PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    call FixtureReportNativeBuild
    add rsp, 28h
    ret
FixtureReportBuilderEnd LABEL BYTE
FixtureReportBuilder ENDP

PUBLIC FixtureReportAdapter, FixtureReportAdapterReturn, FixtureReportAdapterEnd
FixtureReportAdapter PROC FRAME
    sub rsp, 38h
    .allocstack 38h
    .endprolog
    mov eax, DWORD PTR [FixtureReportTaskPool+38h]
    mov DWORD PTR [rsp+20h], eax
    ; Own-host measurement only. No timing operation is added inside the DLL's
    ; qualified full-dirty store -> original call sequence.
    lea rcx, FixtureReportBuilderBefore
    call QWORD PTR __imp_QueryPerformanceCounter
    test eax, eax
    jne builder_clock_before_ok
    inc DWORD PTR FixtureReportTimingClockErrors
builder_clock_before_ok:
    mov ecx, 04321h
    call QWORD PTR __imp_SetLastError
    lea rcx, [rsp+20h]
    mov rax, QWORD PTR [FixtureReportTaskPool+40h]
    call rax
FixtureReportAdapterReturn LABEL BYTE
    movzx eax, al
    mov DWORD PTR FixtureReportLastBuilderResult, eax
    call QWORD PTR __imp_GetLastError
    mov DWORD PTR [rsp+24h], eax
    lea rcx, FixtureReportBuilderAfter
    call QWORD PTR __imp_QueryPerformanceCounter
    test eax, eax
    jne builder_clock_after_ok
    inc DWORD PTR FixtureReportTimingClockErrors
builder_clock_after_ok:
    mov eax, DWORD PTR [rsp+24h]
    cmp eax, 05678h
    je builder_error_ok
    inc DWORD PTR FixtureReportBuilderErrors
builder_error_ok:
    mov ecx, DWORD PTR [rsp+24h]
    call QWORD PTR __imp_SetLastError
    mov eax, DWORD PTR FixtureReportLastBuilderResult
    add rsp, 38h
    ret
FixtureReportAdapterEnd LABEL BYTE
FixtureReportAdapter ENDP

PUBLIC FixtureReportDispatch, FixtureReportDispatchReturn, FixtureReportDispatchEnd
FixtureReportDispatch PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    call FixtureReportAdapter
FixtureReportDispatchReturn LABEL BYTE
    add rsp, 28h
    ret
FixtureReportDispatchEnd LABEL BYTE
FixtureReportDispatch ENDP

PUBLIC FixtureReportTaskPump, FixtureReportTaskPumpReturn, FixtureReportTaskPumpEnd
FixtureReportTaskPump PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    call FixtureReportDispatch
FixtureReportTaskPumpReturn LABEL BYTE
    add rsp, 28h
    ret
FixtureReportTaskPumpEnd LABEL BYTE
FixtureReportTaskPump ENDP

PUBLIC FixtureReportUpdate, FixtureReportUpdateReturn, FixtureReportUpdateEnd
FixtureReportUpdate PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    call FixtureReportTaskPump
FixtureReportUpdateReturn LABEL BYTE
    add rsp, 28h
    ret
FixtureReportUpdateEnd LABEL BYTE
FixtureReportUpdate ENDP

PUBLIC FixtureReportLeechTick, FixtureReportTickReturn, FixtureReportLeechTickEnd
FixtureReportLeechTick PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    call FixtureReportUpdate
FixtureReportTickReturn LABEL BYTE
    add rsp, 28h
    ret
FixtureReportLeechTickEnd LABEL BYTE
FixtureReportLeechTick ENDP

PUBLIC FixtureReportSubsystem, FixtureReportSubsystemReturn, FixtureReportSubsystemEnd
FixtureReportSubsystem PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    cmp DWORD PTR FixtureReportSkipBuilder, 0
    jne skip_fixture_builder
    call FixtureReportLeechTick
FixtureReportSubsystemReturn LABEL BYTE
skip_fixture_builder:
    call FixtureReportNativeProduce
    add rsp, 28h
    ; The real subsystem frame is gone at the post-callback boundary. This
    ; tail jump preserves the same World/Engine parents for the three-frame gate.
    jmp FixtureReportCallbackPump
FixtureReportSubsystemEnd LABEL BYTE
FixtureReportSubsystem ENDP

PUBLIC FixtureReportCallbackPump, FixtureReportCallbackReturn, FixtureReportCallbackPumpEnd
FixtureReportCallbackPump PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    lea rcx, FixtureReportPumpBefore
    call QWORD PTR __imp_QueryPerformanceCounter
    test eax, eax
    jne pump_clock_before_ok
    inc DWORD PTR FixtureReportTimingClockErrors
pump_clock_before_ok:
    mov ecx, 04321h
    call QWORD PTR __imp_SetLastError
    call QWORD PTR __imp_SteamGameServer_RunCallbacks
FixtureReportCallbackReturn LABEL BYTE
    call QWORD PTR __imp_GetLastError
    mov DWORD PTR [rsp+20h], eax
    lea rcx, FixtureReportPumpAfter
    call QWORD PTR __imp_QueryPerformanceCounter
    test eax, eax
    jne pump_clock_after_ok
    inc DWORD PTR FixtureReportTimingClockErrors
pump_clock_after_ok:
    mov eax, DWORD PTR [rsp+20h]
    cmp eax, 05678h
    je callback_error_ok
    inc DWORD PTR FixtureReportCallbackErrors
callback_error_ok:
    mov ecx, DWORD PTR [rsp+20h]
    call QWORD PTR __imp_SetLastError
    add rsp, 28h
    ret
FixtureReportCallbackPumpEnd LABEL BYTE
FixtureReportCallbackPump ENDP

PUBLIC FixtureReportWorldTick, FixtureReportWorldReturn, FixtureReportWorldTickEnd
FixtureReportWorldTick PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    mov rcx, QWORD PTR FixtureReportTickableObject
    mov rax, QWORD PTR [rcx]
    call QWORD PTR [rax+8]
FixtureReportWorldReturn LABEL BYTE
    add rsp, 28h
    ret
FixtureReportWorldTickEnd LABEL BYTE
FixtureReportWorldTick ENDP

PUBLIC FixtureReportEngine, FixtureReportEngineReturn, FixtureReportEngineEnd
FixtureReportEngine PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    call FixtureReportWorldTick
FixtureReportEngineReturn LABEL BYTE
    add rsp, 28h
    ret
FixtureReportEngineEnd LABEL BYTE
FixtureReportEngine ENDP
END
