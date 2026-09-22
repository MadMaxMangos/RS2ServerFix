option casemap:none

EXTERN __imp_X3DAudioInitialize:QWORD
EXTERN FixtureState:DWORD
EXTERN FixtureHandle:BYTE
IFDEF RS2_OBSERVER_FIXTURE
EXTERN __imp_SteamInternal_FindOrCreateGameServerInterface:QWORD
ENDIF

.const
ALIGN 16
PUBLIC FixtureBadConstant, FixtureGoodConstant
FixtureBadConstant DWORD 038000100h,038000100h,038000100h,038000100h
FixtureGoodConstant DWORD 038000000h,038000000h,038000000h,038000000h
FixtureSpeed REAL4 343.5

IFDEF RS2_OBSERVER_FIXTURE
PUBLIC FixtureSteamLiteral
FixtureSteamLiteral BYTE "SteamGameServer013",0
.data
ALIGN 8
PUBLIC FixtureSteamContext, FixtureSteamPrivate, FixtureSteamPublication
FixtureSteamContext QWORD FixtureSteamAccessor,0,0
FixtureSteamPrivate QWORD 0
FixtureSteamPublication QWORD 0
ENDIF

.code
PUBLIC FixtureInitialize, FixtureReturn, FixtureInitializeEnd
; Entry is reached from our EXE's explicit CRT initializer slot.
FixtureInitialize PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    mov ecx, 3
    movss xmm1, DWORD PTR FixtureSpeed
    lea r8, FixtureHandle
    call QWORD PTR __imp_X3DAudioInitialize
FixtureReturn LABEL BYTE
    add rsp, 28h
    ret
FixtureInitializeEnd LABEL BYTE
FixtureInitialize ENDP

PUBLIC FixtureRecon, FixtureReconLoad, FixtureReconEnd
ALIGN 16
; int FixtureRecon(int draw, int count): own-code SSE selector, never an array read.
FixtureRecon PROC
    cvtsi2ss xmm0, ecx
    cvtsi2ss xmm1, edx
    ALIGN 4
FixtureReconLoad LABEL BYTE
    movss xmm2, DWORD PTR FixtureBadConstant
    DB 00Fh,01Fh,040h,000h
    mulss xmm1, xmm2
    mulss xmm0, xmm1
    cvttss2si eax, xmm0
    ret
FixtureReconEnd LABEL BYTE
FixtureRecon ENDP

IFDEF RS2_OBSERVER_FIXTURE
PUBLIC FixtureSteamAccessor, FixtureSteamAccessorReturn, FixtureSteamAccessorEnd
FixtureSteamAccessor PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    mov ecx, 23
    lea rdx, FixtureSteamLiteral
    call QWORD PTR __imp_SteamInternal_FindOrCreateGameServerInterface
FixtureSteamAccessorReturn LABEL BYTE
    add rsp, 28h
    ret
FixtureSteamAccessorEnd LABEL BYTE
FixtureSteamAccessor ENDP

; Two distinct original caller return RVAs exercise the diagnostic buckets.
PUBLIC FixtureSteamPublisher, FixtureSteamPublisherReturn
FixtureSteamPublisher PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    mov rax, [rcx]
    call QWORD PTR [rax+8*8]
FixtureSteamPublisherReturn LABEL BYTE
    add rsp, 28h
    ret
FixtureSteamPublisher ENDP
PUBLIC FixtureSteamAdvertise, FixtureSteamAdvertiseReturn
FixtureSteamAdvertise PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    mov rax, [rcx]
    call QWORD PTR [rax+8*8]
FixtureSteamAdvertiseReturn LABEL BYTE
    add rsp, 28h
    ret
FixtureSteamAdvertise ENDP
ENDIF
END
