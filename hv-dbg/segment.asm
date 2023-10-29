PUBLIC __vmx_enable
PUBLIC AsmPerformInvept
PUBLIC __readcs
PUBLIC __readds
PUBLIC __reades
PUBLIC __readss
PUBLIC __readfs
PUBLIC __readgs
PUBLIC __readldtr
PUBLIC __readtr
PUBLIC __readgdtbase
PUBLIC __readidtbase
PUBLIC __getgdtlimit
PUBLIC __getidtlimit
PUBLIC __readrflags
PUBLIC __vmx_terminate
PUBLIC SaveStateAndVirtualizeCore
PUBLIC AsmVmexitHandler
PUBLIC VmxRestoreState
PUBLIC MSRRead
PUBLIC MSRWrite

EXTERN g_StackPointerForReturning:QWORD
EXTERN g_BasePointerForReturning:QWORD

EXTERN MainVmexitHandler:PROC
EXTERN VmResumeInstruction:PROC
EXTERN VirtualizeCore:PROC

EXTERN InsertStackPointerIntoIpiContextStruct:PROC

.code _text

;------------------------------------------------------------------------
    VMX_ERROR_CODE_SUCCESS              = 0
    VMX_ERROR_CODE_FAILED_WITH_STATUS   = 1
    VMX_ERROR_CODE_FAILED               = 2
;------------------------------------------------------------------------

AsmVmexitHandler PROC

    PUSH R15
    PUSH R14
    PUSH R13
    PUSH R12
    PUSH R11
    PUSH R10
    PUSH R9
    PUSH R8        
    PUSH RDI
    PUSH RSI
    PUSH RBP
    PUSH RBP	; RSP
    PUSH RBX
    PUSH RDX
    PUSH RCX
    PUSH RAX	

	MOV RCX, RSP		; GuestRegs
	SUB	RSP, 28h

	CALL	MainVmexitHandler
	ADD	RSP, 28h	

	POP RAX
    POP RCX
    POP RDX
    POP RBX
    POP RBP		; RSP
    POP RBP
    POP RSI
    POP RDI 
    POP R8
    POP R9
    POP R10
    POP R11
    POP R12
    POP R13
    POP R14
    POP R15

	SUB RSP, 0100h ; to avoid error in future functions
	
    JMP VmResumeInstruction
	
AsmVmexitHandler ENDP

VmxRestoreState PROC

	ADD RSP, 28h
	POP R15
	POP R14
	POP R13
	POP R12
	POP R11
	POP R10
	POP R9
	POP R8
	POP RDI
	POP RSI
	POP RBP
	POP RBX
	POP RDX
	POP RCX
	POP RAX
	
	RET
	
VmxRestoreState ENDP

__vmx_enable PROC PUBLIC

	PUSH RAX			    ; Save the state
	
	XOR RAX, RAX			; Clear the RAX
	MOV RAX, CR4

	OR RAX,02000h	    	; Set the 14th bit
	MOV CR4, RAX
	
	POP RAX			     	; Restore the state
	RET

__vmx_enable ENDP

;------------------------------------------------------------------------

AsmPerformInvept PROC PUBLIC

	INVEPT  RCX, OWORD PTR [RDX]
	JZ FailedWithStatus
	JC Failed
	XOR     RAX, RAX

	RET

FailedWithStatus:    
	MOV     RAX, VMX_ERROR_CODE_FAILED_WITH_STATUS
	RET

Failed:   
	MOV     RAX, VMX_ERROR_CODE_FAILED
	RET

AsmPerformInvept ENDP

;------------------------------------------------------------------------

__vmx_terminate PROC PUBLIC

	VMXOFF  ; turn it off before existing
	
	MOV RSP, g_StackPointerForReturning
	MOV RBP, g_BasePointerForReturning
	
	; make rsp point to a correct return point
	ADD RSP, 8
	
	; return True

	XOR RAX, RAX
	MOV RAX, 1
	
	; return section
	
	MOV     RBX, [RSP+28h+8h]
	MOV     RSI, [RSP+28h+10h]
	ADD     RSP, 020h
	POP     RDI
	
	RET
	
__vmx_terminate ENDP 

;------------------------------------------------------------------------

; No need to raise the irql as these routines run at IPI_LEVEL 

SaveStateAndVirtualizeCore PROC PUBLIC

	PUSH RAX
	PUSH RCX
	PUSH RDX
	PUSH RBX
	PUSH RBP
	PUSH RSI
	PUSH RDI
	PUSH R8
	PUSH R9
	PUSH R10
	PUSH R11
	PUSH R12
	PUSH R13
	PUSH R14
	PUSH R15
	SUB RSP, 28h
	MOV RDX, RSP
	CALL VirtualizeCore	
	RET

SaveStateAndVirtualizeCore ENDP 

;------------------------------------------------------------------------

__readgdtbase PROC

	LOCAL	GDTR[10]:BYTE
	SGDT	GDTR
	MOV		RAX, QWORD PTR GDTR[2]

	RET

__readgdtbase ENDP

;------------------------------------------------------------------------

__readcs PROC

	MOV		RAX, CS
	RET

__readcs ENDP

;------------------------------------------------------------------------

__readds PROC

	MOV		RAX, DS
	RET

__readds ENDP

;------------------------------------------------------------------------

__reades PROC

	MOV		RAX, ES
	RET

__reades ENDP

;------------------------------------------------------------------------

__readss PROC

	MOV		RAX, SS
	RET

__readss ENDP

;------------------------------------------------------------------------

__readfs PROC

	MOV		RAX, FS
	RET

__readfs ENDP

;------------------------------------------------------------------------

__readgs PROC

	MOV		RAX, GS
	RET

__readgs ENDP

;------------------------------------------------------------------------

__readldtr PROC

	SLDT	RAX
	RET

__readldtr ENDP

;------------------------------------------------------------------------

__readtr PROC

	STR		RAX
	RET

__readtr ENDP

;------------------------------------------------------------------------

__readidtbase PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		RAX, QWORD PTR IDTR[2]
	RET

__readidtbase ENDP

;------------------------------------------------------------------------

__getgdtlimit PROC

	LOCAL	GDTR[10]:BYTE

	SGDT	GDTR
	MOV		AX, WORD PTR GDTR[0]

	RET

__getgdtlimit ENDP

;------------------------------------------------------------------------

__getidtlimit PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		AX, WORD PTR IDTR[0]

	RET

__getidtlimit ENDP

;------------------------------------------------------------------------

__readrflags PROC

	PUSHFQ
	POP		RAX
	RET

__readrflags ENDP

;------------------------------------------------------------------------

MSRRead PROC

	RDMSR				; MSR[ECX] --> EDX:EAX
	SHL		RDX, 32
	OR		RAX, RDX

	RET

MSRRead ENDP

;------------------------------------------------------------------------

MSRWrite PROC

	MOV		RAX, RDX
	SHR		RDX, 32
	WRMSR
	RET

MSRWrite ENDP

END