PUBLIC __vmx_enable
PUBLIC __vmx_invept
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
PUBLIC __readmsr
PUBLIC __writemsr

PUBLIC SaveStateAndVirtualizeCore
PUBLIC VmexitHandler
PUBLIC VmxRestoreState

EXTERN VmExitDispatcher:PROC
EXTERN VmResumeInstruction:PROC
EXTERN VirtualizeCore:PROC

EXTERN stack_pointer_to_return:QWORD
EXTERN base_pointer_to_return:QWORD

VMX_ERROR_CODE_SUCCESS              = 0
VMX_ERROR_CODE_FAILED_WITH_STATUS   = 1
VMX_ERROR_CODE_FAILED               = 2

.code _text

VmexitHandler PROC

	sub     rsp, 70h
	vmovups  xmmword ptr [rsp +  0h], xmm0
	vmovups  xmmword ptr [rsp + 10h], xmm1
	vmovups  xmmword ptr [rsp + 20h], xmm2
	vmovups  xmmword ptr [rsp + 30h], xmm3
	vmovups  xmmword ptr [rsp + 40h], xmm4
	vmovups  xmmword ptr [rsp + 50h], xmm5
	push R15
	push R14
	push R13
	push R12
	push R11
	push R10
	push R9
	push R8        
	push RDI
	push RSI
	push RBP
	push RBP	; RSP
	push RBX
	push RDX
	push RCX
	push RAX	
	MOV RCX, RSP		; GuestRegs
	SUB	RSP, 28h
	CALL	VmExitDispatcher
	ADD	RSP, 28h	
	pop RAX
	pop RCX
	pop RDX
	pop RBX
	pop RBP		; RSP
	pop RBP
	pop RSI
	pop RDI 
	pop R8
	pop R9
	pop R10
	pop R11
	pop R12
	pop R13
	pop R14
	pop R15
        vmovups  xmm0, xmmword ptr [rsp +  0h]
        vmovups  xmm1, xmmword ptr [rsp + 10h]
        vmovups  xmm2, xmmword ptr [rsp + 20h]
        vmovups  xmm3, xmmword ptr [rsp + 30h]
        vmovups  xmm4, xmmword ptr [rsp + 40h]
        vmovups  xmm5, xmmword ptr [rsp + 50h]
        add     rsp, 70h

	SUB RSP, 0100h ; to avoid error in future functions
	
    JMP VmResumeInstruction
	
VmexitHandler ENDP

; No need to raise the irql as this routine run at IPI_LEVEL 

SaveStateAndVirtualizeCore PROC PUBLIC

	push RAX
	push RCX
	push RDX
	push RBX
	push RBP
	push RSI
	push RDI
	push R8
	push R9
	push R10
	push R11
	push R12
	push R13
	push R14
	push R15
	SUB RSP, 28h
	MOV RDX, RSP
	CALL VirtualizeCore	
	RET

SaveStateAndVirtualizeCore ENDP 

; Restores the state of the registers pushed before we virtualized the core

VmxRestoreState PROC

	ADD RSP, 28h
	pop R15
	pop R14
	pop R13
	pop R12
	pop R11
	pop R10
	pop R9
	pop R8
	pop RDI
	pop RSI
	pop RBP
	pop RBX
	pop RDX
	pop RCX
	pop RAX
	
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

__vmx_invept PROC PUBLIC

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

__vmx_invept ENDP

__vmx_terminate PROC PUBLIC

	VMXOFF  ; turn it off before existing
	
	MOV RSP, stack_pointer_to_return
	MOV RBP, base_pointer_to_return
	
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

__readgdtbase PROC

	LOCAL	GDTR[10]:BYTE
	SGDT	GDTR
	MOV		RAX, QWORD PTR GDTR[2]

	RET

__readgdtbase ENDP

__readcs PROC

	MOV		RAX, CS
	RET

__readcs ENDP

__readds PROC

	MOV		RAX, DS
	RET

__readds ENDP

__reades PROC

	MOV		RAX, ES
	RET

__reades ENDP

__readss PROC

	MOV		RAX, SS
	RET

__readss ENDP

__readfs PROC

	MOV		RAX, FS
	RET

__readfs ENDP

__readgs PROC

	MOV		RAX, GS
	RET

__readgs ENDP

__readldtr PROC

	SLDT	RAX
	RET

__readldtr ENDP

__readtr PROC

	STR		RAX
	RET

__readtr ENDP

__readidtbase PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		RAX, QWORD PTR IDTR[2]
	RET

__readidtbase ENDP

__getgdtlimit PROC

	LOCAL	GDTR[10]:BYTE

	SGDT	GDTR
	MOV		AX, WORD PTR GDTR[0]

	RET

__getgdtlimit ENDP

__getidtlimit PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		AX, WORD PTR IDTR[0]

	RET

__getidtlimit ENDP

__readrflags PROC

	PUSHFQ
	POP		RAX
	RET

__readrflags ENDP

__readmsr PROC

	RDMSR				; MSR[ECX] --> EDX:EAX
	SHL		RDX, 32
	OR		RAX, RDX

	RET

__readmsr ENDP

__writemsr PROC

	MOV		RAX, RDX
	SHR		RDX, 32
	WRMSR
	RET

__writemsr ENDP

END