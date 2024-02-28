
; custom intrinsic functions

PUBLIC __readcs
PUBLIC __readds
PUBLIC __reades
PUBLIC __readss
PUBLIC __readfs
PUBLIC __readgs
PUBLIC __readldtr
PUBLIC __readtr
PUBLIC __readrflags
PUBLIC __readmsr
PUBLIC __writemsr
PUBLIC __lgdt
PUBLIC __lar
PUBLIC __sgdt
PUBLIC __sldt

PUBLIC __writecr0 
PUBLIC __writecr4

PUBLIC __vmx_vmcall

; standard vmm handler functions

PUBLIC SaveStateAndVirtualizeCore
PUBLIC VmexitHandler
PUBLIC VmxRestoreState

; extern functions

EXTERN VmExitDispatcher:PROC
EXTERN VirtualizeCore:PROC

EXTERN VmmReadGuestRip:PROC
EXTERN VmmReadGuestRsp:PROC
EXTERN VmmGetCoresVcpu:PROC

VMX_VCPU_STATE_OFF        EQU 0
VMX_VCPU_STATE_RUNNING    EQU 1
VMX_VCPU_STATE_TERMINATED EQU 2

.code _text

; save general purpose registers to the stack, matching our GUEST_CONTEXT structure

SAVE_GP macro

	push r15
	push r14
	push r13
	push r12
	push r11
	push r10
	push r9
	push r8        
	push rdi
	push rsi
	push rbp
	push rbp
	push rbx
	push rdx
	push rcx
	push rax

endm

RESTORE_GP macro

	pop rax
	pop rcx
	pop rdx
	pop rbx
	pop rbp
	pop rbp
	pop rsi
	pop rdi 
	pop r8
	pop r9
	pop r10
	pop r11
	pop r12
	pop r13
	pop r14
	pop r15

endm

	; save floating point registers
	; vmovups allows us to store them in an unaligned address
	; which is not ideal and should be fixed.

	; todo: Instead we should align the stack and use the movaps instruction

SAVE_FP macro

	sub     rsp, 256

	vmovups  xmmword ptr [rsp +  0h], xmm0
	vmovups  xmmword ptr [rsp + 10h], xmm1
	vmovups  xmmword ptr [rsp + 20h], xmm2
	vmovups  xmmword ptr [rsp + 30h], xmm3
	vmovups  xmmword ptr [rsp + 40h], xmm4
	vmovups  xmmword ptr [rsp + 50h], xmm5
	vmovups  xmmword ptr [rsp + 60h], xmm6
	vmovups  xmmword ptr [rsp + 70h], xmm7
	vmovups  xmmword ptr [rsp + 80h], xmm8
	vmovups  xmmword ptr [rsp + 90h], xmm9
	vmovups  xmmword ptr [rsp + 160], xmm10
	vmovups  xmmword ptr [rsp + 176], xmm11
	vmovups  xmmword ptr [rsp + 192], xmm12
	vmovups  xmmword ptr [rsp + 208], xmm13
	vmovups  xmmword ptr [rsp + 224], xmm14
	vmovups  xmmword ptr [rsp + 240], xmm15

endm

RESTORE_FP macro

        vmovups  xmm0, xmmword ptr [rsp +  0h]
        vmovups  xmm1, xmmword ptr [rsp + 10h]
        vmovups  xmm2, xmmword ptr [rsp + 20h]
        vmovups  xmm3, xmmword ptr [rsp + 30h]
        vmovups  xmm4, xmmword ptr [rsp + 40h]
        vmovups  xmm5, xmmword ptr [rsp + 50h]
	vmovups  xmm6, xmmword ptr [rsp + 60h]
	vmovups  xmm7, xmmword ptr [rsp + 70h]
	vmovups  xmm8, xmmword ptr [rsp + 80h]
	vmovups  xmm9, xmmword ptr [rsp + 90h]
	vmovups  xmm10, xmmword ptr [rsp + 160]
	vmovups  xmm11, xmmword ptr [rsp + 176]
	vmovups  xmm12, xmmword ptr [rsp + 192]
	vmovups  xmm13, xmmword ptr [rsp + 208]
	vmovups  xmm14, xmmword ptr [rsp + 224]
	vmovups  xmm15, xmmword ptr [rsp + 240]
	
        add     rsp, 256

endm

VmexitHandler PROC

	push 0				; ensure the stack is aligned

	pushfq				; push eflags

	SAVE_GP				; save general purpose registers	

	SAVE_FP

	; first argument for our exit handler is the guest register state, 
	; so store the base of the stack in rcx

	mov rcx, rsp

	sub rsp, 20h			; allocate some space for the shadow stack

	CALL VmExitDispatcher		; call our vm exit dispatcher	

	add rsp, 20h			; increment stack pointer to free our shadow stack space

	cmp al, 1			; check if the return value from our exit dispatcher is 1 (true)
	
	je ExitVmx			; jump to ExitVmx routine if we returned true

	RESTORE_FP			; restore fp registers
	
	RESTORE_GP			; restore gp registers

	popfq				; restore eflags 

	vmresume			; resume vmx execution
	
VmexitHandler ENDP

ExitVmx PROC

	push rax	

	sub rsp, 020h

	call VmmGetCoresVcpu
	
	add rsp, 020h

	mov [rax], dword ptr VMX_VCPU_STATE_TERMINATED

	pop rax

	sub rsp, 020h 

	call VmmReadGuestRsp		; get our guests rsp before we called vmxoff

	add rsp, 020h

	mov [rsp+188h], rax		; store the rsp at "top" of our stack

	sub rsp, 020h

	call VmmReadGuestRip		; get out guests rip before we called vmxoff

	add rsp, 020h

	mov rdx, rsp			; save our current rsp

	mov rbx, [rsp+188h]		; read the guests that we stored on the current stack

	mov rsp, rbx			; change our stack to the guests stack

	push rax			; push the guests rip to our new stack

	mov rsp, rdx			; restore our previous exit handlers stack
                        
	sub rbx,08h			; allocate some space on the guests stack

	mov [rsp+188h], rbx		; store the guests stack on the exit handlers stack

	RESTORE_FP			; restore the floating point registers

	RESTORE_GP			; restore the general purpose registers

	popfq				; restore eflags register

	pop rsp				; pop the guests stack back into rsp (we stored this as the top of our exit handlers stack)

	ret				; pop the instruction pointer from the top of the stack (the guests previous rip)

ExitVmx ENDP

; Save the future guests state before we initialise vmx operation

; This functions runs at IRQL = IPI_LEVEL

SaveStateAndVirtualizeCore PROC PUBLIC

	SAVE_GP

	sub rsp, 28h

	mov rdx, rsp

	call VirtualizeCore	

	ret

SaveStateAndVirtualizeCore ENDP 

; will be used to restore the state of the guest to before we called SaveStateAndVirtualizeCore

; Since we are virtualizing an already running operating system, once vmx operation is initiated

; we will set the guest rip to this function which will restore the guest to the state before 

; we called SaveStateAndVirtualizeCore

VmxRestoreState PROC

	add rsp, 28h

	; We can overwrite rax since we are gonna restore it anyway
	
	call VmmGetCoresVcpu

	mov [rax], dword ptr VMX_VCPU_STATE_RUNNING

	RESTORE_GP
	
	ret
	
VmxRestoreState ENDP

__readcs PROC

	mov rax, cs

	ret

__readcs ENDP

__readds PROC

	mov rax, ds

	ret

__readds ENDP

__reades PROC

	mov rax, es

	ret

__reades ENDP

__readss PROC

	mov rax, ss

	ret

__readss ENDP

__readfs PROC

	mov rax, fs

	ret

__readfs ENDP

__readgs PROC

	mov rax, gs

	ret

__readgs ENDP

__readldtr PROC

	sldt rax

	ret

__readldtr ENDP

__readtr PROC

	str rax

	ret

__readtr ENDP

__readrflags PROC

	pushfq

	pop rax

	ret

__readrflags ENDP

__readmsr PROC

	rdmsr

	shl rdx, 32

	or rax, rdx

	ret

__readmsr ENDP

__writemsr PROC

	mov rax, rdx

	shr rdx, 32

	wrmsr

	ret

__writemsr ENDP

__writecr0 PROC

	mov cr0, rcx

	ret

__writecr0 ENDP

__writecr4 PROC

	mov cr4, rcx

	ret

__writecr4 ENDP

__lgdt PROC

	lgdt fword ptr [rcx]
	
	ret

__lgdt ENDP


__vmx_vmcall PROC
    
	pushfq

	vmcall       

	popfq

	ret

__vmx_vmcall ENDP

__lar PROC

	lar rax, rcx

	ret

__lar ENDP

__sgdt PROC
	
	sgdt [rcx]

	ret

__sgdt ENDP

__sldt PROC

	sldt ax

	ret

__sldt ENDP


END