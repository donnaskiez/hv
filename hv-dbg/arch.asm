
; custom intrinsic functions

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
PUBLIC __readmsr
PUBLIC __writemsr
PUBLIC __lgdt

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

.code _text

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

SAVE_FP macro

	sub     rsp, 60h

	vmovups  xmmword ptr [rsp +  0h], xmm0
	vmovups  xmmword ptr [rsp + 10h], xmm1
	vmovups  xmmword ptr [rsp + 20h], xmm2
	vmovups  xmmword ptr [rsp + 30h], xmm3
	vmovups  xmmword ptr [rsp + 40h], xmm4
	vmovups  xmmword ptr [rsp + 50h], xmm5

endm

RESTORE_FP macro

        vmovups  xmm0, xmmword ptr [rsp +  0h]
        vmovups  xmm1, xmmword ptr [rsp + 10h]
        vmovups  xmm2, xmmword ptr [rsp + 20h]
        vmovups  xmm3, xmmword ptr [rsp + 30h]
        vmovups  xmm4, xmmword ptr [rsp + 40h]
        vmovups  xmm5, xmmword ptr [rsp + 50h]
	
        add     rsp, 60h

endm

VmexitHandler PROC

	push 0				; ensure the stack is aligned

	pushfq				; push eflags

	SAVE_GP				; save general purpose registers	
	
	; save floating point registers
	; vmovups allows us to store them in an unaligned address
	; which is not ideal and should be fixed.

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

	sub rsp, 020h 

	call VmmReadGuestRsp		; get our guests rsp before we called vmxoff

	add rsp, 020h

	mov [rsp+0e8h], rax		; store the rsp at "top" of our stack

	sub rsp, 020h

	call VmmReadGuestRip		; get out guests rip before we called vmxoff

	add rsp, 020h

	mov rdx, rsp			; save our current rsp

	mov rbx, [rsp+0e8h]		; read the guests that we stored on the current stack

	mov rsp, rbx			; change our stack to the guests stack

	push rax			; push the guests rip to our new stack

	mov rsp, rdx			; restore our previous exit handlers stack
                        
	sub rbx,08h			; allocate some space on the guests stack

	mov [rsp+0e8h], rbx		; store the guests stack on the exit handlers stack

	RESTORE_FP			; restore the floating point registers

	RESTORE_GP			; restore the general purpose registers

	popfq				; restore eflags register

	pop rsp				; pop the guests stack back into rsp (we stored this as the top of our exit handlers stack)

	ret				; pop the instruction pointer from the top of the stack (the guests previous rip)

ExitVmx ENDP

; No need to raise the irql as this routine run at IPI_LEVEL 

SaveStateAndVirtualizeCore PROC PUBLIC

	SAVE_GP

	sub rsp, 28h

	mov rdx, rsp

	call VirtualizeCore	

	ret

SaveStateAndVirtualizeCore ENDP 

; will be used to restore the state of the guest to before we called SaveStateAndVirtualizeCore

VmxRestoreState PROC

	add rsp, 28h

	RESTORE_GP
	
	ret
	
VmxRestoreState ENDP

__readgdtbase PROC

	local gdtr[10]:byte

	sgdt gdtr

	mov rax, qword ptr gdtr[2]

	ret

__readgdtbase ENDP

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

__readidtbase PROC

	local idtr[10]:byte
	
	sidt idtr

	mov rax, qword ptr idtr[2]

	ret

__readidtbase ENDP

__getgdtlimit PROC

	local gdtr[10]:byte

	sgdt gdtr

	mov ax, word ptr gdtr[0]

	ret

__getgdtlimit ENDP

__getidtlimit PROC

	local idtr[10]:byte
	
	sidt idtr

	mov ax, word ptr idtr[0]

	ret

__getidtlimit ENDP

__readrflags PROC

	pushfq

	pop		rax

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

END