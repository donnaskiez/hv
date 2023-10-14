; https://revers.engineering/day-4-vmcs-segmentation-ops/

__read_ldtr proc
        sldt    ax
        ret
__read_ldtr endp

__read_tr proc
        str     ax
        ret
__read_tr endp

__read_cs proc
        mov     ax, cs
        ret
__read_cs endp

__read_ss proc
        mov     ax, ss
        ret
__read_ss endp

__read_ds proc
        mov     ax, ds
        ret
__read_ds endp

__read_es proc
        mov     ax, es
        ret
__read_es endp

__read_fs proc
        mov     ax, fs
        ret
__read_fs endp

__read_gs proc
        mov     ax, gs
        ret
__read_gs endp