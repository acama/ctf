.globl _start
_start:
    bl main
hang:
    b hang

.globl DO_SWI
DO_SWI:
    push {r4-r12, lr}
    svc 0
    pop {r4-r12, pc}
