#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/namei.h>
#include <linux/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DFRoot LKM");

/* The exploit passes the app's data dir through insmod, so nothing about where
 * the app lives is baked in. The module reads the app's prefs file from here. */
static char data_dir[128] = "";
module_param_string(data_dir, data_dir, sizeof(data_dir), 0);

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef void *(*umh_setup_t)(const char *path, char **argv, char **envp, gfp_t gfp,
                             void *init, void *cleanup, void *data);
typedef int (*umh_exec_t)(void *info, int wait);
typedef int  (*kern_path_t)(const char *, unsigned int, struct path *);
typedef int  (*invalidate_t)(struct address_space *);
typedef void (*path_put_t)(const struct path *);

static struct kprobe defex_enforce_kp;
static struct kprobe defex_umh_kp;
static int defex_enforce_ok;
static int defex_umh_ok;

static int null_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    (void)p;
    regs->regs[0] = 0;         /* x0 = DEFEX_ALLOW */
    regs->pc = regs->regs[30]; /* skip body: return to caller */
    return 1;
}

static int __nocfi __init dfroot_init(void)
{
    kallsyms_lookup_name_t get_addr;
    kern_path_t  kern_path_fn;
    invalidate_t invalidate_fn;
    path_put_t   path_put_fn;
    struct path  p;
    umh_setup_t umh_setup;
    umh_exec_t  umh_exec;
    bool *selinux_state;
    struct kprobe kln_kp;
    void *info;
    int ret;

    /* Run the installed manager's own libksud.so. The app no longer stages a
     * copy, so the package name and the two switches are read straight from the
     * app's prefs file, whose directory the exploit passes in through insmod. */
    static const char sh[] = "/system/bin/sh";
    static char *envp[] = { "PATH=/system/bin", NULL };
    static char cmd[1024];
    static char *argv[] = { (char *)sh, "-c", cmd, NULL };

    snprintf(cmd, sizeof(cmd),
        "rmmod oplus_secure_harden 2>/dev/null;"         //
        " rmmod oplus_security_keventupload 2>/dev/null;" // Oppo/OnePlus
        " rmmod oplus_security_guard 2>/dev/null;"
        " PREFS=%s/shared_prefs/dfroot.xml;"
        " PKG=$(sed -n 's/.*name=\"su_manager\">\\([^<]*\\)<.*/\\1/p' $PREFS | head -1);"
        " KSUD=$(find /data/app -path \"*/$PKG*/lib/arm64/libksud.so\" 2>/dev/null | head -1);"
        " [ -n \"$KSUD\" ] || KSUD=/data/adb/ksu/bin/ksud;"
        " if grep -q 'name=\"disable_modules\" value=\"true\"' $PREFS; then"
        "   for d in /data/adb/modules/*/; do [ -d \"$d\" ] && touch \"$d/disable\"; done;"
        " fi;"
        " if \"$KSUD\" late-load --package-name \"$PKG\"; then"
        "   touch /dev/dfm0;"
        "   grep -q 'name=\"soft_reboot\" value=\"true\"' $PREFS && \"$KSUD\" soft-reboot;"
        " else"
        "   touch /dev/dfm1;"
        " fi",
        data_dir);

    // Symbol finder
    kln_kp = (struct kprobe){ .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kln_kp) < 0) {
        pr_err("dfroot: kallsyms_lookup_name not found\n");
        return -EINVAL;
    }
    get_addr = (kallsyms_lookup_name_t)kln_kp.addr;
    unregister_kprobe(&kln_kp);

    // Invalidate page_cache for crash_dump64
    // NOTE: this can cause issues if a process is currently executing
    //   crash_dump64. We may want to revert to manual restore patching
    kern_path_fn  = (kern_path_t) get_addr("kern_path");
    invalidate_fn = (invalidate_t)get_addr("invalidate_inode_pages2");
    path_put_fn   = (path_put_t)  get_addr("path_put");
    if (!kern_path_fn || !invalidate_fn || !path_put_fn) {
        pr_err("dfroot: cache drop symbols missing\n");
    } else if (kern_path_fn("/apex/com.android.runtime/bin/crash_dump64",
                            LOOKUP_FOLLOW, &p)) {
        pr_err("dfroot: kern_path failed for crash_dump64\n");
    } else {
        invalidate_fn(p.dentry->d_inode->i_mapping);
        path_put_fn(&p);
        pr_info("dfroot: cleared page cache for crash_dump64\n");
    }

    // Disable SELinux
    selinux_state = (bool *)get_addr("selinux_state");
    if (!selinux_state) {
        pr_err("dfroot: selinux_state not found\n");
        return -EINVAL;
    }
    WRITE_ONCE(*selinux_state, false);
    pr_info("dfroot: selinux_state permissive\n");

    // Samsung
    defex_enforce_kp = (struct kprobe){ .addr = (kprobe_opcode_t *)get_addr("task_defex_enforce"),
                                .pre_handler = null_pre_handler };
    defex_enforce_ok = register_kprobe(&defex_enforce_kp) == 0;
    if (!defex_enforce_ok)
        pr_err("dfroot: task_defex_enforce not in this kernel, skipping\n");
    else
        pr_info("dfroot: task_defex_enforce hooked\n");
    
    defex_umh_kp = (struct kprobe){ .addr = (kprobe_opcode_t *)get_addr("task_defex_user_exec"),
                              .pre_handler = null_pre_handler };
    defex_umh_ok = register_kprobe(&defex_umh_kp) == 0;
    if (!defex_umh_ok)
        pr_err("dfroot: task_defex_user_exec not in this kernel, skipping\n");
    else
        pr_info("dfroot: task_defex_user_exec hooked\n");

    // Run UMH command
    umh_setup = (umh_setup_t)get_addr("call_usermodehelper_setup");
    umh_exec  = (umh_exec_t)get_addr("call_usermodehelper_exec");
    if (!umh_setup || !umh_exec) {
        pr_err("dfroot: usermodehelper symbols missing (setup=%px exec=%px)\n",
               umh_setup, umh_exec);
        goto out_unload;
    }

    info = umh_setup(sh, argv, envp, GFP_KERNEL, NULL, NULL, NULL);
    if (!info) {
        pr_err("dfroot: usermodehelper_setup: returned NULL\n");
        goto out_unload;
    }
    // bypass CONFIG_STATIC_USERMODEHELPER_PATH="" overriding path to ""
    ((struct subprocess_info *)info)->path = sh;

    ret = umh_exec(info, UMH_WAIT_PROC);
    pr_info("dfroot: usermodehelper_exec returned %d\n", ret);

out_unload:
    /* No bootstrap process rmmods us any more, so unload ourselves. init
     * returning an error makes the kernel drop the module once it returns;
     * the exit hook does not run on this path, so undo the kprobes here. */
    if (defex_enforce_ok) unregister_kprobe(&defex_enforce_kp);
    if (defex_umh_ok)     unregister_kprobe(&defex_umh_kp);
    return -E2BIG;
}

module_init(dfroot_init);
