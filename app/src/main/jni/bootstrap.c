#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define BLKROSET   0x125d
#define KSUD       "/data/user_de/0/df.root/ksud"
#define KSUD_ADB   "/data/adb/ksud"   // ksu domain can only exec the ksu_file type
#define PREFS_PATH "/data/user_de/0/df.root/shared_prefs/dfroot.xml"
#define MODULES_DIR "/data/adb/modules"

static int pref_true(const char *buf, const char *key)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "name=\"%s\"", key);
    char *p = strstr(buf, needle);
    if (!p) return 0;
    char *tag_end = strchr(p, '>');
    char *v = strstr(p, "value=\"true\"");
    return v && tag_end && v < tag_end;
}

static int read_prefs(char *su_manager, size_t su_manager_size, int *soft_reboot,
                      int *disable_modules)
{
    int fd = open(PREFS_PATH, O_RDONLY);
    if (fd < 0) return -1;

    char buf[4096];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';

    char *p = strstr(buf, "name=\"su_manager\">");
    if (!p) return -1;
    p += strlen("name=\"su_manager\">");
    char *end = strchr(p, '<');
    if (!end) return -1;
    size_t len = end - p;
    if (len == 0 || len >= su_manager_size) return -1;
    memcpy(su_manager, p, len);
    su_manager[len] = '\0';

    *soft_reboot = pref_true(buf, "soft_reboot");
    *disable_modules = pref_true(buf, "disable_modules");

    return 0;
}

static int adopt_zygote_env(void)
{
    FILE *f = popen("pidof zygote64 zygote", "r");
    if (!f) return -1;
    int pid = 0;
    fscanf(f, "%d", &pid);
    pclose(f);
    if (!pid) return -1;

    char path[32];
    snprintf(path, sizeof(path), "/proc/%d/environ", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    static char buf[16384];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    for (char *p = buf, *end = buf + n; p < end; p += strlen(p) + 1)
        putenv(p);
    return 0;
}

static int should_ro(const char *name)
{
    size_t len = strlen(name);
    if (!strcmp(name, "super"))  return 1;
    if (!strcmp(name, "misc"))   return 1;
    if (!strcmp(name, "steady")) return 1;
    if (len >= 2 && name[len - 2] == '_' &&
        (name[len - 1] == 'a' || name[len - 1] == 'b'))
        return 1;
    return 0;
}

static int set_partitions_ro(void)
{
    DIR *dir = opendir("/dev/block/by-name");
    if (!dir)
        return -1;

    struct dirent *ent;
    while ((ent = readdir(dir))) {
        if (!should_ro(ent->d_name))
            continue;

        char path[128];
        snprintf(path, sizeof(path), "/dev/block/by-name/%s", ent->d_name);

        int fd = open(path, O_RDONLY);
        if (fd < 0)
            continue;

        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISBLK(st.st_mode)) {
            int on = 1;
            ioctl(fd, BLKROSET, &on);
        }
        close(fd);
    }

    closedir(dir);
    return 0;
}

static int run(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execv(argv[0], argv);
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Fork+exec with a SELinux exec context, so the child starts in the ksu domain */
static int run_ctx(char *const argv[], const char *exec_ctx)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int fd = open("/proc/self/attr/exec", O_WRONLY | O_CLOEXEC);
        if (fd >= 0) {
            write(fd, exec_ctx, strlen(exec_ctx));
            close(fd);
        }
        execv(argv[0], argv);
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void touch(const char *path)
{
    int fd = open(path, O_CREAT | O_WRONLY, 0666);
    if (fd >= 0)
        close(fd);
}

/* Mark every installed module disabled before ksud runs. A broken module
 * otherwise loads on the next boot and bootloops the device. */
static int disable_modules(void)
{
    DIR *dir = opendir(MODULES_DIR);
    if (!dir)
        return -1;

    struct dirent *ent;
    while ((ent = readdir(dir))) {
        if (ent->d_name[0] == '.')
            continue;
        char path[256];
        snprintf(path, sizeof(path), MODULES_DIR "/%s/disable", ent->d_name);
        touch(path);
    }
    closedir(dir);
    return 0;
}

/* dfroot_init sets SELinux permissive, and the module only loads while it is */
static int wait_permissive(void)
{
    for (int i = 0; i < 100; i++) {
        int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
        if (fd >= 0) {
            char c = '1';
            int n = read(fd, &c, 1);
            close(fd);
            if (n == 1 && c == '0')
                return 0;
        }
        usleep(50000);
    }
    return -1;
}

/* ksud exits 0 even when it bails before rebooting, so check the property it
 * resets instead */
static int boot_completed_is_zero(void)
{
    FILE *f = popen("/system/bin/getprop sys.boot_completed", "r");
    if (!f)
        return 0;
    char buf[8] = { 0 };
    int n = fread(buf, 1, sizeof(buf) - 1, f);
    pclose(f);
    return n > 0 && buf[0] == '0';
}

static int reboot_started(void)
{
    for (int i = 0; i < 40; i++) {
        if (boot_completed_is_zero())
            return 1;
        usleep(50000);
    }
    return 0;
}

/* Restarting the framework mid-overlay leaves app_process unable to link
 * libnativeloader.so, so wait for the late-load daemon to exit */
static int late_load_alive(void)
{
    DIR *d = opendir("/proc");
    if (!d)
        return 0;
    struct dirent *ent;
    int alive = 0;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9')
            continue;
        char path[64];
        snprintf(path, sizeof(path), "/proc/%s/cmdline", ent->d_name);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            continue;
        char buf[256];
        int n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0)
            continue;
        buf[n] = '\0';
        /* require both, so an unrelated process mentioning "late-load" alone
         * does not hold the wait open for the full timeout */
        if (strstr(buf, "ksud") && strstr(buf, "late-load")) {
            alive = 1;
            break;
        }
    }
    closedir(d);
    return alive;
}

int main(void)
{
    touch("/dev/dfm0");
    touch("/dev/dfm1");
    char su_manager[256];
    int soft_reboot, disable_mods;

    if (wait_permissive())
        touch("/dev/dfmw2");

    if (read_prefs(su_manager, sizeof(su_manager), &soft_reboot, &disable_mods) != 0) {
        touch("/dev/dfme0");
        return 1;
    }

    touch("/dev/dfm2");
    if (adopt_zygote_env())
        touch("/dev/dfmw0");

    touch("/dev/dfm3");
    if (set_partitions_ro())
        touch("/dev/dfmw1");

    if (disable_mods) {
        touch("/dev/dfm4");
        if (disable_modules()) {
            touch("/dev/dfme1");
            return 1;
        }
    }

    touch("/dev/dfm5");
    char **late_load;
    late_load = (char *[]){ KSUD, "late-load", "--package-name", su_manager, NULL };
    if (run(late_load) != 0) {
        touch("/dev/dfme2");
        return 0;
    }
    touch("/dev/dfm6");

    if (soft_reboot) {
        const char *ksud = access(KSUD_ADB, X_OK) == 0 ? KSUD_ADB : KSUD;
        while (late_load_alive())
            usleep(100000);
        char *soft[] = { (char *)ksud, "soft-reboot", NULL };
        if (run_ctx(soft, "u:r:ksu:s0") != 0)
            touch("/dev/dfme3");
        else if (reboot_started())
            touch("/dev/dfm7");
        else
            touch("/dev/dfmw3");
    }

    /* Root is live whether or not the soft reboot ran, so this is the end. */
    touch("/dev/dfm8");
    return 0;
}
