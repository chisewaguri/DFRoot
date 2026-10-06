package df.root;

import android.content.Context;
import android.content.pm.PackageManager;
import rikka.shizuku.Shizuku;
import rikka.shizuku.ShizukuRemoteProcess;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.concurrent.TimeUnit;

/**
 * Runs the exploit binary as shell uid through Shizuku. Shell uid cannot read
 * /data/app, so the binary travels through the shizuku process stdin into
 * /data/local/tmp, where shell can exec it.
 */
public final class ShizukuRunner {
    private static final String Home = "/data/local/tmp";
    private static final String RemoteBinary = Home + "/.dfroot";
    private static final String ShizukuPackage = "moe.shizuku.privileged.api";
    private static final long StageTimeoutSeconds = 60;
    private static final long RunTimeoutSeconds = 300;

    public enum Status { NOT_INSTALLED, NOT_RUNNING, TOO_OLD, NO_PERMISSION, READY }

    public static Status status(Context context) {
        try {
            if (!Shizuku.pingBinder())
                return installed(context) ? Status.NOT_RUNNING : Status.NOT_INSTALLED;
            if (Shizuku.isPreV11())
                return Status.TOO_OLD;
            if (Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED)
                return Status.NO_PERMISSION;
            return Status.READY;
        } catch (Exception e) {
            return Status.NOT_RUNNING;
        }
    }

    /** Opens the shizuku grant dialog. Each run re-reads the grant, so the result is not tracked. */
    public static void requestPermission() {
        try {
            if (!Shizuku.pingBinder() || Shizuku.isPreV11()) return;
            if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) return;
            Shizuku.requestPermission(0);
        } catch (Exception ignored) {
        }
    }

    /**
     * Runs the binary as shell. The transform has to stay installed for the
     * whole run, so the caller keeps it open and passes the argument list; the
     * exploit is execed directly, replacing sh, so destroy() kills it.
     */
    public static int run(String[] args, OutputListener onLog) throws IOException {
        stage(new File(args[0]), RemoteBinary, onLog);
        String[] remoteArgs = args.clone();
        remoteArgs[0] = RemoteBinary;
        StringBuilder cmd = new StringBuilder("exec");
        for (String a : remoteArgs) {
            cmd.append(" '").append(a.replace("'", "'\\''")).append('\'');
        }
        cmd.append(" </dev/null 2>&1");
        onLog.log("[*] launching " + RemoteBinary);
        try {
            return drainAndWait(newProcess(new String[]{"sh", "-c", cmd.toString()}), onLog);
        } finally {
            try {
                sh("rm -f " + RemoteBinary);
            } catch (IOException ignored) {
            }
        }
    }

    public interface OutputListener {
        void log(String line);
    }

    /** Streams output while waiting; a leak child can hold stdout past death. */
    private static int drainAndWait(ShizukuRemoteProcess process, OutputListener onLog) throws IOException {
        java.io.InputStream input = process.getInputStream();
        Thread reader = new Thread(() -> {
            try (java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.InputStreamReader(input))) {
                String line;
                while ((line = r.readLine()) != null) onLog.log(line);
            } catch (IOException ignored) {
            }
        }, "dfroot-shizuku-reader");
        reader.setDaemon(true);
        reader.start();
        boolean exited = false;
        try {
            exited = process.waitForTimeout(RunTimeoutSeconds, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (!exited) {
            onLog.log("[!] shizuku run timed out; killing");
            process.destroy();
            try {
                process.waitForTimeout(5, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
            }
        }
        try {
            input.close();
        } catch (IOException ignored) {
        }
        try {
            reader.join(3000);
        } catch (InterruptedException ignored) {
        }
        try {
            return process.exitValue();
        } catch (IllegalStateException e) {
            return -1;
        }
    }

    /** Shell uid cannot read /data/app, so file bytes travel through stdin; wc -c catches truncation. */
    private static void stage(File src, String dest, OutputListener onLog) throws IOException {
        long want = src.length();
        if (remoteSize(dest) == want) {
            onLog.log("[*] binary already staged (" + want + " bytes)");
            return;
        }
        onLog.log("[*] staging binary (" + want + " bytes) -> " + dest);
        ShizukuRemoteProcess process = newProcess(
                new String[]{"sh", "-c", "rm -f " + dest + " && cat > " + dest + " && chmod 755 " + dest + " && wc -c < " + dest});
        try (java.io.InputStream in = new java.io.FileInputStream(src)) {
            java.io.OutputStream out = process.getOutputStream();
            byte[] buf = new byte[8192];
            for (int n; (n = in.read(buf)) != -1; ) out.write(buf, 0, n);
            out.close();
        }
        boolean exited = false;
        try {
            exited = process.waitForTimeout(StageTimeoutSeconds, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        Long written = null;
        if (exited) {
            try {
                String line = new java.io.BufferedReader(new java.io.InputStreamReader(process.getInputStream()))
                        .readLine();
                if (line != null) written = Long.valueOf(line.trim());
            } catch (IOException ignored) {
            }
        }
        if (!exited || written == null || written != want) {
            process.destroy();
            throw new IOException("staging " + dest + ": wrote " + written + " want " + want);
        }
        onLog.log("[+] staged ok");
    }

    private static long remoteSize(String dest) throws IOException {
        ShizukuRemoteProcess process = newProcess(
                new String[]{"sh", "-c", "wc -c < " + dest + " 2>/dev/null"});
        try {
            if (!process.waitForTimeout(StageTimeoutSeconds, TimeUnit.SECONDS)) {
                process.destroy();
                return -1;
            }
            String line = new java.io.BufferedReader(new java.io.InputStreamReader(process.getInputStream()))
                    .readLine();
            Long v = line == null ? null : Long.valueOf(line.trim());
            return v == null ? -1 : v;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return -1;
        }
    }

    private static void sh(String command) throws IOException {
        ShizukuRemoteProcess process = newProcess(new String[]{"sh", "-c", command});
        try {
            if (process.waitForTimeout(StageTimeoutSeconds, TimeUnit.SECONDS)) {
                try {
                    process.getInputStream().close();
                } catch (IOException ignored) {
                }
            } else {
                process.destroy();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static boolean installed(Context context) {
        try {
            context.getPackageManager().getApplicationInfo(ShizukuPackage, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    /** newProcess is private since api 13.1.1 but still present; proguard-rules.pro keeps R8 off it. */
    private static final Method newProcessMethod = lazyNewProcess();

    private static Method lazyNewProcess() {
        try {
            Method m = Shizuku.class.getDeclaredMethod(
                    "newProcess", String[].class, String[].class, String.class);
            m.setAccessible(true);
            return m;
        } catch (Exception e) {
            throw new IllegalStateException("shizuku newProcess unavailable", e);
        }
    }

    private static ShizukuRemoteProcess newProcess(String[] command) throws IOException {
        try {
            return (ShizukuRemoteProcess) newProcessMethod.invoke(null, command, null, Home);
        } catch (Exception e) {
            throw new IOException("shizuku newProcess failed", e);
        }
    }
}
