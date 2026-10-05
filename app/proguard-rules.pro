# Keep the JNI entry point the native exploit registers.
-keepclasseswithmembernames class df.root.ExploitRunner {
    native <methods>;
}

# The reporter is called back from native code.
-keep interface df.root.IReporter { *; }
-keep class df.root.ExploitRunner { *; }
