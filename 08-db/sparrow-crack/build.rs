fn main() {
    // Compile phc-winner-argon2 from vendored source with AVX2 and pthreads.
    // opt.c selects the AVX2 compression path when HAVE_AVX2 is defined at compile time.
    cc::Build::new()
        .files([
            "vendor/argon2/src/argon2.c",
            "vendor/argon2/src/core.c",
            "vendor/argon2/src/encoding.c",
            "vendor/argon2/src/thread.c",
            "vendor/argon2/src/blake2/blake2b.c",
            "vendor/argon2/src/opt.c",
        ])
        .include("vendor/argon2/include")
        .include("vendor/argon2/src")
        .flag_if_supported("-O3")
        .flag_if_supported("-mavx2")   // sets __AVX2__; opt.c selects AVX2 path on this macro
        .flag_if_supported("-mfma")
        .flag_if_supported("-pthread") // needed for pthread.h in thread.c
        // Do NOT define ARGON2_NO_THREADS — argon2 uses #if !defined(ARGON2_NO_THREADS)
        // to enable pthread parallel lanes; defining it (even to 0) disables threading.
        .compile("argon2_avx2");

    // thread.c uses pthreads for parallel lane processing.
    println!("cargo:rustc-link-lib=pthread");

    // Invalidate if any vendored source changes.
    println!("cargo:rerun-if-changed=vendor/argon2/src");
    println!("cargo:rerun-if-changed=vendor/argon2/include");
}
