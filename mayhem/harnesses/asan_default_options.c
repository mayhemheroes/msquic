/*
 * asan_default_options.c — baked-in, weak ASan/LSan runtime defaults for the msquic harnesses.
 *
 * The `spinquic` harness drives REAL QUIC client+server connections (background worker threads,
 * a 10-second spin) and tears them down when libFuzzer's per-input deadline fires. At that moment
 * in-flight connection/worker allocations are still reachable-but-unfreed, so LeakSanitizer reports
 * a "memory leak" on essentially every input — teardown-race noise, not a real defect — which would
 * abort every run and flood the campaign with false crashes.
 *
 * We disable ONLY leak detection (detect_leaks=0); ASan's use-after-free / heap-overflow / OOB
 * checks and UBSan stay fully armed. This is compiled INTO the binary. Mayhem owns the runtime
 * ASAN_OPTIONS (abort_on_error=1, symbolize=0, ...) and a Mayhemfile env value would REPLACE that
 * whole set — so this must live in the binary, never in the Mayhemfile.
 *
 * These are deliberately STRONG (not weak): the ASan/LSan runtimes ship their OWN weak
 * __asan_default_options/__lsan_default_options that return "", and with two weak defs the linker may
 * keep the runtime's. A strong def here wins unconditionally. An explicit ASAN_OPTIONS/LSAN_OPTIONS
 * env var at run time still overrides the value returned here, so this only sets the DEFAULT.
 */
const char* __asan_default_options(void) {
    return "detect_leaks=0";
}

const char* __lsan_default_options(void) {
    return "detect_leaks=0";
}
