#!/usr/bin/env bash
#
# msquic/mayhem/build.sh — build microsoft/msquic's two OSS-Fuzz libFuzzer harnesses as sanitized
# targets (+ standalone reproducers).
#
# Fuzzed surface (both harnesses drive the *real* QUIC stack, not a toy parser — the input bytes are
# fed into msquic running on the quictls/OpenSSL backend):
#   fuzz      — src/fuzzing/fuzz.cc: instantiates MsQuicApi() and sweeps the input bytes through every
#               global SetParam() (QUIC_PARAM_GLOBAL_*). Exercises the API param-decode / option path.
#   spinquic  — src/tools/spin/spinquic.cpp (built -DFUZZING): the QUIC connection "spinner". The
#               libFuzzer entry consumes the input as a script of QUIC operations and drives real
#               client/server connections + the packet/frame state machine.
#
# Both link the MONOLITHIC static libmsquic.a that msquic's CMake flattens (core + platform + the
# bundled quictls/OpenSSL), exactly like the OSS-Fuzz build. We reproduce
#   scripts/build.ps1 -Static -DisableTest -DisablePerf -DisableLogs
# with a direct CMake invocation (the base image has cmake+ninja+perl but NOT pwsh), and inject
# $SANITIZER_FLAGS into CMAKE_{C,CXX}_FLAGS so the whole stack — including OpenSSL — is instrumented.
#
# Build contract comes from the org base ENV: CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN. $OUT defaults to /mayhem.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS: force DWARF-3 so Mayhem triage can read symbols (clang-19 defaults to DWARF-5).
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${OUT:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS OUT

cd "$SRC"

# msquic's CMake reads the git hash to embed in the binary. The CI checkout is owned by uid 2000 but
# the build may run under a different effective uid — mark it safe so git doesn't bail ("dubious
# ownership"). Harmless if it already matches.
git config --global --add safe.directory "$SRC" 2>/dev/null || true

# clang-19 is far newer than what msquic/quictls were validated against — keep the upstream OSS-Fuzz
# clang workaround and relax a couple of benign-but-fatal -Werror diagnostics that fire only on this
# toolchain (these are warnings-as-errors in third-party / generated code, NOT real defects; the
# sanitizers stay fully armed). This is the single sanctioned build.sh relaxation.
SANFLAGS_BUILD="$SANITIZER_FLAGS $DEBUG_FLAGS \
  -Wno-error=invalid-unevaluated-string \
  -Wno-error=unused-but-set-variable \
  -Wno-error=deprecated-declarations \
  -Wno-error=unused-command-line-argument"

# Coverage instrumentation for the whole stack (so Mayhem/libFuzzer sees edges in msquic + openssl),
# without pulling the libFuzzer runtime into the static lib (that comes in only at the final link).
SANFLAGS_BUILD="$SANFLAGS_BUILD -fsanitize=fuzzer-no-link"

BUILD="$SRC/build/linux/x64_quictls"   # path mirrors what build.ps1 uses; harness include paths match
mkdir -p "$BUILD"

echo "=== configuring msquic (static, quictls, tools on, test/perf off) ==="
cmake -S "$SRC" -B "$BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$SANFLAGS_BUILD" \
  -DCMAKE_CXX_FLAGS="$SANFLAGS_BUILD" \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO="-O2 -DNDEBUG" \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O2 -DNDEBUG" \
  -DQUIC_TLS_LIB=quictls \
  -DQUIC_BUILD_SHARED=off \
  -DQUIC_BUILD_TOOLS=on \
  -DQUIC_BUILD_TEST=off \
  -DQUIC_BUILD_PERF=off \
  -DQUIC_ENABLE_LOGGING=off \
  -DQUIC_OUTPUT_DIR="$BUILD/bin"

echo "=== building libmsquic.a (monolithic) + spinquic tool ==="
# msquic_lib = the flattened monolithic static archive; spinquic = the tool we relink as a fuzzer.
cmake --build "$BUILD" --target msquic_lib spinquic -j"$MAYHEM_JOBS"

# Use the FLATTENED monolithic archive (QUIC_OUTPUT_DIR/bin/libmsquic.a) — it bundles core +
# platform + the public msquic API + quictls. The intermediate obj/Release/libmsquic.a is NOT
# flattened (it omits MsQuicOpenVersion/MsQuicClose), so prefer bin/ and reject the intermediate.
LIBMSQUIC="$BUILD/bin/libmsquic.a"
[ -f "$LIBMSQUIC" ] || LIBMSQUIC="$(find "$BUILD" -path '*/bin/libmsquic.a' | head -1)"
[ -f "$LIBMSQUIC" ] || { echo "FATAL: flattened libmsquic.a not produced" >&2; exit 1; }
echo "libmsquic.a (monolithic): $LIBMSQUIC"

# Include paths the harnesses need (mirror the OSS-Fuzz build.sh).
INCS="-I$SRC/src/test -I$SRC/src/inc -I$SRC/src/generated/common -I$SRC/src/generated/linux \
  -I$BUILD/_deps/opensslquic-build/quictls/include \
  -isystem $SRC/submodules/googletest/googletest/include \
  -isystem $SRC/submodules/googletest/googletest"

# System libs the flattened archive needs at final link (pthread/dl/m/rt/numa-free posix backend).
SYSLIBS="-lpthread -ldl -lm -lrt -lstdc++ -lnuma"
# libnuma may be absent; drop it if not installed.
echo 'int main(){return 0;}' | $CXX -x c++ - -lnuma -o /tmp/.numatest 2>/dev/null && rm -f /tmp/.numatest || SYSLIBS="-lpthread -ldl -lm -lrt -lstdc++"

# The harnesses export LLVMFuzzerTestOneInput with C linkage (extern "C"). The standalone driver
# (StandaloneFuzzTargetMain.c) references it with C linkage too — but only if compiled AS C. Compile
# it once with $CC -x c so the reference stays unmangled and resolves the harness's C symbol.
STANDALONE_OBJ="$BUILD/standalone_main.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" -o "$STANDALONE_OBJ"

# Weak __asan_default_options (detect_leaks=0) baked into every target: spinquic spins real
# connections whose worker threads still hold reachable allocations at the per-input deadline, so
# LSan flags a teardown-race "leak" on nearly every input. Disable ONLY leak detection; ASan/UBSan
# error checks stay armed. (Lives in the binary, NOT the Mayhemfile — Mayhem owns runtime ASAN_OPTIONS.)
ASAN_OPTS_OBJ="$BUILD/asan_default_options.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/harnesses/asan_default_options.c" -o "$ASAN_OPTS_OBJ"

build_one() {  # build_one <out-name> <source.cc> <extra-defs>
  local name="$1" src="$2" defs="$3"
  echo "=== building harness: $name ==="
  $CXX $SANFLAGS_BUILD -DCX_PLATFORM_LINUX -DQUIC_TEST_APIS $defs $INCS \
      -c "$src" -o "$BUILD/$name.o"

  # libFuzzer target -> $OUT/<name>
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$BUILD/$name.o" "$ASAN_OPTS_OBJ" "$LIBMSQUIC" $SYSLIBS \
      -o "$OUT/$name"

  # standalone reproducer (run-once, no libFuzzer runtime) -> $OUT/<name>-standalone
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_OBJ" "$BUILD/$name.o" "$ASAN_OPTS_OBJ" "$LIBMSQUIC" $SYSLIBS \
      -o "$OUT/$name-standalone"

  echo "built $name (+ standalone)"
}

build_one fuzz     "$SRC/src/fuzzing/fuzz.cc"            ""
build_one spinquic "$SRC/src/tools/spin/spinquic.cpp"    "-DFUZZING -DQUIC_BUILD_STATIC"

echo "build.sh complete:"
ls -la "$OUT/fuzz" "$OUT/spinquic" "$OUT/fuzz-standalone" "$OUT/spinquic-standalone" 2>&1 || true
