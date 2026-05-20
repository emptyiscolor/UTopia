# Guide: Adding More Targets to UTopia

This document captures lessons learned from integrating multiple projects with UTopia's fuzzer generation pipeline. Use it to evaluate and integrate new targets.

## Prerequisites for a Compatible Target

A project must satisfy ALL of these requirements:

| Requirement | Why |
|-------------|-----|
| **GoogleTest (gtest)** unit tests | UTopia's `ut_analyzer` only recognizes `TEST()`, `TEST_F()`, `TEST_P()` macros. Boost.Test and Tizen TCT also supported. |
| **CMake build system** | The pipeline replays compile commands from `build.log`. Only `make`-based builds with `V=1` produce the needed verbose output. Ninja/Bazel won't work directly. |
| **Static library (.a) output** | UTopia instruments the `.a` for fuzzer/profile variants. The project must produce at least one meaningful `.a`. |
| **C++17 or lower** | The build environment uses clang 12, which supports up to C++17. Projects requiring C++20 (e.g. `google/filament`) are incompatible. |
| **No `-Werror` / `-pedantic-errors` on test code** | UTopia's `autofuzz.h` redefines keywords via macros. Strict warning flags (e.g. `-Wkeyword-macro` as error) will reject the instrumented code. |
| **Fuzzable parameter types** | The target API must accept primitive types, strings, or byte buffers. Complex types like `StatusOr<unique_ptr<T>>`, protobuf objects, or opaque handles produce `UnidentifiedParam` failures. |

## Quick Evaluation Checklist

Before investing time in configuration, verify:

```bash
# 1. Check test framework
grep -r "TEST\b\|TEST_F\|TEST_P" <project>/test* <project>/src/*test* | head -5

# 2. Check for gtest include
grep -r "gtest/gtest.h" <project>/ | head -5

# 3. Check build system
ls <project>/CMakeLists.txt  # must exist

# 4. Check C++ standard
grep -i "CXX_STANDARD\|std=c++20\|std=c++2a" <project>/CMakeLists.txt

# 5. Check for strict warning flags
grep -i "pedantic-errors\|Werror" <project>/CMakeLists.txt

# 6. Check library targets
grep "add_library.*STATIC" <project>/CMakeLists.txt <project>/src/CMakeLists.txt
```

## Known Failure Modes

### 1. Custom test framework (not gtest)

**Symptom:** `UTCount_Total: 0` — no test cases found.

**Example:** `google/flatbuffers` uses custom `TEST_EQ`/`TEST_ASSERT` macros.

**Fix:** None. Must use gtest/boost/tct. Pick a different project.

### 2. Strict compiler flags reject autofuzz.h

**Symptom:** `-Werror,-Wkeyword-macro` error during fuzzer compilation.

**Example:** `google/benchmark` uses `-pedantic-errors`.

**Fix:** Patch CMakeLists.txt to remove `-pedantic-errors` from test targets, or add `-Wno-keyword-macro` to the compile flags. Add the patch in `make.yml` repo setup:
```yaml
- sed -i 's/-pedantic-errors//g' myproject/test/CMakeLists.txt
```

### 3. Unquoted path macros in -D flags

**Symptom:** `error: use of undeclared identifier 'build'` when a `-DPATH="/some/path"` loses quotes during AST replay.

**Example:** `protobuf` defines `-DGOOGLE_PROTOBUF_FAKE_PLUGIN_PATH="/path/to/plugin"`.

**Fix:** Patch out or rename the macro in the source file that uses it:
```yaml
- sed -i 's/SOME_PATH_MACRO/SOME_PATH_MACRO_DISABLED/g' myproject/src/problematic_file.cc
```

### 4. Protobuf version conflict

**Symptom:** `FuzzArgsProfile.pb.cc` fails to compile with `unknown type name 'PROTOBUF_NAMESPACE_OPEN'`.

**Example:** Any project that bundles a different protobuf version than the system one (used by UTopia's fuzz_generator).

**Fix:** Either use system protobuf for all builds (`-DPREFER_SYSTEM_PROTOBUF=ON`) or don't fuzz projects whose bundled protobuf is incompatible with the system `protoc`. Protobuf-itself as a target is inherently incompatible.

### 5. Micro-library architecture (too many tiny .a files)

**Symptom:** `APICount_Total: 1` per library. Zero fuzzable APIs.

**Example:** `tink-crypto/tink-cc` produces 400+ single-function `.a` files.

**Fix:** You can combine libraries with `llvm-ar`, but the real issue is often that the combined API uses complex types (see #6).

### 6. Complex/opaque parameter types

**Symptom:** `UTCount_UnidentifiedParam: N` — all tests flagged as unfuzzable.

**Example:** `tink-cc` APIs take `StatusOr<unique_ptr<KeysetHandle>>`, protobuf key objects.

## More Targets 

These projects have been successfully fuzzed with UTopia:

| Project | Library | Tests | Fuzzers Generated |
|---------|---------|-------|-------------------|
| libphonenumber | libphonenumber_testing.a | libphonenumber_test | 95 |
| bloaty | libbloaty.a | bloaty_test, range_map_test | yes |
| wabt | libwabt.a | wabt_unittests | 86 |
| tesseract | libtesseract.a | multiple test suites | 246 |
| shaderc | libshaderc_util.a | shaderc_util_*_test | 78 |
| cppcheck | libcppcheck-core.a | gtest_cppcheck | yes |

## Step-by-Step Integration

### 1. Trial build (outside UTopia)

```bash
cd /src/UTopia/exp
git clone <url> myproject && cd myproject
git checkout <tag> -b autofuzz_base
mkdir build && cd build
cmake -DBUILD_TESTING=ON -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ ..
make -j8
```

Verify:
- `find . -name "*.a" -not -path "*/_deps/*"` — find the library
- `find . -type f -executable -name "*test*"` — find test executables
- Test runs: `./mytest` — confirm it uses gtest (prints `[==========]` output)

### 2. Configure make.yml

Key points:
- `org` build: must set `COMPILE_LOG` env var, use `V=1`, enable tests
- `fuzzer`/`profile` builds: can disable tests, use separate build dirs
- Use `k#:cmake_org_flags:#` etc. for standard flag injection
- Patch source in repo setup if needed (sed + git commit)

### 3. Configure build.yml

Key points:
- `builddir` is relative to project root, prepended to lib/ut `builddir`
- `buildkey` defaults to the ut/lib dict key; override if needed for uniqueness
- `srcpath` must point to directory containing test `.cc` files
- `libalias` maps tests to libraries (space-separated if multiple)

### 4. Run pipeline

```bash
python3 -m helper.make myproject      # clone + build 3 variants
python3 -m helper.build myproject     # analyze + generate + compile fuzzers
```

### 5. Troubleshoot

If `helper.build` fails:
1. Check `exp/myproject/output/build.log` — does it contain both compile AND link commands for the test?
2. Check `result/test/myproject/` — did API extraction (`api.json`) work?
3. Check fuzzGen_Report.json — what are the `*Count` stats?
4. If fuzzer compilation fails, use the error-tolerant script pattern (see shaderc example in CLAUDE.md)

### 6. Run fuzzers

```bash
cp exp/libphonenumber/run_fuzzers.py exp/myproject/
cd exp/myproject
python3 run_fuzzers.py output/fuzzers -j 4 -t 60 --print-coverage
```

