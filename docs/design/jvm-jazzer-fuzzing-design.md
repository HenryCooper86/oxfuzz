# JVM Jazzer Fuzzing Design

Status: **first slice implemented, acceptance open** (2026-11-21). Owners:
`hf-discovery` for the Java inventory, `hf-harness` for the generated class
and its build, `hf-engine` for the Jazzer argv, `hf-service` for admission
and workflow, and `hf-runtime` for every process. Feature flag: `jvm-jazzer`
(default on); the `jazzer` engine is outside the default enabled set.

## Goal and supported class

Fuzz a Java method through [Jazzer](https://github.com/CodeIntelligenceTesting/jazzer),
a coverage-guided JVM fuzzer built on libFuzzer. The first supported class is
deliberately narrow:

- a `public static` method of a top-level `public` class,
- taking one to eight parameters, each a `byte[]`, a `String` or a
  primitive (`boolean`, `byte`, `short`, `int`, `long`, `char`, `float`,
  `double`),
- in a project whose sources compile with `javac` against the JDK, the
  project's own `.java` files, and the jars it carries directly inside `lib/`
  or `libs/`. No build tool runs and nothing is resolved or downloaded.

Instance methods, constructors, generic methods, other parameter types,
Kotlin and Scala sources, annotation processors, and resolving a Maven or
Gradle class path are refused or out of scope; a Maven or Gradle project
copies its dependency jars into `lib/` first. Discovery's lexical name is not proof that
the project compiles.

## Evidence

Probes in `oxfuzz/fuzz-sandbox:0.2.3` (linux/arm64, OpenJDK 21, Jazzer
0.30.0), 2026-11-21:

- `javac` plus `jazzer --cp=<classes> --target_class=<class>` found a planted
  `ArrayIndexOutOfBoundsException` in under 25 seconds at 2 GiB memory, one
  CPU, no network, dropped capabilities, and a read-only project mount. The
  resident set was about 700 MiB.
- A finding prints `== Java Exception: <class>: <message>` followed by `at`
  frames and a `DEDUP_TOKEN`, writes `crash-<sha1>` under `-artifact_prefix`,
  and exits 77. Replaying the input exits 77 with the same report; a benign
  input exits 0.
- Jazzer also writes a Java reproducer source file to `--reproducer_path`
  (default: the working directory), so that path must be writable.
- A jar with a shell stub prepended still loads as a class path, so one file
  can be both the class path and the launcher.

## Toolchain

The image carries `openjdk-21-jdk-headless` from the distribution and the
Jazzer 0.30.0 release archive for the image architecture, verified against a
pinned SHA-256 at image build time. Nothing is downloaded at run time.

## Discovery

`hf-discovery` scans `.java` files lexically, like the Go and Python
scanners: it lists the `public static` methods with at least one parameter
that are declared directly in the top-level class a file is named after, as
`Class.method` candidates (`main` excluded, the first overload of a name
kept). Files under a `test` or `tests` directory, `module-info.java`, and
`package-info.java` are skipped. The harness template reads the `package`
clause from the target's file when it is drafted. The scanner is conservative: a
missed declaration is a lost candidate, never a wrong one.

## Harness

`hf_harness::jvm_jazzer` renders one fixed class from the selected method:

```java
// oxfuzz:java-target com.example.Frames#parse bytes
public final class OxfuzzFuzzTarget {
    private OxfuzzFuzzTarget() {}

    public static void fuzzerTestOneInput(byte[] data) {
        com.example.Frames.parse(data);
    }
}
```

A `String` parameter receives the input decoded as UTF-8. A method with any
other parameter list takes `com.code_intelligence.jazzer.api.FuzzedDataProvider`
instead and decodes one local per parameter in declaration order
(`data.consumeInt()`, `data.consumeBoolean()`, a bounded
`consumeBytes`/`consumeString` for a parameter that is not the last, and
`consumeRemainingAsBytes`/`consumeRemainingAsString` for the last); the
directive line records the types (`... #read string,int,boolean,bytes`). The
class is in the default package and is generated without a model call. As with the Python
path, lint accepts only the generated text for the recorded target, and the
service requires the recorded method to be the selected one.

## Build

One fixed sandboxed script unpacks the jars staged from the project's `lib/`
and `libs/` directories into the class directory (dropping their manifests,
signature files and `module-info.class`), compiles every staged `.java` file
outside `test` and `tests` directories and the run, output, and corpus trees,
together with the harness class, against those classes and the image's
Jazzer API jar, packs the classes into a jar, and writes the harness
artifact: a two-line shell stub followed by the jar. The project's own
classes are compiled last, so they replace a vendored class of the same
name. The Jazzer API jar is on the compile class path only; it is not packed.

```sh
#!/bin/sh
exec jazzer --cp="$0" --target_class=OxfuzzFuzzTarget --reproducer_path=/tmp "$@"
```

The artifact is one executable file that contains every class the run
executes, so smoke, campaign, and replay start it the way they start a
compiled harness, and a run's staged copy is immutable. `javac` compiles
without running project code; nothing from the project executes before the
smoke approval.

## Execution and findings

The argv is fixed libFuzzer flags (`-max_total_time`, `-artifact_prefix`,
`-use_value_profile=1`, `-print_final_stats=1`, the corpus directory, the
recorded seed and per-input timeout). A run is one JVM; fork and job flags
are refused.

The template treats the types in the method's `throws` clause, qualified
through the file's imports, `java.lang` or its own package, as the method's
rejections of an input (JSON-java's `XML.toJSONObject` declares
`JSONException`): the entry point declares `throws Throwable`, catches, and
rethrows anything that is not one of them. `Exception`, `Throwable`,
`RuntimeException` and `Error` are never treated as rejections. The
directive records the list (`throws:org.json.JSONException`).

The seed is passed as its low 32 bits, the value libFuzzer keeps of any
`-seed`; Jazzer refuses a wider value and would not start.

An uncaught exception or a Jazzer bug-detector report exits 77 and writes
`crash-<sha1>`, collected like a libFuzzer artifact. Classification names the
exception line and signs the `at` frames of the code under test, leaving out
the harness class and Jazzer's own frames. An exit other than 0, 70, or 77 is
a failed run, never a finding.

No sanitizer selection applies. Selected-function entry evidence, coverage
reports, minimization, and CASR are not implemented for this path.

## Verification

Unit tests cover the scanner, the template and lint, the build script,
the argv, admission by engine and sanitizer, and classification on recorded
output.

One ignored live test (`jvm_jazzer_tests`, passed 2026-11-21 in image 0.2.3
on macOS arm64) runs the product's own build and smoke operations over a
project with a planted `ArrayIndexOutOfBoundsException`: the finding is
collected as one `crash-*` input, replays with exit 77, and classifies as
`java.lang.ArrayIndexOutOfBoundsException: Index N out of bounds for length
3`; a staged run artifact replays to the same signature; the corrected
method fuzzes clean with throughput and the saved input exits 0; a source
that does not compile fails the build with `cannot find symbol`. The project
in that test also carries a JUnit test source and a class named like the
harness, and neither reaches the build.

Two more ignored live tests passed 2026-11-22 in the same image: a project
that imports a class from a jar under `lib/` fails the build without the jar
and, with it, builds, runs, and has its planted exception found inside the
vendored class; and a method taking `(int, boolean, byte[])` is decoded
through the data provider, its planted exception is found, and the saved
input replays with exit 77.

A full review/promotion/campaign/Stop cycle through the commands and a
multi-project acceptance remain open.
