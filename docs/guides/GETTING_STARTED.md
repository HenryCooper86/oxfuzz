# Getting Started (for people who are not fuzzing engineers)

This guide explains, in plain language, what hobot_fuzz is, what it does for you,
and how to run it for the first time. You do **not** need to be a security
researcher or know anything about "fuzzing" to follow along. Every technical
term is explained the first time it appears, and there is a [glossary](#glossary)
at the end.

---

## What is fuzzing? (the one-paragraph version)

Imagine you wrote a program that reads files -- say, an image viewer. It works
fine on normal images. But what happens if someone feeds it a *broken* or
*malicious* image? It might crash, leak data, or be hijacked by an attacker.

**Fuzzing** is the practice of finding those problems automatically: a tool
throws millions of weird, random, and deliberately malformed inputs at your
program as fast as possible, watching for any that make it crash or misbehave.
Each crash is a potential bug -- often a security vulnerability. Fuzzing is one
of the most effective ways to find serious bugs, and it is how companies like
Google continuously test the software the world runs on.

The catch: fuzzing is normally **a lot of expert work**. You have to figure out
*what* to test, write special "test driver" code by hand, configure a fuzzing
engine, run it safely, and then make sense of the crashes. That expertise is
exactly what hobot_fuzz automates.

---

## What does hobot_fuzz do for you?

hobot_fuzz is an **AI fuzzing assistant**. You point it at a codebase, and it
walks through the whole process for you, asking for your approval at the
important steps:

1. **Finds what to test.** It scans the project and ranks the functions most
   worth fuzzing (the ones that handle untrusted input).
2. **Writes the test code.** An AI model writes the small "harness" program that
   feeds fuzz input into a chosen function -- the part that normally takes an
   engineer.
3. **Builds and runs it safely.** All untrusted code is compiled and executed
   inside an isolated **sandbox** (a locked-down container), so nothing touches
   your real machine without permission.
4. **Runs the fuzzer.** It drives a real, industry-standard fuzzing engine
   (libFuzzer, AFL++, or honggfuzz) for as long as you want.
5. **Explains the crashes.** When it finds bugs, it groups duplicates, rates how
   serious each one is, and drafts a human-readable bug report.

You stay in control the whole time: hobot_fuzz never runs generated code on your
computer without your approval.

## Who is this for?

- **Developers** who want to harden their code but are not fuzzing experts.
- **Security teams** who want to scale up testing without writing every harness
  by hand.
- **Anyone curious** who wants to see what fuzzing finds in a codebase.

---

## What you need before you start

| You need | Why | Notes |
| --- | --- | --- |
| **The hobot_fuzz desktop app** | The friendliest way to use it | A normal macOS app window. See [Installing](#installing-the-desktop-app). |
| **An AI provider key** | The AI writes the test code and bug reports | An API key from an LLM provider (e.g. OpenAI). You paste it into Settings. |
| **Docker** | Runs the sandbox that keeps untrusted code isolated | Install [OrbStack](https://orbstack.dev) or Docker Desktop. The app can start it for you. |
| **A project to test** | Something to fuzz | A folder of C or C++ source code works best today. |

You do **not** need to install fuzzing engines yourself -- they come bundled
inside the sandbox.

---

## Installing the desktop app

If you have a prebuilt app, just open it. To build it from source:

```bash
git clone https://github.com/hobot/hobot_fuzz.git
cd hobot_fuzz
./scripts/build-app.sh
open target/release/bundle/macos/hobot_fuzz.app
```

The first launch builds the sandbox image, which can take a few minutes.

---

## Your first run, step by step

Open the app. You will see a left sidebar (the pipeline), a main panel, and a
**Progress 0/6** checklist on the right. Here is what each step means and what to
click.

### 0. Connect your AI provider

Go to **Settings -> Providers**, add your provider, and paste your API key.
Without this, the AI cannot write harnesses or reports. (Settings shows sensible
defaults out of the box; you only need to fill in the key.)

### 1. Pick a project

On the **AI Assistant** screen, click the **No project** dropdown and choose the
folder of code you want to test. Then either use the **Fuzzing Workflow** screen
(which walks you through all six steps) or just tell the assistant what you want
in plain English ("discover targets and fuzz the riskiest one").

### 2. The six-step pipeline (what the Progress checklist tracks)

| Step | Plain-language meaning |
| --- | --- |
| **1. Discover targets** | Scan the project and list the functions most worth fuzzing, ranked by risk. |
| **2. Generate harness** | The AI writes the small test-driver program for the function you picked. |
| **3. Compile in sandbox** | Build that test program inside the isolated container. |
| **4. Generate seed corpus** | Create a starter set of example inputs to give the fuzzer a head start. |
| **5. Run fuzzer** | Launch a real fuzzing engine and let it hammer the target for a set time. |
| **6. Triage crashes** | Collect any crashes, remove duplicates, rate severity, and draft bug reports. |

You approve the actions that matter (e.g. compiling and running generated code).
Each finished step gets a checkmark.

### 3. Read your results

Open the **Triage** screen or the **Fuzzing Report**. For each finding you will
see:

- **Kind** -- what kind of error (e.g. "Asan" means the AddressSanitizer caught a
  memory bug like a buffer overflow).
- **Severity** -- how dangerous it is. **"Exploitable"** means an attacker could
  likely abuse it; lower ratings are still bugs but less risky.
- **Location** -- the file and line where it crashed.
- **A drafted bug report** -- a written explanation of the bug and its impact.

A finding here is a real crash the fuzzer reproduced -- a concrete lead to fix.

---

## Prefer the terminal? (optional)

Everything above is also available as a command-line tool, `hobot-fuzz`. A full
campaign looks like this:

```bash
hobot-fuzz discover /path/to/project --lang c            # step 1
hobot-fuzz harness  /path/to/project --target parse_value --engine libfuzzer  # steps 2-3
hobot-fuzz run      /path/to/project --target parse_value --engine libfuzzer --duration 30m  # steps 4-5
hobot-fuzz triage   /path/to/project --target parse_value  # step 6
```

See the [README](../../README.md#quick-start) for the full command reference.

---

## Glossary

Plain-language definitions, in the order you are likely to meet them.

- **Fuzzing** -- automatically throwing huge numbers of malformed/random inputs
  at a program to find inputs that crash it.
- **Target** -- a specific function (or entry point) you want to fuzz, usually
  one that handles untrusted input (a parser, decoder, etc.).
- **Harness** -- a small piece of test code that takes a chunk of fuzz bytes and
  feeds it into the target function. hobot_fuzz writes this for you.
- **Fuzzing engine** -- the actual tool that generates inputs and runs the target
  millions of times. hobot_fuzz supports the standard ones: **libFuzzer**,
  **AFL++**, and **honggfuzz** (plus advanced options like ClusterFuzzLite and
  Syzkaller).
- **Corpus** -- the collection of example inputs the fuzzer keeps and mutates. A
  good starter corpus ("seed corpus") helps it find bugs faster.
- **Coverage** -- how much of the program's code the fuzzer has actually
  exercised. More coverage means it has explored more behavior.
- **Crash** -- an input that makes the program fail (segfault, abort, memory
  error, etc.). Each unique crash is a candidate bug.
- **Triage** -- sorting crashes: grouping duplicates, judging severity, and
  writing up what each one means.
- **Sanitizer** (e.g. **AddressSanitizer / ASan**) -- a debugging tool compiled
  into the target that detects subtle memory bugs (like buffer overflows) the
  moment they happen, even if the program would not have crashed on its own.
- **Exploitable** -- a severity rating meaning an attacker could likely turn the
  crash into a real security compromise.
- **Sandbox** -- an isolated, locked-down environment (a Docker container here)
  where untrusted code is built and run so it cannot harm your machine.
- **LLM provider** -- the AI service (e.g. OpenAI) that powers the assistant; you
  supply an API key for it.
- **HITL (human-in-the-loop)** -- the principle that a person approves the
  important, risky actions instead of the AI doing them unsupervised.

---

## Where to go next

- [README](../../README.md) -- features, configuration, and the command-line
  reference.
- [docs/design/](../design/) -- how each part works under the hood.
- [docs/standards/](../standards/) -- the engineering standards the project
  follows.
