// Every string the page shows, per language. The template in src/index.html
// refers to these by key; the build fails on a missing or unused key, and a
// test keeps the two languages in step. Values may contain inline HTML.
export const locales = {
  en: {
    lang: "en",
    home: "/",
    alt_lang: "zh-CN",
    alt_href: "/zh/",
    alt_label: "中文",
    alt_title: "阅读中文版",
    page_title: "oxfuzz: the open-source AI fuzzing agent",
    meta_description:
      "oxfuzz is an open-source AI fuzzing agent for C, C++ and Rust. It picks the functions worth fuzzing, writes the harness, runs AFL++, libFuzzer, honggfuzz or syzkaller in a sandbox, and hands back every crash with the input and stack trace that reproduce it.",
    skip: "Skip to content",
    home_aria: "oxfuzz home",
    nav_aria: "Main navigation",
    nav_how: "How it works",
    nav_engines: "Engines",
    nav_contribute: "Contribute",
    nav_download: "Download",

    hero_title: "Find the crash<br />before your users do.",
    hero_lede:
      "oxfuzz is an open-source AI fuzzing agent for C, C++ and Rust. Point it at a source folder: it picks the functions worth attacking, writes the harness, runs the fuzzer in a sandbox, and hands back every crash with the input and stack trace that reproduce it.",
    hero_download: "Download v{{VERSION}}",
    hero_source: "View the source on GitHub",
    hero_facts:
      "Free under the MIT license. macOS, Linux and Windows. You approve every step.",

    fuzz_aria: "A finding oxfuzz produced, replayed step by step",
    fuzz_running: "fuzzing",
    fuzz_found: "crash found",
    fuzz_input: "input",
    fuzz_execs: "executions",
    fuzz_replay: "Replay",
    finding_kind: "use-after-poison",
    finding_severity: "probably exploitable",
    finding_where: "decode_utf8 at utf8.c:31",
    fact_engine: "Engine",
    fact_found: "Found after",
    fact_found_value: "123 executions",
    fact_inputs: "Crashing inputs",
    fact_inputs_value: "4, grouped into 1 finding",
    finding_caption:
      "A real result from the bundled <code>utf8_decoder</code> example. Two bytes are enough: a lead byte that promises three sends the decoder past the end of the buffer.",

    demo_title: "Watch it find a real bug in one minute",
    demo_intro:
      "A recording of oxfuzz on the bundled <code>utf8_decoder</code> example, shortened to fit. It shows the harness it wrote, runs AFL++ for a minute while the numbers move, and files the crash.",
    demo_alt:
      "Recording of oxfuzz showing a generated harness, running a one-minute AFL++ campaign with live coverage and speed, and listing the resulting finding",
    demo_fact_score: "Target score",
    demo_fact_score_value: "83 / 100",
    demo_fact_campaign: "Campaign",
    demo_fact_campaign_value: "1 minute, AFL++",
    demo_fact_speed: "Peak speed",
    demo_fact_speed_value: "10,095 runs per second",
    demo_fact_result: "Result",
    demo_fact_result_value: "4 crashing inputs, 1 finding",

    why_title: "Fuzzing finds what tests miss. Setting it up is the hard part.",
    why_intro:
      "A fuzzer throws millions of unexpected inputs at your code and watches for memory errors. The catch has always been the groundwork: choosing targets, writing harnesses, building with sanitizers, and sorting through piles of duplicate crashes. oxfuzz does that groundwork and leaves the decisions to you.",
    why_1_title: "Minutes to a first run",
    why_1_text:
      "Open a folder and get a ranked list of targets, with a reason for each. There is no harness to write by hand.",
    why_2_title: "Crashes you can prove",
    why_2_text:
      "Every finding keeps its input, sanitizer report and stack trace, so anyone on your team can replay it.",
    why_3_title: "Nothing runs unreviewed",
    why_3_text:
      "Generated code is built and run in a container with no network, and only after you approve it.",

    how_title: "From a source folder to a triaged crash in four steps",
    how_tabs_aria: "Choose a step",
    step_discover: "Discover",
    step_harness: "Harness",
    step_run: "Run",
    step_triage: "Triage",
    shot_open: "Open this screenshot at full size",
    discover_alt:
      "oxfuzz Discover screen listing nine ranked fuzz targets, with tlv_decode scored 100 out of 100 and recommended first",
    discover_caption:
      "<strong>Discover.</strong> oxfuzz scans the project and ranks the functions most worth fuzzing, with a score and a short reason for each.",
    harness_alt:
      "oxfuzz Harness screen showing the generated harness source for decode_utf8 and its smoke-test result",
    harness_caption:
      "<strong>Review the harness.</strong> A model drafts it. It is compiled and smoke-tested in the sandbox, then waits for you. No campaign runs until you approve it.",
    run_alt:
      "oxfuzz Run screen after a one-minute AFL++ campaign, showing edges covered, crash signals and executions per second",
    run_caption:
      "<strong>Run.</strong> Start a time-limited campaign and watch coverage, speed and crashes live. Stop it whenever you like; the results stay.",
    triage_alt:
      "oxfuzz Triage screen showing one finding with its sanitizer classification and stack trace at utf8.c line 31",
    triage_caption:
      "<strong>Triage.</strong> Crashes are replayed, grouped by stack and rated. Export a report, SARIF, or an issue draft.",

    engines_title: "Four engines, one workflow",
    engines_intro:
      "oxfuzz drives the fuzzers you already trust. You choose the engine; the steps around it stay the same.",
    engine_libfuzzer:
      "In-process and fast. The usual first choice for a library.",
    engine_libfuzzer_link: "libFuzzer documentation",
    engine_afl: "Coverage-guided, with strong mutation and corpus tools.",
    engine_afl_link: "AFL++ documentation",
    engine_honggfuzz: "Multi-process, with hardware and software feedback.",
    engine_honggfuzz_link: "honggfuzz documentation",
    engine_syzkaller:
      "Linux kernel fuzzing in a VM. You supply the kernel and guest image.",
    engine_syzkaller_link: "syzkaller setup guide",

    control_title: "The fuzzer runs untrusted code. You stay in charge of it.",
    control_1_title: "Sandboxed",
    control_1_text:
      "Every build and every run happens in a Docker container with no network. Nothing generated runs on your machine directly.",
    control_2_title: "Approved by a person",
    control_2_text:
      "A harness is reviewed by a model and then by you. Campaigns only run harnesses you approved.",
    control_3_title: "Your choice of model",
    control_3_text:
      "Use OpenAI, Anthropic, Gemini, Azure OpenAI, Ollama, or any OpenAI-compatible endpoint, with spending limits you set.",
    control_also:
      "Also included: scheduled campaigns, corpus tools, project search, reusable skills and agents, and DefectDojo, GitHub and GitLab hand-off.",

    oss_title: "oxfuzz is open source, and you can help shape it",
    oss_p1:
      "The whole project is on GitHub under the MIT license: the desktop app, the service behind it, and the sandbox. Read it, run it, change it.",
    oss_p2:
      "Any improvement is welcome. A bug report, a fixed typo, a new example target, or a feature you built for your own team all make oxfuzz better for the next person.",
    oss_button: "Open the repository",
    oss_way_1: "Report a bug or ask for a feature",
    oss_way_1_text: "Tell us what broke or what is missing.",
    oss_way_2: "Send a pull request",
    oss_way_2_text: "The contributing guide covers setup, tests and style.",
    oss_way_3: "Pick up an open issue",
    oss_way_3_text: "See what is planned and what needs a hand.",
    oss_way_4: "Report a security problem privately",
    oss_way_4_text: "Please do not open a public issue for these.",

    dl_title: "Download oxfuzz {{VERSION}}",
    dl_intro:
      "Pick the package for your system. You also need Docker, and the sandbox kit to build the fuzzing environment.",
    dl_macos: "Apple silicon or Intel. Ad-hoc signed; not notarized.",
    dl_linux: "x86_64 desktop. Docker Engine required.",
    dl_windows:
      "64-bit Windows. Unsigned installers. Docker Desktop with WSL 2.",
    dl_sandbox:
      "Build the isolated engine environment locally. Docker required.",
    dl_sandbox_name: "Sandbox",
    dl_unavailable: "Candidate build, not yet available",
    dl_preview:
      "Release verification is in progress. Downloads will be enabled after the checks finish.",
    dl_notice:
      "This is an early release. macOS packages are ad-hoc signed and not notarized, and Windows packages are unsigned, so your system may warn you before installing. Only the macOS Apple silicon package is tested live for each release; the others are built and checked in CI.",
    setup_title: "Set up in three steps",
    setup_1:
      "<strong>Install the app.</strong> On macOS, drag oxfuzz to Applications. On Linux, install the DEB or RPM, or make the AppImage executable. On Windows, run the installer.",
    setup_2:
      "<strong>Build the sandbox.</strong> Extract the sandbox kit and run the script below. It needs Bash, Python 3 and Docker (on Windows, a WSL 2 shell), and a few GB of disk space.",
    setup_3:
      "<strong>Add a model provider and open a project.</strong> Enter your provider in Settings, then open a source folder and follow the workflow.",
    setup_note:
      "Kernel fuzzing with syzkaller also needs an instrumented kernel, a root filesystem and a guest SSH key, which the download does not include.",
    verify_title: "Verify your download",
    verify_text:
      "Compare the SHA-256 of the file with the published checksums before you install it.",
    verify_pending: "Checksums appear with the verified release.",
    verify_sums: "Download SHA256SUMS.txt",
    verify_manifest: "Release manifest",

    footer_license: "Open source under the MIT license.",
    footer_aria: "Footer",
    footer_notes: "Release notes",
    footer_contributing: "Contributing",
    footer_license_link: "License",
    footer_checksums: "Checksums",
  },

  zh: {
    lang: "zh-CN",
    home: "/zh/",
    alt_lang: "en",
    alt_href: "/",
    alt_label: "English",
    alt_title: "Read this page in English",
    page_title: "oxfuzz：开源的 AI 模糊测试智能体",
    meta_description:
      "oxfuzz 是面向 C、C++ 和 Rust 的开源 AI 模糊测试智能体。它挑选值得测试的函数，编写测试桩，在沙箱中运行 AFL++、libFuzzer、honggfuzz 或 syzkaller，并为每个崩溃保留可复现的输入和调用栈。",
    skip: "跳到正文",
    home_aria: "oxfuzz 首页",
    nav_aria: "主导航",
    nav_how: "工作流程",
    nav_engines: "引擎",
    nav_contribute: "参与贡献",
    nav_download: "下载",

    hero_title: "抢在用户之前，<br />找到那个崩溃。",
    hero_lede:
      "oxfuzz 是面向 C、C++ 和 Rust 的开源 AI 模糊测试智能体。给它一个源码目录，它会挑出最值得攻击的函数，写好测试桩，在沙箱里运行模糊测试，并把每个崩溃连同可复现的输入和调用栈一起交给你。",
    hero_download: "下载 v{{VERSION}}",
    hero_source: "在 GitHub 查看源码",
    hero_facts:
      "MIT 许可，免费使用。支持 macOS、Linux 和 Windows。每一步都由你批准。",

    fuzz_aria: "oxfuzz 产出的一个发现，逐步重放",
    fuzz_running: "测试中",
    fuzz_found: "发现崩溃",
    fuzz_input: "输入",
    fuzz_execs: "次执行",
    fuzz_replay: "重放",
    finding_kind: "use-after-poison",
    finding_severity: "很可能可利用",
    finding_where: "decode_utf8，位于 utf8.c:31",
    fact_engine: "引擎",
    fact_found: "发现于",
    fact_found_value: "第 123 次执行",
    fact_inputs: "崩溃输入",
    fact_inputs_value: "4 个，归并为 1 个发现",
    finding_caption:
      "这是内置示例 <code>utf8_decoder</code> 的真实结果。只需两个字节：首字节声称后面有三个字节，解码器就会读到缓冲区之外。",

    demo_title: "一分钟，看它找出一个真实的漏洞",
    demo_intro:
      "这是 oxfuzz 处理内置示例 <code>utf8_decoder</code> 的录屏，为便于展示做了缩短。它展示自己写出的测试桩，用 AFL++ 运行一分钟并实时刷新数据，然后登记崩溃。",
    demo_alt:
      "录屏：oxfuzz 展示生成的测试桩，运行一分钟的 AFL++ 测试并实时显示覆盖率和速度，然后列出得到的发现",
    demo_fact_score: "目标评分",
    demo_fact_score_value: "83 / 100",
    demo_fact_campaign: "测试时长",
    demo_fact_campaign_value: "1 分钟，AFL++",
    demo_fact_speed: "峰值速度",
    demo_fact_speed_value: "每秒 10,095 次执行",
    demo_fact_result: "结果",
    demo_fact_result_value: "4 个崩溃输入，1 个发现",

    why_title: "模糊测试能找到单元测试漏掉的问题，难的是把它搭起来。",
    why_intro:
      "模糊测试器向你的代码投入数以百万计的异常输入，并盯住内存错误。真正费事的一直是前期工作：选目标、写测试桩、带着 sanitizer 编译，再从一大堆重复的崩溃里理出头绪。oxfuzz 替你做完这些，把决定权留给你。",
    why_1_title: "几分钟内开始第一次运行",
    why_1_text:
      "打开一个目录，就能得到排好序的目标列表，每个都附有理由。不用手写测试桩。",
    why_2_title: "拿得出证据的崩溃",
    why_2_text:
      "每个发现都保留输入、sanitizer 报告和调用栈，团队里任何人都能重放。",
    why_3_title: "未经审查的代码不会运行",
    why_3_text:
      "生成的代码只在没有网络的容器里编译和运行，而且要先经过你的批准。",

    how_title: "从源码目录到分类完毕的崩溃，只需四步",
    how_tabs_aria: "选择步骤",
    step_discover: "发现目标",
    step_harness: "测试桩",
    step_run: "运行",
    step_triage: "崩溃分类",
    shot_open: "查看原图",
    discover_alt:
      "oxfuzz 的发现界面，列出九个已排序的模糊测试目标，其中 tlv_decode 评分 100 分并被推荐优先测试",
    discover_caption:
      "<strong>发现目标。</strong>oxfuzz 扫描整个项目，给最值得测试的函数排序，并为每个函数给出评分和简短理由。",
    harness_alt:
      "oxfuzz 的测试桩界面，显示为 decode_utf8 生成的测试桩源码及其冒烟测试结果",
    harness_caption:
      "<strong>审查测试桩。</strong>模型先起草，随后在沙箱里编译并做冒烟测试，然后等你确认。在你批准之前，不会启动任何测试。",
    run_alt:
      "oxfuzz 的运行界面，显示一分钟 AFL++ 测试结束后的覆盖边数、崩溃信号和每秒执行次数",
    run_caption:
      "<strong>运行。</strong>启动一次限时测试，实时查看覆盖率、速度和崩溃。可以随时停止，结果会保留。",
    triage_alt:
      "oxfuzz 的崩溃分类界面，显示一个发现及其 sanitizer 分类和位于 utf8.c 第 31 行的调用栈",
    triage_caption:
      "<strong>崩溃分类。</strong>崩溃会被重放、按调用栈归并并评级。可以导出报告、SARIF 或 issue 草稿。",

    engines_title: "四个引擎，一套流程",
    engines_intro:
      "oxfuzz 驱动的是你早已信任的模糊测试器。引擎由你选择，其余步骤保持不变。",
    engine_libfuzzer: "进程内运行，速度快。测试库代码时通常首选它。",
    engine_libfuzzer_link: "libFuzzer 文档",
    engine_afl: "覆盖率引导，变异能力和语料工具都很强。",
    engine_afl_link: "AFL++ 文档",
    engine_honggfuzz: "多进程，支持硬件和软件反馈。",
    engine_honggfuzz_link: "honggfuzz 文档",
    engine_syzkaller:
      "在虚拟机中对 Linux 内核做模糊测试。内核和客户机镜像由你提供。",
    engine_syzkaller_link: "syzkaller 配置指南",

    control_title: "模糊测试运行的是不可信代码，控制权始终在你手里。",
    control_1_title: "沙箱隔离",
    control_1_text:
      "每次编译、每次运行都在没有网络的 Docker 容器中进行。生成的代码不会直接在你的机器上运行。",
    control_2_title: "由人批准",
    control_2_text:
      "测试桩先由模型审查，再由你审查。只有你批准过的测试桩才会用于测试。",
    control_3_title: "模型由你选择",
    control_3_text:
      "可使用 OpenAI、Anthropic、Gemini、Azure OpenAI、Ollama，或任何兼容 OpenAI 的接口，并自行设定花费上限。",
    control_also:
      "还包括：定时测试、语料工具、项目搜索、可复用的技能与智能体，以及与 DefectDojo、GitHub 和 GitLab 的对接。",

    oss_title: "oxfuzz 是开源项目，欢迎你一起把它做得更好",
    oss_p1:
      "整个项目都在 GitHub 上，采用 MIT 许可：桌面应用、背后的服务以及沙箱。你可以阅读、运行和修改它。",
    oss_p2:
      "任何改进我们都欢迎。一份缺陷报告、一处错别字修正、一个新的示例目标，或者你为自己团队做的功能，都会让下一位使用者受益。",
    oss_button: "打开代码仓库",
    oss_way_1: "报告缺陷或提出功能建议",
    oss_way_1_text: "告诉我们哪里出了问题，或者还缺什么。",
    oss_way_2: "提交 Pull Request",
    oss_way_2_text: "贡献指南介绍了环境搭建、测试和代码风格。",
    oss_way_3: "认领一个未解决的 issue",
    oss_way_3_text: "看看有哪些计划，哪些地方需要帮手。",
    oss_way_4: "私下报告安全问题",
    oss_way_4_text: "这类问题请不要公开提交 issue。",

    dl_title: "下载 oxfuzz {{VERSION}}",
    dl_intro:
      "选择适合你系统的安装包。你还需要 Docker，以及用来构建测试环境的沙箱套件。",
    dl_macos: "Apple 芯片或 Intel。临时签名，未经公证。",
    dl_linux: "x86_64 桌面系统。需要 Docker Engine。",
    dl_windows:
      "64 位 Windows。安装包未签名。需要启用 WSL 2 的 Docker Desktop。",
    dl_sandbox: "在本机构建隔离的引擎环境。需要 Docker。",
    dl_sandbox_name: "沙箱",
    dl_unavailable: "候选版本，暂未提供",
    dl_preview: "发布验证正在进行，检查完成后将开放下载。",
    dl_notice:
      "这是早期版本。macOS 安装包为临时签名且未经公证，Windows 安装包未签名，安装前系统可能会给出警告。每个版本只有 macOS Apple 芯片安装包做过实机测试，其余安装包在 CI 中构建并检查。",
    setup_title: "三步完成安装",
    setup_1:
      "<strong>安装应用。</strong>macOS：把 oxfuzz 拖进“应用程序”。Linux：安装 DEB 或 RPM，或给 AppImage 加上可执行权限。Windows：运行安装程序。",
    setup_2:
      "<strong>构建沙箱。</strong>解压沙箱套件并运行下面的脚本。需要 Bash、Python 3 和 Docker（Windows 上请使用 WSL 2 终端），以及几个 GB 的磁盘空间。",
    setup_3:
      "<strong>添加模型服务并打开项目。</strong>在“设置”中填写模型服务，然后打开一个源码目录，按流程操作即可。",
    setup_note:
      "使用 syzkaller 做内核模糊测试，还需要带插桩的内核、根文件系统和客户机 SSH 密钥，下载包中不包含这些内容。",
    verify_title: "校验下载的文件",
    verify_text: "安装前，请把文件的 SHA-256 与公布的校验和进行比对。",
    verify_pending: "校验和将随通过验证的版本一同发布。",
    verify_sums: "下载 SHA256SUMS.txt",
    verify_manifest: "发布清单",

    footer_license: "以 MIT 许可开源。",
    footer_aria: "页脚",
    footer_notes: "更新日志",
    footer_contributing: "贡献指南",
    footer_license_link: "许可证",
    footer_checksums: "校验和",
  },
};
