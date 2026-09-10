import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { HELP_SECTIONS } from "../views/help/helpContent";
import { HELP_SECTIONS_ZH } from "../views/help/helpContent.zh";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("in-app documentation", () => {
  it("does not mention retired engines in rendered help content", () => {
    const retired = String.fromCharCode(99, 108, 117, 115, 116, 101, 114, 102, 117, 122, 122, 108, 105, 116, 101);
    const bodies = [...HELP_SECTIONS, ...HELP_SECTIONS_ZH]
      .map((section) => section.body)
      .join("\n")
      .toLowerCase();

    expect(bodies).not.toContain(retired);
  });

  it("documents every current library surface in both languages", () => {
    const englishIds = HELP_SECTIONS.map((section) => section.id);
    const chineseIds = HELP_SECTIONS_ZH.map((section) => section.id);

    expect(englishIds).toContain("automotive");
    expect(chineseIds).toEqual(englishIds);
  });

  it("documents installing the packaged app and the Gatekeeper first-launch step in both languages", () => {
    const englishFirstRun = HELP_SECTIONS.find((section) => section.id === "first-run");
    const chineseFirstRun = HELP_SECTIONS_ZH.find((section) => section.id === "first-run");

    expect(englishFirstRun?.body).toContain("Applications");
    expect(englishFirstRun?.body).toContain("Gatekeeper");
    expect(englishFirstRun?.body).toContain("xattr -cr /Applications/oxfuzz.app");
    expect(chineseFirstRun?.body).toContain("Gatekeeper");
    expect(chineseFirstRun?.body).toContain("xattr -cr /Applications/oxfuzz.app");
  });

  it("states that approval never enables generated host execution", () => {
    const englishWelcome = HELP_SECTIONS.find((section) => section.id === "welcome");
    const chineseWelcome = HELP_SECTIONS_ZH.find((section) => section.id === "welcome");

    expect(englishWelcome?.body).toContain("never execute on the host");
    expect(englishWelcome?.body).toContain("exact promoted revision");
    expect(englishWelcome?.body).not.toContain("host without your explicit approval");
    expect(chineseWelcome?.body).toContain("绝不会在主机上执行");
  });

  it("documents corpus import, exact readiness, and reduction meanings in both languages", () => {
    const englishCorpus = HELP_SECTIONS.find((section) => section.id === "corpus");
    const chineseCorpus = HELP_SECTIONS_ZH.find((section) => section.id === "corpus");

    expect(englishCorpus?.body).toContain("approved root");
    expect(englishCorpus?.body).toContain("byte-identical");
    expect(englishCorpus?.body).toContain("exact promoted");
    expect(englishCorpus?.body).toContain("empty input");
    expect(englishCorpus?.body).toContain("byte deduplication");
    expect(englishCorpus?.body).toContain("Unknown");
    expect(chineseCorpus?.body).toContain("批准根目录");
    expect(chineseCorpus?.body).toContain("字节相同");
    expect(chineseCorpus?.body).toContain("准确的已提升");
    expect(chineseCorpus?.body).toContain("空输入");
    expect(chineseCorpus?.body).toContain("字节去重");
    expect(chineseCorpus?.body).toContain("未知");
  });

  it("documents retained health, closeout, work-order, and experiment handoffs in both languages", () => {
    const englishHarness = HELP_SECTIONS.find((section) => section.id === "harness");
    const chineseHarness = HELP_SECTIONS_ZH.find((section) => section.id === "harness");
    const englishRun = HELP_SECTIONS.find((section) => section.id === "run");
    const chineseRun = HELP_SECTIONS_ZH.find((section) => section.id === "run");
    const englishCorpus = HELP_SECTIONS.find((section) => section.id === "corpus");
    const chineseCorpus = HELP_SECTIONS_ZH.find((section) => section.id === "corpus");
    const englishRuns = HELP_SECTIONS.find((section) => section.id === "runs");
    const chineseRuns = HELP_SECTIONS_ZH.find((section) => section.id === "runs");

    expect(englishHarness?.body).toContain("file-qualified target selector");
    expect(englishHarness?.body).toContain("retained attempt ID");
    expect(chineseHarness?.body).toContain("文件限定目标选择器");
    expect(chineseHarness?.body).toContain("保留的尝试 ID");

    expect(englishRun?.body).toContain("whole-run mean");
    expect(englishRun?.body).toContain("read-only");
    expect(chineseRun?.body).toContain("全程平均值");
    expect(chineseRun?.body).toContain("只读");

    expect(englishRuns?.body).toContain("seven-step");
    expect(englishRuns?.body).toContain("Analyze / Resume");
    expect(chineseRuns?.body).toContain("七个步骤");
    expect(chineseRuns?.body).toContain("分析 / 继续");

    expect(englishCorpus?.body).toContain("Start reviewed replay");
    expect(englishCorpus?.body).toContain("current resource limits");
    expect(englishCorpus?.body).toContain("legacy baseline");
    expect(chineseCorpus?.body).toContain("启动已审查的重放");
    expect(chineseCorpus?.body).toContain("当前资源限制");
    expect(chineseCorpus?.body).toContain("旧版基线");
  });

  it("links shipped documentation surfaces to the public GitHub project", () => {
    const helpView = source("../views/HelpView.tsx");
    const aboutTab = source("../components/settings/AboutTab.tsx");
    const projectLinks = source("../lib/projectLinks.ts");
    const messages = source("../i18n.extra.ts");

    // The public repository is the only repository an external user can reach.
    // Pin the host positively rather than denying a specific one: this fails for
    // any non-github.com URL, and avoids naming a private host in a public repo.
    expect(projectLinks).toContain("https://github.com/HenryCooper86/oxfuzz");
    expect(projectLinks).toMatch(
      /PROJECT_REPOSITORY_URL = "https:\/\/github\.com\//,
    );
    // GitHub blob URLs have no `/-/` infix, unlike GitLab.
    expect(projectLinks).toContain("/blob/main/docs/guides/GETTING_STARTED.md");
    expect(projectLinks).not.toContain("/-/blob/");
    expect(helpView).toContain('from "../lib/projectLinks"');
    expect(aboutTab).toContain('from "../../lib/projectLinks"');
    expect(helpView).toContain("Open the GitHub repository");
    expect(helpView).toContain("<Github");
    expect(aboutTab).toContain("<Github");
    expect(helpView).not.toContain("<Gitlab");
    expect(aboutTab).not.toContain("<Gitlab");
    expect(messages).toContain('"settings.about.repo": "GitHub Project"');
    expect(messages).toContain('"settings.about.repo": "GitHub 项目"');
  });
});
