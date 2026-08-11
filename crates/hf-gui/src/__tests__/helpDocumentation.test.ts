import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { HELP_SECTIONS } from "../views/help/helpContent";
import { HELP_SECTIONS_ZH } from "../views/help/helpContent.zh";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("in-app documentation", () => {
  it("does not mention retired engines in rendered help content", () => {
    const retired = ["cluster", "fuzz", "lite"].join("");
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
