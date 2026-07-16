import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { HELP_SECTIONS } from "../views/help/helpContent";
import { HELP_SECTIONS_ZH } from "../views/help/helpContent.zh";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("in-app documentation", () => {
  it("documents every current library surface in both languages", () => {
    const englishIds = HELP_SECTIONS.map((section) => section.id);
    const chineseIds = HELP_SECTIONS_ZH.map((section) => section.id);

    expect(englishIds).toContain("automotive");
    expect(chineseIds).toEqual(englishIds);
  });

  it("states that approval never enables generated host execution", () => {
    const englishWelcome = HELP_SECTIONS.find((section) => section.id === "welcome");
    const chineseWelcome = HELP_SECTIONS_ZH.find((section) => section.id === "welcome");

    expect(englishWelcome?.body).toContain("never execute on the host");
    expect(englishWelcome?.body).toContain("exact promoted revision");
    expect(englishWelcome?.body).not.toContain("host without your explicit approval");
    expect(chineseWelcome?.body).toContain("绝不会在主机上执行");
  });

  it("links shipped documentation surfaces to the local GitLab project", () => {
    const helpView = source("../views/HelpView.tsx");
    const aboutTab = source("../components/settings/AboutTab.tsx");
    const projectLinks = source("../lib/projectLinks.ts");
    const messages = source("../i18n.extra.ts");

    expect(projectLinks).toContain("https://gitlab-ce.orb.local/hobot/hobot_fuzz");
    expect(helpView).toContain('from "../lib/projectLinks"');
    expect(aboutTab).toContain('from "../../lib/projectLinks"');
    expect(helpView).toContain("Open the GitLab repository");
    expect(helpView).toContain("<Gitlab");
    expect(aboutTab).toContain("<Gitlab");
    expect(helpView).not.toContain("github.com/hobot/hobot_fuzz");
    expect(aboutTab).not.toContain("github.com/hobot/hobot_fuzz");
    expect(messages).toContain('"settings.about.repo": "GitLab Project"');
    expect(messages).toContain('"settings.about.repo": "GitLab 项目"');
  });
});
