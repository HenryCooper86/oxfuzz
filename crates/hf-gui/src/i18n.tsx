// Lightweight, dependency-free internationalization.
//
// A locale is stored in localStorage and exposed via `useI18n().t(key)`, which
// looks up the active locale's string, falling back to English, then to the key
// itself. Only a curated set of high-visibility UI strings is translated so
// far; untranslated strings render their English fallback. Add keys to both
// dictionaries to extend coverage.

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

export type Locale = "en" | "zh";

/** Locales offered in the language selector, in display order. */
export const LOCALES: { value: Locale; label: string }[] = [
  { value: "en", label: "English" },
  { value: "zh", label: "简体中文" },
];

const STORAGE_KEY = "hf_locale";

type Dict = Record<string, string>;

const en: Dict = {
  // Sidebar navigation
  "nav.dashboard": "Dashboard",
  "nav.chat": "AI Assistant",
  "nav.workflow": "Fuzzing Workflow",
  "nav.discover": "Discover",
  "nav.harness": "Harness",
  "nav.run": "Run",
  "nav.triage": "Triage",
  "nav.corpus": "Corpus",
  "nav.projects": "Projects",
  "nav.artifacts": "Artifacts",
  "nav.agents": "Agents",
  "nav.skills": "Skills",
  "nav.knowledge": "Knowledge",
  "nav.automation": "Automation",
  "nav.settings": "Settings",
  "sidebar.newTarget": "New fuzzing target",
  "sidebar.targets": "Targets",
  "sidebar.pipeline": "Pipeline",
  "sidebar.library": "Library",
  "sidebar.noTargets": "No targets yet. Add a project folder to start fuzzing.",
  "sidebar.removeTarget": "Remove from targets",

  // Header (screen titles)
  "title.dashboard": "Team Dashboard",
  "title.workflow": "Fuzzing Workflow",
  "title.chat": "AI Assistant",
  "title.discover": "Target Discovery",
  "title.harness": "Harness Generation",
  "title.run": "Fuzz Run",
  "title.triage": "Crash Triage",
  "title.corpus": "Corpus Management",
  "title.settings": "Settings",
  "title.projects": "Projects",
  "title.artifacts": "Artifacts",
  "title.agents": "Agents",
  "title.skills": "Skills",
  "title.knowledge": "Knowledge",
  "title.automation": "Automation",

  // Header toggles (right-side panels)
  "header.progress": "Progress",
  "header.diagnostics": "Diagnostics",
  "header.observability": "Observability",
  "header.info": "Info",

  // Progress panel
  "progress.title": "Progress",
  "progress.reset": "Reset progress",
  "stage.discover": "Discover targets",
  "stage.harness": "Generate harness",
  "stage.compile": "Compile in sandbox",
  "stage.seeds": "Generate seed corpus",
  "stage.run": "Run fuzzer",
  "stage.triage": "Triage crashes",

  // Settings
  "settings.back": "Back",
  "settings.save": "Save Changes",
  "settings.language": "Language",
  "settings.tab.general": "General",
  "settings.tab.providers": "Providers",
  "settings.tab.session": "Session",
  "settings.tab.runtime": "Runtime",
  "settings.tab.engines": "Engines",
  "settings.tab.tools": "Tools",
  "settings.tab.guardrails": "Guardrails",
  "settings.tab.storage": "Storage",
  "settings.tab.about": "About",

  // AI Assistant welcome screen
  "welcome.title": "Welcome to hobot_fuzz",
  "welcome.tagline":
    "An AI fuzzing agent that discovers targets, writes harnesses, and drives fuzzing engines.",
  "welcome.pick": "Pick a project to get started, or ask the assistant below.",
  "welcome.chip.discover": "Discover targets",
  "welcome.chip.harness": "Generate harness",
  "welcome.chip.run": "Run a fuzzer",
  "welcome.chip.triage": "Triage crashes",
  "welcome.chip.corpus": "Manage corpus",
  "composer.placeholder": "Type a message…",
  "composer.placeholderPlan": "Describe the goal — the agent will plan first…",
  "common.noProject": "No project",
};

const zh: Dict = {
  // Sidebar navigation
  "nav.dashboard": "仪表盘",
  "nav.chat": "AI 助手",
  "nav.workflow": "模糊测试流程",
  "nav.discover": "发现",
  "nav.harness": "测试桩",
  "nav.run": "运行",
  "nav.triage": "分类定级",
  "nav.corpus": "语料库",
  "nav.projects": "项目",
  "nav.artifacts": "产物",
  "nav.agents": "智能体",
  "nav.skills": "技能",
  "nav.knowledge": "知识库",
  "nav.automation": "自动化",
  "nav.settings": "设置",
  "sidebar.newTarget": "新建模糊测试目标",
  "sidebar.targets": "目标",
  "sidebar.pipeline": "流程",
  "sidebar.library": "资源库",
  "sidebar.noTargets": "暂无目标。添加一个项目文件夹以开始模糊测试。",
  "sidebar.removeTarget": "从目标中移除",

  // Header (screen titles)
  "title.dashboard": "团队仪表盘",
  "title.workflow": "模糊测试流程",
  "title.chat": "AI 助手",
  "title.discover": "目标发现",
  "title.harness": "测试桩生成",
  "title.run": "模糊测试运行",
  "title.triage": "崩溃分类定级",
  "title.corpus": "语料库管理",
  "title.settings": "设置",
  "title.projects": "项目",
  "title.artifacts": "产物",
  "title.agents": "智能体",
  "title.skills": "技能",
  "title.knowledge": "知识库",
  "title.automation": "自动化",

  // Header toggles (right-side panels)
  "header.progress": "进度",
  "header.diagnostics": "诊断",
  "header.observability": "可观测性",
  "header.info": "信息",

  // Progress panel
  "progress.title": "进度",
  "progress.reset": "重置进度",
  "stage.discover": "发现目标",
  "stage.harness": "生成测试桩",
  "stage.compile": "在沙箱中编译",
  "stage.seeds": "生成种子语料",
  "stage.run": "运行模糊器",
  "stage.triage": "分类崩溃",

  // Settings
  "settings.back": "返回",
  "settings.save": "保存更改",
  "settings.language": "语言",
  "settings.tab.general": "常规",
  "settings.tab.providers": "提供方",
  "settings.tab.session": "会话",
  "settings.tab.runtime": "运行时",
  "settings.tab.engines": "引擎",
  "settings.tab.tools": "工具",
  "settings.tab.guardrails": "安全护栏",
  "settings.tab.storage": "存储",
  "settings.tab.about": "关于",

  // AI Assistant welcome screen
  "welcome.title": "欢迎使用 hobot_fuzz",
  "welcome.tagline": "一个 AI 模糊测试智能体，自动发现目标、编写测试桩并驱动模糊测试引擎。",
  "welcome.pick": "选择一个项目开始，或在下方向助手提问。",
  "welcome.chip.discover": "发现目标",
  "welcome.chip.harness": "生成测试桩",
  "welcome.chip.run": "运行模糊器",
  "welcome.chip.triage": "分类崩溃",
  "welcome.chip.corpus": "管理语料库",
  "composer.placeholder": "输入消息…",
  "composer.placeholderPlan": "描述目标——助手会先制定计划…",
  "common.noProject": "未选择项目",
};

const DICTS: Record<Locale, Dict> = { en, zh };

interface I18nContextValue {
  locale: Locale;
  setLocale: (l: Locale) => void;
  /** Translate a key, falling back to English then the key itself. */
  t: (key: string) => string;
}

const I18nContext = createContext<I18nContextValue | null>(null);

function loadLocale(): Locale {
  try {
    return localStorage.getItem(STORAGE_KEY) === "zh" ? "zh" : "en";
  } catch {
    return "en";
  }
}

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(loadLocale);

  useEffect(() => {
    document.documentElement.lang = locale === "zh" ? "zh-CN" : "en";
  }, [locale]);

  const setLocale = useCallback((l: Locale) => {
    setLocaleState(l);
    try {
      localStorage.setItem(STORAGE_KEY, l);
    } catch {
      /* ignore */
    }
  }, []);

  const t = useCallback(
    (key: string) => DICTS[locale][key] ?? en[key] ?? key,
    [locale],
  );

  const value = useMemo(() => ({ locale, setLocale, t }), [locale, setLocale, t]);
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (!ctx) {
    throw new Error("useI18n must be used within an I18nProvider");
  }
  return ctx;
}
