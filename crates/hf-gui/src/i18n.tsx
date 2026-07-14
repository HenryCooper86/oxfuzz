// Lightweight, dependency-free internationalization.
//
// A locale is stored in localStorage and exposed via `useI18n().t(key)`, which
// looks up the active locale's string, falling back to English, then to the key
// itself. Only a curated set of high-visibility UI strings is translated so
// far; untranslated strings render their English fallback. Add keys to both
// dictionaries to extend coverage.

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { enExtra, zhExtra } from "./i18n.extra";

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
  "nav.reports": "Reports",
  "nav.runs": "Run History",
  "nav.audit": "Policy Audit",
  "nav.agents": "Agents",
  "nav.skills": "Skills",
  "nav.knowledge": "Knowledge",
  "nav.automation": "Automation",
  "nav.defectdojo": "DefectDojo",
  "nav.help": "Help & Docs",
  "nav.settings": "Settings",
  "sidebar.newTarget": "Open project",
  "sidebar.targets": "Recent",
  "sidebar.pipeline": "Pipeline",
  "sidebar.library": "Library",
  "sidebar.noTargets": "No projects yet. Add a project folder to start fuzzing.",
  "sidebar.removeTarget": "Remove from recents (keeps data)",

  // Header (screen titles)
  "title.dashboard": "Dashboard",
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
  "title.reports": "Composed Reports",
  "title.runs": "Run History",
  "title.audit": "Policy Audit",
  "title.agents": "Agents",
  "title.skills": "Skills",
  "title.knowledge": "Knowledge",
  "title.automation": "Automation",
  "title.defectdojo": "DefectDojo",
  "title.help": "Help & Documentation",

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
  "settings.tab.integrations": "Integrations",
  "settings.tab.issuetracker": "Issue Tracker",
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
  "nav.reports": "报告",
  "nav.runs": "运行历史",
  "nav.audit": "策略审计",
  "nav.agents": "智能体",
  "nav.skills": "技能",
  "nav.knowledge": "知识库",
  "nav.automation": "自动化",
  "nav.defectdojo": "DefectDojo",
  "nav.help": "帮助与文档",
  "nav.settings": "设置",
  "sidebar.newTarget": "打开项目",
  "sidebar.targets": "最近",
  "sidebar.pipeline": "流程",
  "sidebar.library": "资源库",
  "sidebar.noTargets": "暂无项目。添加一个项目文件夹以开始模糊测试。",
  "sidebar.removeTarget": "从最近列表中移除（保留数据）",

  // Header (screen titles)
  "title.dashboard": "仪表盘",
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
  "title.reports": "已生成报告",
  "title.runs": "运行历史",
  "title.audit": "策略审计",
  "title.agents": "智能体",
  "title.skills": "技能",
  "title.knowledge": "知识库",
  "title.automation": "自动化",
  "title.defectdojo": "DefectDojo",
  "title.help": "帮助与文档",

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
  "settings.tab.integrations": "集成",
  "settings.tab.issuetracker": "问题跟踪",
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

  // Dashboard readiness -- localized from the backend's stable state/blocker/
  // action codes (see workbench.rs). English intentionally has no entries here:
  // it falls back to the backend's own prose (with correct singular/plural).
  "readiness.state.persistence_required.headline": "需要初始化持久化",
  "readiness.state.persistence_required.detail": "在跟踪目标、测试桩、运行和崩溃之前，请先初始化持久化。",
  "readiness.state.persistence_required.badge": "需初始化",
  "readiness.state.setup_required.headline": "需要发现目标",
  "readiness.state.setup_required.detail": "在创建测试桩或活动之前，请先运行目标发现。",
  "readiness.state.setup_required.badge": "需发现",
  "readiness.state.harness_required.headline": "需要生成测试桩",
  "readiness.state.harness_required.detail": "为排名最高的目标生成一个在沙箱中构建的测试桩。",
  "readiness.state.harness_required.badge": "需测试桩",
  "readiness.state.review_required.headline": "需要审查测试桩",
  "readiness.state.review_required.detail": "在开展完整模糊测试活动之前，请先批准已生成的测试桩。",
  "readiness.state.review_required.badge": "需审查",
  "readiness.state.triage_required.headline": "需要分类崩溃",
  "readiness.state.triage_required.detail": "在扩大活动范围之前，请先分类新的崩溃。",
  "readiness.state.triage_required.badge": "需分类",
  "readiness.state.active.headline": "活动进行中",
  "readiness.state.active.detail": "监控正在进行的模糊测试活动，并及时审查新出现的发现。",
  "readiness.state.active.badge": "进行中",
  "readiness.state.campaign_ready.headline": "可开始冒烟活动",
  "readiness.state.campaign_ready.detail": "启动一次简短的沙箱模糊测试运行，以确立基线稳定性。",
  "readiness.state.campaign_ready.badge": "就绪",
  "readiness.state.ready.headline": "可开展更深入的活动",
  "readiness.state.ready.detail": "所选范围已具备目标、经审查的测试桩和活动历史。",
  "readiness.state.ready.badge": "就绪",
  "readiness.blocker.persistence": "持久化尚未初始化。",
  "readiness.blocker.no_targets": "尚未发现模糊测试目标。",
  "readiness.blocker.no_harnesses": "已发现的目标尚无生成的测试桩。",
  "readiness.blocker.harnesses_need_review": "{n} 个生成的测试桩需要人工批准。",
  "readiness.blocker.no_runs": "尚无模糊测试活动历史。",
  "readiness.blocker.crashes_need_triage": "{n} 个崩溃仍需分类。",
  "readiness.action.run_discovery": "在内部项目上运行目标发现。",
  "readiness.action.review_harnesses": "在完整模糊测试前审查 {n} 个生成的测试桩。",
  "readiness.action.triage_crashes": "分类最近一次运行中的 {n} 个崩溃。",
  "readiness.action.smoke_campaign": "为排名最高的目标安排一次简短的冒烟活动。",
  "readiness.action.none": "暂无紧急事项；可安排更深入的夜间活动。",
  "readiness.action.init_persistence": "初始化持久化以开始跟踪团队的模糊测试工作。",
  "readiness.action.select_project": "选择一个项目以查看其模糊测试工作台。",
};

// The curated inline dicts (nav/title/settings tabs/welcome) plus the
// per-view keys generated from the localized components (i18n.extra.ts).
// Inline keys win on any accidental overlap, keeping the hand-tuned wording.
const DICTS: Record<Locale, Dict> = {
  en: { ...enExtra, ...en },
  zh: { ...zhExtra, ...zh },
};

/** Values substituted into `{name}` placeholders in a translated string. */
export type TParams = Record<string, string | number>;

interface I18nContextValue {
  locale: Locale;
  setLocale: (l: Locale) => void;
  /**
   * Translate a key, falling back to English then the key itself. Optional
   * `params` replace `{name}` placeholders -- passing `{ n: 3 }` for a value of
   * "{n} items" yields "3 items".
   */
  t: (key: string, params?: TParams) => string;
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
    (key: string, params?: TParams) => {
      let s = DICTS[locale][key] ?? en[key] ?? key;
      if (params) {
        for (const [k, v] of Object.entries(params)) {
          s = s.split(`{${k}}`).join(String(v));
        }
      }
      return s;
    },
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
