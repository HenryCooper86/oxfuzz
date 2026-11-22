// Strings for the languages surfaces added for command-line parity.
export const enParityLanguages: Record<string, string> = {
  "parity.lang.engineDesc": "Drives {language} targets. Off by default: enable it to harness and fuzz {language} from the app.",
  "parity.lang.language": "Language",
  "parity.lang.auto": "Auto-detect",
  "parity.lang.fresh": "Start fresh (ignore the existing harness)",
  "parity.lang.sanitizer": "Sanitizer",
  "parity.lang.sanitizerDefault": "configured default",
  "parity.lang.cmplog": "Build the CmpLog companion (AFL++ only)",
  "parity.lang.skipModelReview": "Skip the model review (recorded in the audit trail; your approval is still required)",
  "parity.lang.engineDisabled": "{language} (enable {engine} in Settings)",
  "parity.lang.aboutLanguage": "{language} ({engine})",
};
export const zhParityLanguages: Record<string, string> = {
  "parity.lang.engineDesc": "用于 {language} 目标。默认关闭：启用后即可在应用内为 {language} 生成测试桩并进行模糊测试。",
  "parity.lang.language": "语言",
  "parity.lang.auto": "自动检测",
  "parity.lang.fresh": "重新开始（忽略已有测试桩）",
  "parity.lang.sanitizer": "Sanitizer",
  "parity.lang.sanitizerDefault": "已配置的默认值",
  "parity.lang.cmplog": "构建 CmpLog 伴随二进制（仅 AFL++）",
  "parity.lang.skipModelReview": "跳过模型审查（会记入审计记录；仍需你批准）",
  "parity.lang.engineDisabled": "{language}（请先在设置中启用 {engine}）",
  "parity.lang.aboutLanguage": "{language}（{engine}）",
};
