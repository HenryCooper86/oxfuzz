import { enExtra, zhExtra } from "../i18n.extra";

// Existing label scanners inspect the exported dictionaries, independent of how
// their shared keys are stored. Each locale still contributes its actual entries.
export const extraTranslationDictionariesJson = JSON.stringify({ en: enExtra, zh: zhExtra }, null, 2);
