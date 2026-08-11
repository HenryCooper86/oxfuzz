import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { FuzzingTab } from "../components/settings/FuzzingTab";
import { I18nContext } from "../i18nContext";

const RETIRED_ENGINE = ["cluster", "fuzz", "lite"].join("");
const RETIRED_ENGINE_ERROR =
  `fuzzing engine '${RETIRED_ENGINE}' has been retired; choose one of: afl++, honggfuzz, libfuzzer, syzkaller`;
const REPAIR_GUIDANCE = "Update it in RAW mode before saving.";

describe("FuzzingTab", () => {
  it("renders the exact retired-engine error separately from RAW repair guidance", () => {
    const onChange = vi.fn();
    const html = renderToStaticMarkup(
      <I18nContext.Provider
        value={{
          locale: "en",
          setLocale: () => undefined,
          t: () => REPAIR_GUIDANCE,
        }}
      >
        <FuzzingTab
          value={{
            fuzzing: {
              enabled_engines: [RETIRED_ENGINE],
              default_engine: RETIRED_ENGINE,
            },
          }}
          onChange={onChange}
        />
      </I18nContext.Provider>,
    );
    const alert = html.match(/<div[^>]*role="alert"[^>]*>([^<]*)<\/div>/);

    expect(alert?.[1]?.replaceAll("&#x27;", "'")).toBe(RETIRED_ENGINE_ERROR);
    expect(html).toContain(REPAIR_GUIDANCE);
    expect(html).toContain('aria-describedby="retired-engine-config-guidance"');
    expect(html).toContain('id="retired-engine-config-guidance"');
    expect(onChange).not.toHaveBeenCalled();
  });
});
