import type { ProtectedValueDraft } from "../../lib/integrationSettings";
import { useI18n } from "../../i18nContext";
import { Button } from "../ui/Button";
import { Input, Textarea } from "../ui/Input";

export function ProtectedValueEditor({
  value,
  onChange,
  placeholder,
  secret = false,
  multiline = false,
}: {
  value: ProtectedValueDraft;
  onChange: (next: ProtectedValueDraft) => void;
  placeholder?: string;
  secret?: boolean;
  multiline?: boolean;
}) {
  const { t } = useI18n();

  if (value.change === "clear") {
    return (
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs" style={{ color: "var(--warning)" }}>
          {t("settings.protected.pendingClear")}
        </span>
        <Button size="sm" variant="ghost" onClick={() => onChange({ ...value, change: "keep", replacement: "" })}>
          {t("settings.protected.undo")}
        </Button>
      </div>
    );
  }

  if (value.change === "replace") {
    const common = {
      "aria-label": placeholder,
      autoComplete: secret ? "new-password" : undefined,
      mono: true,
      placeholder,
      spellCheck: secret ? false : undefined,
      value: value.replacement,
      onChange: (event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => onChange({
        ...value,
        replacement: event.target.value,
      }),
    };
    return (
      <div className="flex items-start gap-2 flex-wrap">
        <div className="w-[320px]">
          {multiline
            ? <Textarea {...common} rows={3} />
            : <Input {...common} type={secret ? "password" : "text"} />}
        </div>
        <Button size="sm" variant="ghost" onClick={() => onChange({ ...value, change: "keep", replacement: "" })}>
          {t("common.cancel")}
        </Button>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <span className="text-xs text-text-secondary">
        {value.current ?? (value.configured ? t("settings.protected.configured") : t("settings.protected.notConfigured"))}
      </span>
      <Button size="sm" variant="outline" onClick={() => onChange({
        ...value,
        change: "replace",
        replacement: value.current ?? "",
      })}>
        {value.configured ? t("settings.protected.replace") : t("settings.protected.set")}
      </Button>
      {value.configured && (
        <Button size="sm" variant="ghost" onClick={() => onChange({ ...value, change: "clear", replacement: "" })}>
          {t("common.clear")}
        </Button>
      )}
    </div>
  );
}
