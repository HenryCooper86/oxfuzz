import { Monitor, Moon, Sun } from "lucide-react";
import { useI18n } from "../i18nContext";
import type { Theme } from "../providers/prefs";
import { Button } from "./ui/Button";

const modes = {
  dark: { next: "light", label: "settings.general.themeDark", icon: Moon },
  light: { next: "system", label: "settings.general.themeLight", icon: Sun },
  system: { next: "dark", label: "settings.general.themeSystem", icon: Monitor },
} satisfies Record<Theme, { next: Theme; label: string; icon: typeof Moon }>;

export function ThemeButton({ theme, onChange }: { theme: Theme; onChange: (theme: Theme) => void }) {
  const { t } = useI18n();
  const { next, label, icon: Icon } = modes[theme];
  const description = `${t("settings.general.theme")}: ${t(label)} → ${t(modes[next].label)}`;
  return (
    <Button type="button" onClick={() => onChange(next)} title={description} aria-label={description}>
      <Icon size={16} aria-hidden="true" />
      {t(label)}
    </Button>
  );
}
