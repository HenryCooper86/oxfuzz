// ObjectForm -- a generic, introspective settings form driven by a parsed
// config object. Renders one control per top-level key (string -> text,
// number -> number, boolean -> toggle, primitive array -> comma-separated,
// nested table -> a labeled sub-group). Used for Session and Tools, and as a
// fallback for any config-backed section without a bespoke form.
//
// Unknown / non-editable shapes (e.g. arrays of tables) are preserved untouched
// because every patch spreads the existing object and only replaces one key.

import { SlidersHorizontal } from "lucide-react";
import { Input } from "../ui/Input";
import { Switch } from "../ui/Switch";
import { EmptyState } from "../ui";
import { SettingsGroup, SettingsItem } from "../ui/SettingsGroup";
import { useI18n } from "../../i18nContext";
import { isSecretFieldName } from "../../lib/secretFields";

type Cfg = Record<string, unknown>;

function humanize(key: string): string {
  return key
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function isPlainObject(v: unknown): v is Cfg {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isPrimitiveArray(v: unknown): v is unknown[] {
  return Array.isArray(v) && v.every((x) => typeof x === "string" || typeof x === "number" || typeof x === "boolean");
}

function Field({ name, label, value, onSet }: { name: string; label: string; value: unknown; onSet: (v: unknown) => void }) {
  const { t } = useI18n();
  if (typeof value === "boolean") {
    return (
      <SettingsItem title={label}>
        <Switch checked={value} onChange={onSet} ariaLabel={label} />
      </SettingsItem>
    );
  }
  if (typeof value === "number") {
    return (
      <SettingsItem title={label}>
        <div style={{ width: 140 }}>
          <Input aria-label={label} type="number" value={value} onChange={(e) => onSet(e.target.value === "" ? 0 : Number(e.target.value))} />
        </div>
      </SettingsItem>
    );
  }
  if (isPrimitiveArray(value)) {
    return (
      <SettingsItem title={label} description={t("settings.objectForm.commaSeparated")}>
        <div style={{ width: 260 }}>
          <Input
            aria-label={label}
            mono
            value={(value as unknown[]).join(", ")}
            onChange={(e) => onSet(e.target.value.split(",").map((s) => s.trim()).filter(Boolean))}
          />
        </div>
      </SettingsItem>
    );
  }
  // A nested object/array-of-tables has no simple control; surface it read-only
  // (with a hint to edit in RAW) instead of rendering a useless "[object Object]".
  if (typeof value === "object" && value !== null) {
    return (
      <SettingsItem title={label} description={t("settings.objectForm.nestedConfig")}>
        <span className="text-xs text-text-muted font-mono">{Array.isArray(value) ? "[…]" : "{…}"}</span>
      </SettingsItem>
    );
  }
  // string (and any other scalar fallback rendered as text)
  return (
    <SettingsItem title={label}>
      <div style={{ width: 260 }}>
        <Input
          aria-label={label}
          autoComplete={isSecretFieldName(name) ? "new-password" : undefined}
          mono
          spellCheck={isSecretFieldName(name) ? false : undefined}
          type={isSecretFieldName(name) ? "password" : "text"}
          value={value == null ? "" : String(value)}
          onChange={(e) => onSet(e.target.value)}
        />
      </div>
    </SettingsItem>
  );
}

export function ObjectForm({ value, onChange }: { value: Cfg; onChange: (next: Cfg) => void }) {
  const { t } = useI18n();
  const entries = Object.entries(value);
  const scalars = entries.filter(([, v]) => !isPlainObject(v));
  const tables = entries.filter(([, v]) => isPlainObject(v)) as [string, Cfg][];

  if (entries.length === 0) {
    return (
      <EmptyState
        icon={<SlidersHorizontal size={20} />}
        title={t("settings.objectForm.emptyTitle")}
        hint={t("settings.objectForm.emptyHint")}
      />
    );
  }

  function setKey(key: string, v: unknown) {
    onChange({ ...value, [key]: v });
  }
  function setTableKey(table: string, key: string, v: unknown) {
    const cur = (value[table] as Cfg) ?? {};
    onChange({ ...value, [table]: { ...cur, [key]: v } });
  }

  return (
    <div>
      {scalars.length > 0 && (
        <SettingsGroup title={t("settings.objectForm.settings")}>
          {scalars.map(([key, v]) => (
            <Field key={key} name={key} label={humanize(key)} value={v} onSet={(nv) => setKey(key, nv)} />
          ))}
        </SettingsGroup>
      )}
      {tables.map(([table, obj]) => (
        <SettingsGroup key={table} title={humanize(table)}>
          {Object.entries(obj).map(([key, v]) => (
            <Field key={key} name={key} label={humanize(key)} value={v} onSet={(nv) => setTableKey(table, key, nv)} />
          ))}
        </SettingsGroup>
      ))}
    </div>
  );
}
