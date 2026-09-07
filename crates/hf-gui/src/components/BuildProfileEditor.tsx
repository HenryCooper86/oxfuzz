import { useState } from "react";
import { Button, Input } from "./ui";
import { useI18n } from "../i18nContext";
import type { BuildDependency, BuildProfileView, ProfileBuildSystem } from "../types";

interface ProfileFields {
  componentRoot: string;
  buildSystem: ProfileBuildSystem;
  compileDatabasePath: string;
  cmakeDefinitions: Record<string, string>;
  dependencies: BuildDependency[];
}

export function BuildProfileEditor({ profile, busy, onSave }: { profile: BuildProfileView | null; busy: boolean; onSave: (fields: ProfileFields) => Promise<void> }) {
  const { t } = useI18n();
  const [componentRoot, setComponentRoot] = useState(profile?.component_root ?? ".");
  const [buildSystem, setBuildSystem] = useState<ProfileBuildSystem>(profile?.build_system ?? "cmake");
  const [compileDatabasePath, setCompileDatabasePath] = useState(profile?.compile_database_path ?? "build/compile_commands.json");
  const [definitions, setDefinitions] = useState(() => Object.entries(profile?.cmake_definitions ?? {}).map(([name, value]) => ({ name, value })));
  const [dependencies, setDependencies] = useState<BuildDependency[]>(profile?.dependencies ?? []);
  const [error, setError] = useState<string | null>(null);

  function save() {
    if (new Set(definitions.map(({ name }) => name)).size !== definitions.length) {
      setError(t("buildDoctor.duplicateDefinition")); return;
    }
    setError(null);
    void onSave({ componentRoot, buildSystem, compileDatabasePath, cmakeDefinitions: Object.fromEntries(definitions.map(({ name, value }) => [name, value])), dependencies });
  }
  return <fieldset disabled={busy} className="mt-3 flex flex-col gap-2 text-xs">
    <legend>{t("buildDoctor.optionalProfile")}</legend>
    <label>{t("buildDoctor.component")}<Input className="block w-full" aria-label={t("buildDoctor.component")} value={componentRoot} onChange={(event) => setComponentRoot(event.target.value)} /></label>
    <label>{t("buildDoctor.buildSystem")}<select className="block rounded border border-border bg-surface-primary p-1" aria-label={t("buildDoctor.buildSystem")} value={buildSystem} onChange={(event) => setBuildSystem(event.target.value as ProfileBuildSystem)}><option value="cmake">CMake</option><option value="make">Make</option></select></label>
    <label>{t("buildDoctor.database")}<Input className="block w-full" aria-label={t("buildDoctor.database")} value={compileDatabasePath} onChange={(event) => setCompileDatabasePath(event.target.value)} /></label>
    {definitions.map((definition, index) => <div key={index} className="flex gap-2">
      <Input aria-label={t("buildDoctor.definitionName", { index: index + 1 })} value={definition.name} placeholder="BUILD_TESTING" onChange={(event) => setDefinitions((items) => items.map((item, i) => i === index ? { ...item, name: event.target.value } : item))} />
      <Input aria-label={t("buildDoctor.definitionValue", { index: index + 1 })} value={definition.value} placeholder="OFF" onChange={(event) => setDefinitions((items) => items.map((item, i) => i === index ? { ...item, value: event.target.value } : item))} />
      <Button size="sm" variant="outline" onClick={() => setDefinitions((items) => items.filter((_, i) => i !== index))}>{t("buildDoctor.remove")}</Button>
    </div>)}
    <Button size="sm" variant="outline" className="self-start" disabled={buildSystem !== "cmake"} onClick={() => setDefinitions((items) => [...items, { name: "", value: "" }])}>{t("buildDoctor.addDefinition")}</Button>
    {dependencies.map((dependency, index) => <div key={index} className="flex gap-2">
      <select className="rounded border border-border bg-surface-primary p-1" aria-label={t("buildDoctor.dependencyKind", { index: index + 1 })} value={dependency.kind} onChange={(event) => setDependencies((items) => items.map((item, i) => i === index ? { ...item, kind: event.target.value as BuildDependency["kind"] } : item))}><option value="command">{t("buildDoctor.command")}</option><option value="pkg_config">pkg-config</option></select>
      <Input aria-label={t("buildDoctor.dependencyName", { index: index + 1 })} value={dependency.name} onChange={(event) => setDependencies((items) => items.map((item, i) => i === index ? { ...item, name: event.target.value } : item))} />
      <Button size="sm" variant="outline" onClick={() => setDependencies((items) => items.filter((_, i) => i !== index))}>{t("buildDoctor.remove")}</Button>
    </div>)}
    <Button size="sm" variant="outline" className="self-start" onClick={() => setDependencies((items) => [...items, { kind: "command", name: "" }])}>{t("buildDoctor.addDependency")}</Button>
    {error && <p role="alert">{error}</p>}
    <Button size="sm" variant="primary" className="self-start" onClick={save}>{t("buildDoctor.saveProfile")}</Button>
  </fieldset>;
}
