import { useState } from "react";
import { ScrollText } from "lucide-react";
import { Badge, Button, Input, Textarea } from "./ui";
import { getTransport } from "../lib";
import { useI18n } from "../i18nContext";
import type {
  MetamorphicRelation,
  OracleKind,
  OracleProperty,
  OracleScaffoldView,
} from "../types";

const KINDS: OracleKind[] = [
  "differential",
  "round_trip",
  "invariant",
  "metamorphic",
  "stateful",
  "resource",
];

const RELATIONS: MetamorphicRelation[] = ["equal", "not_less", "not_greater"];

/// Mirrors the service bounds; the service revalidates.
const DEFAULT_STEPS = 32;
const DEFAULT_GROWTH = 4096;

/// A nil UUID until the operator saves the oracle; the service assigns
/// identity, and the scaffold records whatever id it was given.
const DRAFT_ID = "00000000-0000-0000-0000-000000000000";

export function OracleStudioPanel({ target }: { target: string }) {
  const { t } = useI18n();
  const [kind, setKind] = useState<OracleKind>("differential");
  const [reference, setReference] = useState("");
  const [encode, setEncode] = useState("");
  const [decode, setDecode] = useState("");
  const [predicate, setPredicate] = useState("");
  const [transform, setTransform] = useState("");
  const [relation, setRelation] = useState<MetamorphicRelation>("equal");
  const [apply, setApply] = useState("");
  const [check, setCheck] = useState("");
  const [maxSteps, setMaxSteps] = useState(DEFAULT_STEPS);
  const [measure, setMeasure] = useState("");
  const [maxGrowth, setMaxGrowth] = useState(DEFAULT_GROWTH);
  const [description, setDescription] = useState("");
  const [view, setView] = useState<OracleScaffoldView | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function property(): OracleProperty {
    switch (kind) {
      case "differential":
        return { kind: "differential", reference };
      case "round_trip":
        return { kind: "round_trip", encode, decode };
      case "invariant":
        return { kind: "invariant", predicate };
      case "metamorphic":
        return { kind: "metamorphic", transform, relation };
      case "stateful":
        return { kind: "stateful", apply, check, max_steps: maxSteps };
      case "resource":
        return { kind: "resource", measure, max_growth: maxGrowth };
    }
  }

  function symbolsGiven(): boolean {
    switch (kind) {
      case "differential":
        return reference.trim().length > 0;
      case "round_trip":
        return encode.trim().length > 0 && decode.trim().length > 0;
      case "invariant":
        return predicate.trim().length > 0;
      case "metamorphic":
        return transform.trim().length > 0;
      case "stateful":
        return apply.trim().length > 0 && check.trim().length > 0;
      case "resource":
        return measure.trim().length > 0;
    }
  }

  const ready = description.trim().length > 0 && symbolsGiven();

  async function render() {
    setBusy(true);
    setError(null);
    try {
      const result = await getTransport().invoke<OracleScaffoldView>("oracle_scaffold", {
        spec: {
          id: DRAFT_ID,
          target_symbol: target,
          property: property(),
          description,
        },
      });
      setView(result);
    } catch (e) {
      setView(null);
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section
      className="rounded-md border border-border"
      style={{ padding: "var(--space-sm)", background: "var(--surface-code)" }}
    >
      <div className="flex items-center gap-2 text-xs font-semibold">
        <ScrollText size={14} style={{ color: "var(--accent)" }} />
        {t("oracleStudio.title")}
      </div>
      <p className="text-xs text-text-muted mt-1">{t("oracleStudio.advisory")}</p>

      <div className="flex flex-wrap items-center gap-2 mt-3">
        {KINDS.map((option) => (
          <Button
            key={option}
            variant={option === kind ? "primary" : "outline"}
            size="sm"
            onClick={() => {
              setKind(option);
              setView(null);
            }}
          >
            {t(`oracleStudio.kind.${option}`)}
          </Button>
        ))}
      </div>
      <p className="text-xs text-text-muted mt-2">{t(`oracleStudio.help.${kind}`)}</p>

      <div className="flex flex-col gap-2 mt-2">
        {kind === "differential" && (
          <Input
            mono
            placeholder={t("oracleStudio.reference")}
            value={reference}
            onChange={(event) => setReference(event.target.value)}
          />
        )}
        {kind === "round_trip" && (
          <>
            <Input
              mono
              placeholder={t("oracleStudio.encode")}
              value={encode}
              onChange={(event) => setEncode(event.target.value)}
            />
            <Input
              mono
              placeholder={t("oracleStudio.decode")}
              value={decode}
              onChange={(event) => setDecode(event.target.value)}
            />
          </>
        )}
        {kind === "invariant" && (
          <Input
            mono
            placeholder={t("oracleStudio.predicate")}
            value={predicate}
            onChange={(event) => setPredicate(event.target.value)}
          />
        )}
        {kind === "metamorphic" && (
          <>
            <Input
              mono
              placeholder={t("oracleStudio.transform")}
              value={transform}
              onChange={(event) => setTransform(event.target.value)}
            />
            {/* The relation is chosen from a closed vocabulary, never typed as
                an expression that would be interpolated into the harness. */}
            <div className="flex flex-wrap items-center gap-2">
              {RELATIONS.map((option) => (
                <Button
                  key={option}
                  variant={option === relation ? "primary" : "outline"}
                  size="sm"
                  onClick={() => setRelation(option)}
                >
                  {t(`oracleStudio.relation.${option}`)}
                </Button>
              ))}
            </div>
          </>
        )}
        {kind === "stateful" && (
          <>
            <Input
              mono
              placeholder={t("oracleStudio.apply")}
              value={apply}
              onChange={(event) => setApply(event.target.value)}
            />
            <Input
              mono
              placeholder={t("oracleStudio.check")}
              value={check}
              onChange={(event) => setCheck(event.target.value)}
            />
            <label className="flex items-center gap-2 text-xs text-text-secondary">
              {t("oracleStudio.maxSteps")}
              <input
                type="number"
                min={1}
                max={256}
                value={maxSteps}
                onChange={(event) => setMaxSteps(Number(event.target.value))}
                className="w-24 px-2 py-1 text-11px border border-solid border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface-primary)] text-text-primary outline-none"
              />
            </label>
          </>
        )}
        {kind === "resource" && (
          <>
            <Input
              mono
              placeholder={t("oracleStudio.measure")}
              value={measure}
              onChange={(event) => setMeasure(event.target.value)}
            />
            <label className="flex items-center gap-2 text-xs text-text-secondary">
              {t("oracleStudio.maxGrowth")}
              <input
                type="number"
                min={1}
                value={maxGrowth}
                onChange={(event) => setMaxGrowth(Number(event.target.value))}
                className="w-32 px-2 py-1 text-11px border border-solid border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface-primary)] text-text-primary outline-none"
              />
            </label>
          </>
        )}
        <Textarea
          rows={2}
          placeholder={t("oracleStudio.description")}
          value={description}
          onChange={(event) => setDescription(event.target.value)}
        />
        <Button
          variant="outline"
          size="sm"
          className="self-start"
          loading={busy}
          disabled={!ready || !target}
          onClick={() => void render()}
        >
          {t("oracleStudio.render")}
        </Button>
      </div>

      {view && (
        <div className="flex flex-col gap-2 mt-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-medium text-text-secondary mr-auto">
              {t("oracleStudio.scaffold")}
            </span>
            {view.blocking_lint && (
              <Badge variant="error">{t("oracleStudio.blockingLint")}</Badge>
            )}
          </div>
          <p className="text-xs text-text-muted">{t("oracleStudio.reviewNotice")}</p>
          <pre
            className="text-xs font-mono"
            style={{
              background: "var(--surface-primary)",
              padding: "var(--space-sm)",
              borderRadius: "var(--radius-sm)",
              overflowX: "auto",
              maxHeight: "24rem",
            }}
          >
            {view.source}
          </pre>
          {view.lint.length > 0 && (
            <div className="flex flex-col gap-1">
              {view.lint.map((finding) => (
                <span key={finding} className="text-xs text-text-muted font-mono">
                  {finding}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {error && <p className="text-xs mt-2" style={{ color: "var(--error)" }}>{error}</p>}
    </section>
  );
}
