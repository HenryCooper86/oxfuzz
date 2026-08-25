import { useState } from "react";
import { ScrollText } from "lucide-react";
import { Badge, Button, Input, Textarea } from "./ui";
import { getTransport } from "../lib";
import { useI18n } from "../i18nContext";
import type { OracleKind, OracleProperty, OracleScaffoldView } from "../types";

const KINDS: OracleKind[] = ["differential", "round_trip", "invariant"];

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
  const [description, setDescription] = useState("");
  const [view, setView] = useState<OracleScaffoldView | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function property(): OracleProperty {
    if (kind === "differential") return { kind: "differential", reference };
    if (kind === "round_trip") return { kind: "round_trip", encode, decode };
    return { kind: "invariant", predicate };
  }

  const ready =
    description.trim().length > 0 &&
    (kind === "differential"
      ? reference.trim().length > 0
      : kind === "round_trip"
        ? encode.trim().length > 0 && decode.trim().length > 0
        : predicate.trim().length > 0);

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
