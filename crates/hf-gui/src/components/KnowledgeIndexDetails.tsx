import { useI18n } from "../i18nContext";

interface KnowledgeConfiguration {
  retrieval_strategy: string;
  chunk_max_tokens: number;
  embedding_model: string | null;
  embedding_dimensions: number | null;
}
export interface KnowledgeIndexDetailsStatus {
  effective: KnowledgeConfiguration | null;
  configured: KnowledgeConfiguration;
  stale: boolean | null;
  warnings: string[];
}
export function KnowledgeIndexDetails({ status }: { status: KnowledgeIndexDetailsStatus }) {
  const { t } = useI18n();
  const describe = (config: KnowledgeConfiguration) => t("knowledge.configuration", {
    strategy: config.retrieval_strategy, tokens: config.chunk_max_tokens,
    model: config.embedding_model ?? t("knowledge.noEmbedding"),
  });
  return <div className="text-xs flex flex-col gap-1">
    {status.effective ? <p className="m-0">{t("knowledge.indexedSettings")}: {describe(status.effective)}</p> : null}
    <p className="m-0 text-text-muted">{t("knowledge.configuredSettings")}: {describe(status.configured)}</p>
    {status.effective ? <p className="m-0" role="status">{t(status.stale === true ? "knowledge.stale" : status.stale === false ? "knowledge.current" : "knowledge.freshnessUnavailable")}</p> : null}
    {status.warnings.length ? <ul role="status" className="m-0 pl-4">{status.warnings.map(warning => <li key={warning}>{warning}</li>)}</ul> : null}
  </div>;
}
