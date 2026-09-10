import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { I18nProvider } from "../i18n";
import { KnowledgeIndexDetails } from "../components/KnowledgeIndexDetails";

it("distinguishes indexed settings from pending configuration and displays degradation", () => {
  const html = renderToStaticMarkup(<I18nProvider><KnowledgeIndexDetails status={{
    effective: { retrieval_strategy: "keyword", chunk_max_tokens: 23, embedding_model: null, embedding_dimensions: null },
    configured: { retrieval_strategy: "hybrid", chunk_max_tokens: 41, embedding_model: "new-model", embedding_dimensions: 2 },
    stale: true, warnings: ["Embedding request failed; using keyword retrieval"],
  }} /></I18nProvider>);
  expect(html).toContain("Indexed settings");
  expect(html).toContain("Configured settings");
  expect(html).toContain("23");
  expect(html).toContain("41");
  expect(html).toContain("new-model");
  expect(html).toContain("Index is stale");
  expect(html).toContain("Embedding request failed");
});
