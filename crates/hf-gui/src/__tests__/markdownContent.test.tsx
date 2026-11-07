import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { MarkdownContent } from "../components/MarkdownContent";

it("keeps table cells from breaking inside words", () => {
  // The message body may break anywhere so long tokens never overflow, but in
  // a table that lets the layout shrink a column to one character: cells wrap
  // at word boundaries and the table scrolls sideways instead.
  const html = renderToStaticMarkup(
    <MarkdownContent text={"| Symbol | Fit |\n|---|---|\n| `handleData1` | 0.55 |"} />,
  );
  const cells = html.match(/<t[dh] [^>]*>/g) ?? [];
  expect(cells.length).toBe(4);
  for (const cell of cells) expect(cell).toContain("overflow-wrap:normal");
});
