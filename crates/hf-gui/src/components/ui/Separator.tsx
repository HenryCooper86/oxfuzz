export function Separator({ orientation = "horizontal" }: { orientation?: "horizontal" | "vertical" }) {
  return (
    <div
      style={{
        background: "var(--border)",
        width: orientation === "horizontal" ? "100%" : "1px",
        height: orientation === "horizontal" ? "1px" : "100%",
      }}
    />
  );
}