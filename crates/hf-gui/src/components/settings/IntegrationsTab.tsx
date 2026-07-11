// Integrations settings -- external systems hobot_fuzz can push findings to.
//
// Currently DefectDojo: the section is config-backed (config/defectdojo.toml),
// so the orchestrator handles load/save via the generic ObjectForm. This tab
// adds context plus a "Test connection" button that validates the *saved* URL +
// token against the live DefectDojo API.

import { useState } from "react";
import { getTransport } from "../../lib";
import { Button } from "../ui/Button";
import { ObjectForm } from "./ObjectForm";

type Cfg = Record<string, unknown>;

export function IntegrationsTab({ value, onChange }: { value: Cfg; onChange: (next: Cfg) => void }) {
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; msg: string } | null>(null);

  async function testConnection() {
    setTesting(true);
    setResult(null);
    try {
      await getTransport().invoke("defectdojo_test_connection");
      setResult({ ok: true, msg: "Connected to DefectDojo successfully." });
    } catch (e) {
      setResult({ ok: false, msg: String(e) });
    } finally {
      setTesting(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="text-text-secondary" style={{ fontSize: "13px", lineHeight: 1.6 }}>
        <p>
          Push triaged crashes to <strong>DefectDojo</strong> as findings. Set the instance{" "}
          <code>url</code>, then provide the API v2 token one of two ways: paste it into{" "}
          <code>api_token</code> (stored with your desktop settings, like a provider key), or set{" "}
          <code>api_token_env</code> to the NAME of an environment variable that holds it and export
          that variable (preferred for CLI/CI so the secret stays out of the config file). A direct{" "}
          <code>api_token</code> takes priority. Repeat pushes use reimport-scan, so re-found crashes
          update in place instead of duplicating.
        </p>
      </div>

      <ObjectForm value={value} onChange={onChange} />

      <div className="flex items-center gap-3 flex-wrap">
        <Button
          variant="outline"
          size="sm"
          onClick={() => void testConnection()}
          loading={testing}
          disabled={testing}
        >
          Test connection
        </Button>
        {result && (
          <span
            role="status"
            style={{
              fontSize: "12px",
              color: result.ok ? "var(--success, #10b981)" : "var(--danger, #ef4444)",
            }}
          >
            {result.msg}
          </span>
        )}
      </div>
      <p className="text-text-muted" style={{ fontSize: "11px" }}>
        Test uses the last <strong>saved</strong> settings -- save your changes first.
      </p>
    </div>
  );
}
