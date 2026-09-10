import { useEffect, useRef, useState } from "react";
import { useI18n } from "../../i18nContext";
import { Button } from "../ui/Button";
import { ProviderSetup } from "./ProviderSetup";
import { SandboxSetup } from "./SandboxSetup";

export type SetupOutcome = "complete" | "deferred";
const steps = ["connection", "sandbox", "start"] as const;

export function SetupWizard({ onComplete }: { onComplete: (outcome: SetupOutcome) => void }) {
  const { t } = useI18n();
  const [step, setStep] = useState(0);
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { heading.current?.focus(); }, [step]);
  return <div className="flex min-h-0 h-full w-full items-center justify-center bg-surface-tertiary p-4">
    <section className="surface-card flex flex-col gap-4 w-full max-w-xl overflow-y-auto p-6" style={{ maxHeight: "calc(100vh - 32px)" }} aria-labelledby="setup-title">
      <header><h1 id="setup-title" className="m-0 text-lg font-semibold">{t("setup.title")}</h1><p className="mt-1 mb-0 text-sm text-text-secondary">{t("setup.subtitle")}</p></header>
      <ol aria-label={t("setup.steps")} className="m-0 p-0 list-none flex flex-wrap gap-3 text-sm">
        {steps.map((name, index) => <li key={name} aria-current={index === step ? "step" : undefined} className={index === step ? "font-semibold text-text-primary" : "text-text-secondary"}>{index + 1}. {t(`setup.${name}`)}</li>)}
      </ol>
      <h2 ref={heading} tabIndex={-1} className="m-0 text-base font-semibold">{t(`setup.${steps[step]}`)}</h2>
      {step === 0 && <ProviderSetup onContinue={() => setStep(1)} />}
      {step === 1 && <SandboxSetup onContinue={() => setStep(2)} />}
      {step === 2 && <div className="flex flex-col gap-4">
        <p className="m-0 text-sm">{t("setup.startHint")}</p>
        <p className="m-0 text-sm text-text-secondary">{t("setup.approvalHint")}</p>
        <p className="m-0 text-sm text-text-secondary">{t("setup.integrationsLater")}</p>
        <Button variant="primary" onClick={() => onComplete("complete")}>{t("setup.openWorkflow")}</Button>
      </div>}
      <footer className="flex flex-wrap justify-between gap-2 border-t border-border pt-3">
        <Button variant="ghost" disabled={step === 0} onClick={() => setStep(value => value - 1)}>{t("common.back")}</Button>
        <Button variant="ghost" onClick={() => onComplete("deferred")}>{t("setup.later")}</Button>
      </footer>
    </section>
  </div>;
}
