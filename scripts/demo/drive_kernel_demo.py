#!/usr/bin/env python3
"""Drive the oxfuzz desktop app through a kernel campaign for the demo video.

Talks W3C WebDriver to tauri-driver (stdlib only). The caller starts Xvfb,
the screen recorder and tauri-driver; this script launches the app through
the driver, walks the Run view for a syzkaller campaign, approves the
campaign prompt (allowed for the demo test kernel only), waits for the run to
finish, and writes screenshots, page sources and a step log with timestamps
that the caption script turns into WebVTT cues.

Usage:
  drive_kernel_demo.py --app /usr/bin/oxfuzz --project DIR --kernel BZIMAGE \
      --rootfs ROOTFS --ssh-key KEY --duration-minutes 10 --out DIR
"""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DRIVER = "http://127.0.0.1:4444"
ELEMENT = "element-6066-11e4-a52e-4f735466cecc"


class WebDriverError(RuntimeError):
    pass


class Session:
    def __init__(self, app: str) -> None:
        body = {"capabilities": {"alwaysMatch": {"tauri:options": {"application": app}}}}
        value = self._call("POST", "/session", body)
        self.id = value["sessionId"]

    @staticmethod
    def _call(method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body if body is not None else {}).encode() if method == "POST" else None
        request = urllib.request.Request(DRIVER + path, data=data, method=method,
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                payload = json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            raise WebDriverError(f"{method} {path}: {error.code} {error.read()[:400]!r}") from None
        except (urllib.error.URLError, http.client.HTTPException, OSError) as error:
            raise WebDriverError(f"{method} {path}: {error}") from None
        return payload.get("value", payload) if path != "/session" else payload["value"]

    def call(self, method: str, path: str, body: dict | None = None):
        return self._call(method, f"/session/{self.id}{path}", body)

    def find_all(self, xpath: str) -> list[str]:
        found = self.call("POST", "/elements", {"using": "xpath", "value": xpath})
        # WebKitWebDriver may key the reference as ELEMENT rather than the
        # W3C name; each reference holds exactly one id either way.
        return [item.get(ELEMENT) or next(iter(item.values())) for item in found]

    def displayed(self, element: str) -> bool:
        try:
            return bool(self.call("GET", f"/element/{element}/displayed"))
        except WebDriverError:
            return False

    def wait(self, xpath: str, timeout: float = 30, visible: bool = True) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for element in self.find_all(xpath):
                if not visible or self.displayed(element):
                    return element
            time.sleep(0.4)
        raise WebDriverError(f"timed out waiting for {xpath}")

    def click(self, element: str) -> None:
        self.call("POST", f"/element/{element}/click")

    def type_into(self, element: str, text: str) -> None:
        self.call("POST", f"/element/{element}/clear")
        self.call("POST", f"/element/{element}/value", {"text": text})

    def script(self, source: str, *args):
        return self.call("POST", "/execute/sync", {"script": source, "args": list(args)})

    def screenshot(self, path: Path) -> None:
        path.write_bytes(base64.b64decode(self.call("GET", "/screenshot")))

    def source(self) -> str:
        return self.call("GET", "/source")

    def close(self) -> None:
        try:
            self.call("DELETE", "")
        except WebDriverError:
            pass


def text_match(text: str) -> str:
    """XPath predicate: an element's normalized text equals `text`."""
    return f"normalize-space(.)={json.dumps(text)}"


class Demo:
    def __init__(self, session: Session, out: Path) -> None:
        self.s = session
        self.out = out
        self.started = time.monotonic()
        self.steps: list[dict] = []
        self.shot = 0

    def step(self, name: str, caption: str) -> None:
        at = round(time.monotonic() - self.started, 1)
        self.steps.append({"at": at, "name": name, "caption": caption})
        print(f"[demo {at:7.1f}s] {name}: {caption}", flush=True)
        self.snapshot(name)

    def snapshot(self, name: str) -> None:
        self.shot += 1
        stem = self.out / f"{self.shot:02d}-{name}"
        try:
            self.s.screenshot(stem.with_suffix(".png"))
            stem.with_suffix(".html").write_text(self.s.source())
        except WebDriverError as error:
            print(f"snapshot {name} failed: {error}", file=sys.stderr)

    def save(self) -> None:
        (self.out / "steps.json").write_text(json.dumps(self.steps, indent=1))

    def button(self, *labels: str, timeout: float = 30) -> str:
        predicate = " or ".join(text_match(label) for label in labels)
        return self.s.wait(f"//button[{predicate}] | //*[@role='button' or @role='option' or @role='menuitem'][{predicate}]", timeout)

    def input_by_placeholder(self, placeholder: str) -> str:
        return self.s.wait(f"//input[@placeholder={json.dumps(placeholder)}]")

    def input_by_label(self, label: str) -> str:
        return self.s.wait(f"//input[@aria-label={json.dumps(label)}]")


def open_project(demo: Demo, project: str) -> None:
    """Open the project folder through the native GTK chooser, with a fallback."""
    s = demo.s
    s.click(demo.button("Projects"))
    time.sleep(1)
    demo.step("projects", "Projects: open the folder to fuzz")
    try:
        s.click(demo.button("Add project", "Open folder", "Open project", "Add folder", timeout=10))
        time.sleep(2)
        subprocess.run(["xdotool", "key", "--clearmodifiers", "ctrl+l"], check=True)
        time.sleep(0.5)
        subprocess.run(["xdotool", "type", "--delay", "40", project], check=True)
        time.sleep(0.5)
        subprocess.run(["xdotool", "key", "Return"], check=True)
        time.sleep(1.5)
        if s.find_all("//*[contains(@class,'surface')]") and project.rstrip("/").split("/")[-1] not in s.source():
            subprocess.run(["xdotool", "key", "Return"], check=False)
            time.sleep(1.5)
    except (WebDriverError, subprocess.CalledProcessError) as error:
        print(f"native chooser path failed ({error}); using the recents fallback", file=sys.stderr)
    if project.rstrip("/").split("/")[-1] not in s.source():
        s.script(
            "localStorage.setItem('hf_recent_projects', JSON.stringify([arguments[0]]));"
            "localStorage.setItem('hf_active_project', arguments[0]); location.reload();",
            project,
        )
        time.sleep(4)
    demo.step("project-open", f"Project opened: {project.rstrip('/').split('/')[-1]}")


def configure_campaign(demo: Demo, args: argparse.Namespace) -> None:
    s = demo.s
    s.click(demo.button("Run", "Fuzz"))
    time.sleep(1.5)
    demo.step("run-view", "Run view: choose the engine")
    s.click(s.wait("//button[@aria-label='Engine'] | //*[@role='combobox'][@aria-label='Engine']"))
    time.sleep(0.8)
    s.click(s.wait("//*[@role='option'][contains(normalize-space(.), 'syzkaller')]"))
    time.sleep(1)
    demo.step("engine", "syzkaller selected: the form asks for the kernel artifacts")
    for placeholder, value in (("/path/to/bzImage", args.kernel), ("/path/to/rootfs.img", args.rootfs),
                               ("/path/to/id_rsa", args.ssh_key)):
        s.type_into(demo.input_by_placeholder(placeholder), value)
        time.sleep(0.6)
    s.type_into(s.wait("//input[@type='number'][@aria-label='VMs' or @aria-label='VM count' or "
                       "contains(@aria-label,'VM')]"), "1")
    duration = s.find_all("//input[contains(@aria-label,'uration')]")
    if duration:
        s.type_into(duration[0], f"{args.duration_minutes}m")
    time.sleep(1)
    demo.step("artifacts", "Kernel image, Debian rootfs and SSH key filled in; one VM")


def launch_and_approve(demo: Demo) -> None:
    s = demo.s
    s.script("window.scrollTo(0, document.body.scrollHeight);"
             "document.querySelectorAll('main, [data-scroll]').forEach(e => e.scrollTop = e.scrollHeight);")
    time.sleep(1)
    demo.step("summary", "Campaign summary before launch: budget, CPU and memory limits")
    s.click(demo.button("Launch Campaign"))
    time.sleep(1.5)
    try:
        s.wait("//*[contains(normalize-space(.), 'needs your approval')]", timeout=20)
        demo.step("approval", "oxfuzz asks for approval before the campaign starts")
        time.sleep(2)
        s.click(s.wait("//*[@id='approval-prompt-title']/ancestor::*[.//button][1]//button[normalize-space(.)='Approve']"))
        demo.step("approved", "Approved: the campaign starts in the sandbox with /dev/kvm")
    except WebDriverError:
        demo.step("no-approval", "The campaign started without a separate approval prompt")


def wait_for_campaign(demo: Demo, minutes: int) -> bool:
    """Leave the app alone while the campaign runs; the screen recorder keeps
    capturing. Fetching the page source on a timer made WebKitWebDriver drop
    the session once the live log grew, so this only scrolls the live stats
    into view, sleeps, and polls one cheap lookup near the end. Returns False
    when the driver session is gone (the recording is still usable)."""
    s = demo.s
    try:
        s.script("const b = [...document.querySelectorAll('button')]"
                 ".find(e => e.textContent.trim() === 'Stop');"
                 "if (b) b.scrollIntoView({block: 'start'});")
        time.sleep(20)
        demo.step("running", "The campaign is running under KVM; live stats and the manager log update")
    except WebDriverError as error:
        print(f"could not scroll to the live stats: {error}", file=sys.stderr)
    time.sleep(max(minutes * 60 - 60, 0))
    deadline = time.monotonic() + 900
    failures = 0
    while time.monotonic() < deadline:
        try:
            if not s.find_all("//button[starts-with(normalize-space(.), 'Running')]"):
                break
            failures = 0
        except WebDriverError as error:
            failures += 1
            print(f"poll failed ({failures}): {error}", file=sys.stderr)
            if failures >= 3:
                return False
        time.sleep(15)
    time.sleep(5)
    try:
        s.script("const b = [...document.querySelectorAll('button')]"
                 ".find(e => e.textContent.includes('Launch Campaign'));"
                 "if (b) b.scrollIntoView({block: 'start'});")
        time.sleep(3)
        demo.step("finished", "Campaign finished: executions, corpus and coverage are recorded")
    except WebDriverError as error:
        print(f"could not show the result: {error}", file=sys.stderr)
        return False
    return True


def show_results(demo: Demo) -> None:
    s = demo.s
    for label, caption in (("Runs", "Runs: the kernel campaign is in the run history"),
                           ("Dashboard", "Dashboard after the campaign")):
        try:
            s.click(demo.button(label, timeout=10))
            time.sleep(3)
            demo.step(label.lower(), caption)
        except WebDriverError as error:
            print(f"could not open {label}: {error}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser()
    for flag in ("--app", "--project", "--kernel", "--rootfs", "--ssh-key", "--out"):
        parser.add_argument(flag, required=True)
    parser.add_argument("--duration-minutes", type=int, default=10)
    parser.add_argument("--ui-only", action="store_true",
                        help="stop after the summary screenshot, without launching")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    session = Session(args.app)
    demo = Demo(session, out)
    try:
        session.wait("//body", timeout=60)
        time.sleep(3)
        session.script("localStorage.setItem('hf_setup_completed', 'true');"
                       "localStorage.removeItem('hf_setup_deferred'); location.reload();")
        time.sleep(5)
        demo.step("start", "oxfuzz desktop app on Linux x86_64 (GitHub-hosted runner with KVM)")
        open_project(demo, args.project)
        configure_campaign(demo, args)
        if args.ui_only:
            demo.step("ui-only", "UI-only pass: stopping before launch")
            return 0
        launch_and_approve(demo)
        if wait_for_campaign(demo, args.duration_minutes):
            show_results(demo)
        else:
            # Keep recording until the campaign's budget has surely ended.
            time.sleep(120)
        return 0
    except WebDriverError as error:
        print(f"demo failed: {error}", file=sys.stderr)
        demo.snapshot("failure")
        return 1
    finally:
        demo.save()
        session.close()


if __name__ == "__main__":
    sys.exit(main())
