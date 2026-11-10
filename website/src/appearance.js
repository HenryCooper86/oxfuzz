(() => {
  const modes = ["dark", "light", "system"];
  let preference = "system";
  try {
    const saved = localStorage.getItem("oxfuzz-theme");
    if (modes.includes(saved)) preference = saved;
  } catch {
    // Storage may be disabled; the theme still works for this visit.
  }
  const media = matchMedia("(prefers-color-scheme: dark)");
  const root = document.documentElement;
  let button;
  const label = (value) => value[0].toUpperCase() + value.slice(1);
  function render() {
    root.dataset.theme =
      preference === "system" ? (media.matches ? "dark" : "light") : preference;
    root.dataset.preference = preference;
    if (button) {
      const next = modes[(modes.indexOf(preference) + 1) % modes.length];
      const description = `Theme: ${label(preference)} → ${label(next)}`;
      button.setAttribute("aria-label", description);
      button.setAttribute("title", description);
    }
  }
  render();
  media.addEventListener("change", render);
  document.addEventListener("DOMContentLoaded", () => {
    button = document.getElementById("theme-toggle");
    button.hidden = false;
    button.addEventListener("click", () => {
      preference = modes[(modes.indexOf(preference) + 1) % modes.length];
      try {
        localStorage.setItem("oxfuzz-theme", preference);
      } catch {
        // A blocked storage write only prevents persistence between visits.
      }
      render();
    });
    render();
    const controls = [...document.querySelectorAll("[data-view]")];
    for (const control of controls) {
      control.addEventListener("click", () => {
        for (const item of controls) {
          const selected = item === control;
          item.setAttribute("aria-pressed", String(selected));
          document.getElementById(item.dataset.view).hidden = !selected;
        }
      });
    }
  });
})();
