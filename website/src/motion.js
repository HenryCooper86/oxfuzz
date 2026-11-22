// Motion is an enhancement. This script runs in the head so the "motion" class
// is set before first paint; without it (no script, or reduced motion asked
// for) every element is simply visible in its final state.
(() => {
  if (
    matchMedia("(prefers-reduced-motion: reduce)").matches ||
    !("IntersectionObserver" in window)
  )
    return;
  document.documentElement.classList.add("motion");

  const hex = () =>
    Math.floor(Math.random() * 256)
      .toString(16)
      .padStart(2, "0");

  // Replays the moment the page is about: inputs mutate, one of them crashes
  // the target, and the finding is written up.
  function fuzz(card) {
    const bytes = [...card.querySelectorAll(".fuzz-bytes b")];
    const crashing = bytes.map((byte) => byte.textContent);
    const status = card.querySelector(".fuzz-status");
    const counter = card.querySelector("[data-execs]");
    const total = Number(counter.textContent);
    const replay = card.querySelector("[data-replay]");
    const duration = 2600;
    let timer;
    function play() {
      clearInterval(timer);
      card.classList.remove("found");
      card.classList.add("fuzzing");
      status.textContent = status.dataset.running;
      const started = performance.now();
      timer = setInterval(() => {
        const progress = Math.min(1, (performance.now() - started) / duration);
        if (progress < 1) {
          for (const byte of bytes) byte.textContent = hex();
          counter.textContent = Math.round(total * progress * progress);
          return;
        }
        clearInterval(timer);
        bytes.forEach((byte, index) => {
          byte.textContent = crashing[index];
        });
        counter.textContent = total;
        status.textContent = status.dataset.found;
        card.classList.remove("fuzzing");
        card.classList.add("found");
      }, 70);
    }
    replay.hidden = false;
    replay.addEventListener("click", play);
    play();
  }

  // Plays a terminal recording: its lines appear at the times the transcript
  // gives them. The markup already holds every line, so a page without this
  // script shows the finished session.
  function terminal(figure, whenVisible) {
    const lines = [...figure.querySelectorAll(".term-line")];
    const replay = figure.querySelector("[data-term-replay]");
    let timers = [];
    function play() {
      for (const timer of timers) clearTimeout(timer);
      for (const line of lines) line.classList.add("pending");
      timers = lines.map((line, index) =>
        setTimeout(
          () => {
            line.classList.remove("pending");
            if (index === lines.length - 1) replay.hidden = false;
          },
          Number(line.dataset.at) * 1000,
        ),
      );
    }
    replay.addEventListener("click", play);
    whenVisible(figure, play);
  }

  document.addEventListener("DOMContentLoaded", () => {
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          entry.target.classList.add("in");
          observer.unobserve(entry.target);
        }
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.08 },
    );
    for (const element of document.querySelectorAll("[data-reveal]"))
      observer.observe(element);
    for (const card of document.querySelectorAll("[data-fuzz]")) fuzz(card);
    const starts = new Map();
    const screens = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          screens.unobserve(entry.target);
          starts.get(entry.target)();
        }
      },
      { threshold: 0.35 },
    );
    for (const figure of document.querySelectorAll("[data-term]"))
      terminal(figure, (target, play) => {
        starts.set(target, play);
        screens.observe(target);
      });
  });
})();
