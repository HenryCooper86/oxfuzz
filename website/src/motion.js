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
  });
})();
