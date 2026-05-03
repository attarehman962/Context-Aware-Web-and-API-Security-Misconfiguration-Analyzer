document.addEventListener("DOMContentLoaded", () => {
  const cards = document.querySelectorAll(".panel, .scan-card");
  cards.forEach((card, index) => {
    card.animate(
      [{ opacity: 0, transform: "translateY(12px)" }, { opacity: 1, transform: "translateY(0)" }],
      { duration: 300 + index * 30, easing: "ease-out", fill: "both" },
    );
  });
});
