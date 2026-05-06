const root = document.documentElement;
const themeToggle = document.getElementById("themeToggle");
const navToggle = document.getElementById("navToggle");
const siteNav = document.getElementById("siteNav");

function applyTheme(theme) {
  root.setAttribute("data-theme", theme);
  if (themeToggle) {
    const isDark = theme === "dark";
    themeToggle.setAttribute("aria-pressed", String(isDark));
    themeToggle.setAttribute("aria-label", isDark ? "Switch to light mode" : "Switch to dark mode");
  }
}

if (themeToggle) {
  applyTheme(root.getAttribute("data-theme") || "dark");
  themeToggle.addEventListener("click", () => {
    const nextTheme = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    applyTheme(nextTheme);
    localStorage.setItem("cawasma-theme", nextTheme);
  });
}

if (navToggle && siteNav) {
  navToggle.addEventListener("click", () => {
    const isOpen = siteNav.classList.toggle("is-open");
    navToggle.setAttribute("aria-expanded", String(isOpen));
  });
}

document.querySelectorAll("[data-target-fill]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = document.getElementById("target_url");
    if (input) {
      input.value = button.dataset.targetFill || "";
      input.focus();
    }
  });
});

document.querySelectorAll("[data-finding-toggle]").forEach((button) => {
  button.addEventListener("click", () => {
    const card = button.closest("[data-finding-card]");
    if (!card) {
      return;
    }

    const isOpen = card.classList.toggle("is-open");
    button.setAttribute("aria-expanded", String(isOpen));
  });
});

document.querySelectorAll("[data-scan-row-toggle]").forEach((button) => {
  button.addEventListener("click", () => {
    const row = button.closest("[data-scan-row]");
    if (!row) {
      return;
    }

    const isExpanded = row.classList.toggle("is-expanded");
    button.setAttribute("aria-expanded", String(isExpanded));
    button.textContent = isExpanded ? "Show Less" : "Show More";
  });
});

const filterButtons = document.querySelectorAll("[data-filter]");
const findingCards = document.querySelectorAll("[data-finding-card]");
const searchInput = document.getElementById("findingSearch");

function syncFindings() {
  const activeFilter = document.querySelector("[data-filter].active")?.dataset.filter || "all";
  const searchTerm = (searchInput?.value || "").trim().toLowerCase();

  findingCards.forEach((card) => {
    const matchesFilter = activeFilter === "all" || card.dataset.severity === activeFilter;
    const haystack = card.dataset.search || "";
    const matchesSearch = !searchTerm || haystack.includes(searchTerm);
    card.classList.toggle("is-hidden", !(matchesFilter && matchesSearch));
  });
}

filterButtons.forEach((button) => {
  button.addEventListener("click", () => {
    filterButtons.forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    syncFindings();
  });
});

if (searchInput) {
  searchInput.addEventListener("input", syncFindings);
}

const fadeElements = document.querySelectorAll(".fade-up");
if ("IntersectionObserver" in window && fadeElements.length) {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.12 });

  fadeElements.forEach((element) => observer.observe(element));
} else {
  fadeElements.forEach((element) => element.classList.add("is-visible"));
}

syncFindings();
