/* =========================================================
   NetShield :: dashboard.js
   Shared front-end behaviour: live clock, lightweight polling
   of status endpoints, and Chart.js theme defaults so every
   chart across the app looks consistent without repeating
   config in each template.
   ========================================================= */

// ---- Live clock in the topbar --------------------------------------
function tickClock() {
  const el = document.getElementById("liveClock");
  if (!el) return;
  const now = new Date();
  el.textContent = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
setInterval(tickClock, 1000);
tickClock();

// ---- Chart.js shared theme ------------------------------------------
if (window.Chart) {
  Chart.defaults.color = "#8195A6";
  Chart.defaults.font.family = "'Inter', sans-serif";
  Chart.defaults.borderColor = "#21303D";
}

const NETSHIELD_COLORS = {
  accent: "#2DD4BF",
  accent2: "#5B8DEF",
  good: "#3FB950",
  warn: "#D29922",
  danger: "#F85149",
  critical: "#B855F0",
};

/**
 * Build a themed line chart for latency / time-series data.
 * ctx: canvas 2D context or element
 * datasets: [{label, data, color}]
 */
function buildLineChart(ctx, labels, datasets) {
  return new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: datasets.map((d) => ({
        label: d.label,
        data: d.data,
        borderColor: d.color,
        backgroundColor: d.color + "22",
        tension: 0.35,
        fill: true,
        pointRadius: 0,
        borderWidth: 2,
      })),
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { display: datasets.length > 1, labels: { boxWidth: 10, usePointStyle: true } } },
      scales: {
        x: { grid: { display: false }, ticks: { maxTicksLimit: 6 } },
        y: { grid: { color: "#1A252F" }, beginAtZero: true },
      },
    },
  });
}

/** Build a themed doughnut chart for status breakdowns. */
function buildDoughnutChart(ctx, labels, data, colors) {
  return new Chart(ctx, {
    type: "doughnut",
    data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 0 }] },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "70%",
      plugins: { legend: { position: "bottom", labels: { boxWidth: 10, usePointStyle: true, padding: 14 } } },
    },
  });
}

/** Build a themed bar chart. */
function buildBarChart(ctx, labels, data, colors) {
  return new Chart(ctx, {
    type: "bar",
    data: { labels, datasets: [{ data, backgroundColor: colors, borderRadius: 4, maxBarThickness: 34 }] },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false } },
        y: { grid: { color: "#1A252F" }, beginAtZero: true },
      },
    },
  });
}

// ---- Poll the lightweight status endpoint every 15s -----------------
async function refreshStatusChip() {
  try {
    const res = await fetch("/api/status");
    if (!res.ok) return;
    const data = await res.json();
    const chip = document.querySelector(".status-chip");
    if (chip) {
      chip.querySelector.length; // no-op guard
      chip.lastChild.textContent = " " + (data.system === "online" ? "System Online" : "System Degraded");
    }
  } catch (e) {
    /* network hiccup — keep last known status, no need to alarm the UI */
  }
}
setInterval(refreshStatusChip, 15000);
