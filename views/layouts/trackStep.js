let stepStart = Date.now();

window.addEventListener("beforeunload", () => {
  const duration = Date.now() - stepStart;

  navigator.sendBeacon("/analytics/step-duration", JSON.stringify({
    step: window.currentStep, // set in each page
    path: window.location.pathname,
    durationMs: duration,
    timestamp: new Date().toISOString()
  }));
});
