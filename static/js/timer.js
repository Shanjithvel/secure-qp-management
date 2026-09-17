/**
 * Time-Based Release Countdown & Lock Engine
 */

const timerInstances = {};

function startCountdown(elementId, releaseIsoTime, onUnlockCallback) {
  if (timerInstances[elementId]) {
    clearInterval(timerInstances[elementId]);
  }

  const targetDate = new Date(releaseIsoTime).getTime();

  function updateClock() {
    const el = document.getElementById(elementId);
    if (!el) return;

    const now = new Date().getTime();
    const diff = targetDate - now;

    if (diff <= 0) {
      clearInterval(timerInstances[elementId]);
      el.innerText = "00:00:00 (UNLOCKED)";
      const box = el.closest('.timer-box');
      if (box) box.classList.add('unlocked');
      if (onUnlockCallback) onUnlockCallback();
      return;
    }

    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((diff % (1000 * 60)) / 1000);

    const hStr = String(hours).padStart(2, '0');
    const mStr = String(minutes).padStart(2, '0');
    const sStr = String(seconds).padStart(2, '0');

    el.innerText = `${hStr}:${mStr}:${sStr}`;
  }

  updateClock();
  timerInstances[elementId] = setInterval(updateClock, 1000);
}
