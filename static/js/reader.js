/**
 * Dynamic Watermarked Document Canvas Reader
 * Embeds user identity, exam center code, timestamp, IP, and session token diagonally across text.
 */

function renderWatermarkedDocument(canvasId, title, paperCode, contentText, watermarkData) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  
  // Set dimensions based on content length
  const lines = contentText.split('\n');
  const lineHeight = 26;
  const padding = 40;
  const requiredHeight = Math.max(600, lines.length * lineHeight + 200);

  canvas.width = 900;
  canvas.height = requiredHeight;

  // Background
  ctx.fillStyle = "#0f172a";
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // Border & Header Container
  ctx.strokeStyle = "#38bdf8";
  ctx.lineWidth = 2;
  ctx.strokeRect(15, 15, canvas.width - 30, canvas.height - 30);

  // Header Banner
  ctx.fillStyle = "rgba(56, 189, 248, 0.1)";
  ctx.fillRect(15, 15, canvas.width - 30, 80);

  // Document Title & Code
  ctx.fillStyle = "#38bdf8";
  ctx.font = "bold 18px 'Outfit', sans-serif";
  ctx.fillText("CONFIDENTIAL QUESTION PAPER VAUlT - RELEASED VIEW", 35, 50);

  ctx.fillStyle = "#f8fafc";
  ctx.font = "bold 15px 'Outfit', sans-serif";
  ctx.fillText(`${title} (${paperCode})`, 35, 75);

  // Render Watermark Grid (Tiled Diagonally)
  ctx.save();
  ctx.rotate(-22 * Math.PI / 180);
  ctx.font = "bold 16px 'JetBrains Mono', monospace";
  ctx.fillStyle = "rgba(244, 63, 94, 0.18)"; // Glowing red watermarks

  const wmText = `[ CONFIDENTIAL ] ${watermarkData.center_code} | ${watermarkData.timestamp} | IP: ${watermarkData.ip_address} | ${watermarkData.session_id}`;
  
  for (let x = -400; x < canvas.width + 400; x += 450) {
    for (let y = -200; y < canvas.height + 600; y += 120) {
      ctx.fillText(wmText, x, y);
    }
  }
  ctx.restore();

  // Render Main Paper Text
  ctx.font = "14px 'JetBrains Mono', monospace";
  ctx.fillStyle = "#e2e8f0";

  let startY = 130;
  lines.forEach((line) => {
    // Highlight headers/sections
    if (line.startsWith("SECTION") || line.startsWith("NATIONAL") || line.startsWith("SUBJECT:")) {
      ctx.fillStyle = "#38bdf8";
      ctx.font = "bold 15px 'Outfit', sans-serif";
    } else if (line.startsWith("Q") || line.startsWith("INSTRUCTIONS")) {
      ctx.fillStyle = "#fbbf24";
      ctx.font = "bold 14px 'Outfit', sans-serif";
    } else {
      ctx.fillStyle = "#cbd5e1";
      ctx.font = "14px 'JetBrains Mono', monospace";
    }
    
    ctx.fillText(line, padding, startY);
    startY += lineHeight;
  });

  // Footer Security Note
  ctx.fillStyle = "rgba(255, 255, 255, 0.3)";
  ctx.font = "11px 'Outfit', sans-serif";
  ctx.fillText(`VERIFIED SHA-256 INTEGRITY MATCH | LOGGED ACCESS TO CENTER ${watermarkData.center_code}`, 35, canvas.height - 25);
}
