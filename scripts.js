// Date & Clock
const dateDisplay = document.getElementById("dateDisplay");
const today = new Date();
const dateString = today.toLocaleDateString('vi-VN', {
  weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
});
dateDisplay.textContent = `Hôm nay: ${dateString}, ngày 17 tháng 7 2025`; // Cập nhật ngày mới

function updateClock() {
  const now = new Date();
  const timeString = now.toLocaleTimeString('vi-VN');
  document.getElementById("clock").textContent = `Bây giờ: ${timeString}`;
}
setInterval(updateClock, 1000);
updateClock();

// Popup Handling
const popup = document.getElementById('popup');
const music = document.getElementById('bg-music');
const closeBtn = document.getElementById('close-btn');
const fade = document.getElementById('fade');

closeBtn.addEventListener('click', function () {
  popup.classList.add('fade-out');
  fade.classList.add('active');
  setTimeout(() => {
    popup.style.display = 'none';
    fade.classList.remove('active');
    music.volume = 0.5;
    music.play();
    alert("Hãy bật âm lượng điện thoại để nghe nhạc to hơn!");
    startFireworks();
  }, 500);
});

// Fireworks
const canvas = document.getElementById("fireworks");
const ctx = canvas.getContext("2d");
let fireworks = [];
let particles = [];

function resizeCanvas() {
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
}
window.addEventListener("resize", resizeCanvas);
resizeCanvas();

function startFireworks() {
  setInterval(() => {
    for (let i = 0; i < 2; i++) {
      fireworks.push({
        x: Math.random() * canvas.width,
        y: canvas.height,
        vx: Math.random() * 2 - 1,
        vy: Math.random() * -10 - 5,
        size: Math.random() * 3 + 2,
        color: `hsl(${Math.random() * 360}, 100%, 50%)`,
        life: 100
      });
    }
  }, 300);

  animate();
}

function createParticles(x, y, color) {
  for (let i = 0; i < 20; i++) {
    particles.push({
      x: x,
      y: y,
      vx: (Math.random() * 4 - 2),
      vy: (Math.random() * 4 - 2),
      size: Math.random() * 2 + 1,
      color: color,
      life: 50
    });
  }
}

function animate() {
  ctx.fillStyle = "rgba(0, 0, 0, 0.05)";
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // Draw fireworks
  for (let i = fireworks.length - 1; i >= 0; i--) {
    let f = fireworks[i];
    ctx.beginPath();
    ctx.arc(f.x, f.y, f.size, 0, Math.PI * 2);
    ctx.fillStyle = f.color;
    ctx.fill();

    f.x += f.vx;
    f.y += f.vy;
    f.vy += 0.1; // Gravity
    f.life--;

    if (f.life <= 0) {
      createParticles(f.x, f.y, f.color);
      fireworks.splice(i, 1);
    }
  }

  // Draw particles
  for (let i = particles.length - 1; i >= 0; i--) {
    let p = particles[i];
    ctx.beginPath();
    ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
    ctx.fillStyle = p.color;
    ctx.fill();

    p.x += p.vx;
    p.y += p.vy;
    p.life--;
    p.size *= 0.98;

    if (p.life <= 0) particles.splice(i, 1);
  }

  requestAnimationFrame(animate);
}