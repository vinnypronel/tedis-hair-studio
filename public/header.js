// header.js
document.addEventListener("DOMContentLoaded", () => {
  fetch("header.html")
    .then(response => response.text())
    .then(data => {
      document.body.insertAdjacentHTML("afterbegin", data);
      initHeaderAuth();
      initCursorGlow();
    })
    .catch(err => console.error("Header load failed:", err));
});

// Initialize cursor glow effect
function initCursorGlow() {
  // Create cursor glow element
  const glow = document.createElement('div');
  glow.className = 'cursor-glow';
  // Ensure fixed position for perfect sync with viewport
  glow.style.position = 'fixed';
  document.body.appendChild(glow);

  const GLOW_SIZE = 250; // Smaller size
  const HALF_SIZE = GLOW_SIZE / 2;

  // Track target mouse position
  let mouseX = 0;
  let mouseY = 0;

  // Track current glow position
  let glowX = 0;
  let glowY = 0;

  document.addEventListener('mousemove', (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;

    if (!glow.classList.contains('active')) {
      glow.classList.add('active');
    }
  });

  // Smooth animation loop (lerp)
  function animateGlow() {
    // 0.1 = slow follow, 0.2 = medium, 1 = instant
    const ease = 0.15;

    glowX += (mouseX - glowX) * ease;
    glowY += (mouseY - glowY) * ease;

    const x = glowX - HALF_SIZE;
    const y = glowY - HALF_SIZE;

    glow.style.transform = `translate3d(${x}px, ${y}px, 0)`;
    requestAnimationFrame(animateGlow);
  }

  animateGlow();

  // Hide glow when mouse leaves window
  document.addEventListener('mouseleave', () => {
    glow.classList.remove('active');
  });
}

// Secret keyboard shortcut: Ctrl + Shift + A to access admin login
document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.shiftKey && e.key === 'A') {
    e.preventDefault();
    window.location.href = 'login.html';
  }
});

function initHeaderAuth() {
  const API_URL = 'http://localhost:3000/api';
  const loginBtn = document.getElementById('loginBtn');
  const accountDropdown = document.getElementById('accountDropdown');
  const accountBtn = document.getElementById('accountBtn');
  const navDropdown = document.getElementById('navDropdown');
  const navUsername = document.getElementById('navUsername');
  const logoutBtn = document.getElementById('logoutBtn');
  const brandText = document.getElementById('brandText');
  const brandLink = document.getElementById('brandLink');

  // ================= THEME TOGGLE =================
  const navActions = document.querySelector('.nav-actions');
  const themeBtn = document.createElement('button');
  themeBtn.className = 'nav-login-btn'; // Re-use styles
  themeBtn.style.marginRight = '8px';
  themeBtn.style.padding = '8px 10px';
  themeBtn.innerHTML = '🌙'; // Default icon
  themeBtn.title = "Toggle Light/Dark Mode";

  // Insert before login button (or account dropdown if logged in)
  if (navActions) {
    navActions.prepend(themeBtn);
  }

  function updateThemeIcon(theme) {
    themeBtn.innerHTML = theme === 'light' ? '☀️' : '🌙';
  }

  // Load saved theme
  const savedTheme = localStorage.getItem('theme') || 'dark';
  if (savedTheme === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
    updateThemeIcon('light');
  }

  themeBtn.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    const newTheme = current === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateThemeIcon(newTheme);
  });
  // ===============================================

  // Create dynamic admin links
  let dashboardLink, historyLink;
  if (navDropdown && logoutBtn) {
    // Check if they already exist to avoid duplicates if init runs twice
    if (!document.querySelector('a[href="admin.html"]')) {
      dashboardLink = document.createElement('a');
      dashboardLink.href = 'admin.html';
      dashboardLink.className = 'dropdown-item admin-only';
      dashboardLink.style.display = 'none';
      dashboardLink.textContent = 'Dashboard';
      navDropdown.insertBefore(dashboardLink, logoutBtn);
    }

    if (!document.querySelector('a[href="admin-history.html"]')) {
      historyLink = document.createElement('a');
      historyLink.href = 'admin-history.html';
      historyLink.className = 'dropdown-item admin-only';
      historyLink.style.display = 'none';
      historyLink.textContent = 'Haircut History';
      navDropdown.insertBefore(historyLink, logoutBtn);
    }
  }

  const token = localStorage.getItem('adminToken');
  const user = JSON.parse(localStorage.getItem('adminUser') || '{}');

  // Show/hide admin items and update brand for admin
  function setAdminMode(isAdmin) {
    // Re-query to include dynamic elements
    const adminOnlyItems = document.querySelectorAll('.admin-only');
    adminOnlyItems.forEach(item => {
      item.style.display = isAdmin ? 'flex' : 'none';
    });

    // Update brand text and link for admin
    if (brandText) {
      brandText.textContent = isAdmin ? "Tedi's Admin" : "Tedi's Hair Studio";
    }
    if (brandLink && isAdmin) {
      brandLink.href = 'admin.html';
    }
  }

  // Check if logged in
  if (token) {
    fetch(`${API_URL}/auth/verify`, {
      headers: { 'Authorization': `Bearer ${token}` }
    })
      .then(res => res.json())
      .then(data => {
        if (data.ok) {
          // Show account dropdown, hide login button
          loginBtn.style.display = 'none';
          accountDropdown.style.display = 'flex';
          navUsername.textContent = data.user.username || user.username || 'User';

          // Enable admin mode for admins
          setAdminMode(data.user.role === 'admin');

          // Update stored user data
          localStorage.setItem('adminUser', JSON.stringify(data.user));
        } else {
          // Token invalid, clear and hide login
          localStorage.removeItem('adminToken');
          localStorage.removeItem('adminUser');
          loginBtn.style.display = 'none';
          accountDropdown.style.display = 'none';
          setAdminMode(false);
        }
      })
      .catch(() => {
        // Network error, assume logged out - hide login button
        loginBtn.style.display = 'none';
        accountDropdown.style.display = 'none';
        setAdminMode(false);
      });
  } else {
    // Hide login button - access via Ctrl+Shift+A
    loginBtn.style.display = 'none';
    accountDropdown.style.display = 'none';
    setAdminMode(false);
  }

  // Toggle dropdown
  accountBtn?.addEventListener('click', (e) => {
    e.stopPropagation();
    navDropdown.classList.toggle('open');
    accountBtn.classList.toggle('active');
  });

  // Close dropdown when clicking outside
  document.addEventListener('click', () => {
    navDropdown?.classList.remove('open');
    accountBtn?.classList.remove('active');
  });

  // Logout handler
  logoutBtn?.addEventListener('click', async () => {
    try {
      await fetch(`${API_URL}/auth/logout`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
    } catch (e) {
      // Ignore errors
    }

    localStorage.removeItem('adminToken');
    localStorage.removeItem('adminUser');

    // Refresh page to show logged out state
    window.location.reload();
  });
}
