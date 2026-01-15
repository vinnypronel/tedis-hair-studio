// header.js
document.addEventListener("DOMContentLoaded", () => {
  fetch("header.html")
    .then(response => response.text())
    .then(data => {
      document.body.insertAdjacentHTML("afterbegin", data);
      initHeaderAuth();

    })
    .catch(err => console.error("Header load failed:", err));
});

// Inject click-spark.js
const script = document.createElement('script');
script.src = 'click-spark.js';
document.body.appendChild(script);

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

  // Create desktop toggle switch
  const desktopToggleWrapper = document.createElement('div');
  desktopToggleWrapper.className = 'nav-theme-toggle';
  desktopToggleWrapper.innerHTML = `
    <label class="theme-switch">
      <input type="checkbox" id="desktopThemeCheckbox">
      <span class="theme-slider"></span>
    </label>
  `;

  // Insert before hamburger button
  if (navActions) {
    navActions.prepend(desktopToggleWrapper);
  }

  const desktopCheckbox = document.getElementById('desktopThemeCheckbox');
  const mobileCheckbox = document.getElementById('mobileThemeCheckbox');

  // Function to update all toggle states
  function updateAllToggles(isDark) {
    if (desktopCheckbox) desktopCheckbox.checked = isDark;
    if (mobileCheckbox) mobileCheckbox.checked = isDark;
  }

  // Function to apply theme
  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    updateAllToggles(theme === 'dark');
  }

  // Load saved theme
  const savedTheme = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);
  updateAllToggles(savedTheme === 'dark');

  // Desktop toggle event
  desktopCheckbox?.addEventListener('change', () => {
    const newTheme = desktopCheckbox.checked ? 'dark' : 'light';
    applyTheme(newTheme);
  });

  // Mobile toggle event
  mobileCheckbox?.addEventListener('change', () => {
    const newTheme = mobileCheckbox.checked ? 'dark' : 'light';
    applyTheme(newTheme);
  });

  // ================= HAMBURGER MENU =================
  const hamburgerBtn = document.getElementById('hamburgerBtn');
  const mobileMenuOverlay = document.getElementById('mobileMenuOverlay');

  // Hamburger toggle
  hamburgerBtn?.addEventListener('click', () => {
    hamburgerBtn.classList.toggle('active');
    mobileMenuOverlay?.classList.toggle('open');
    // Prevent body scroll when menu is open
    document.body.style.overflow = mobileMenuOverlay?.classList.contains('open') ? 'hidden' : '';
  });

  // Close menu when clicking a link
  const mobileNavLinks = document.querySelectorAll('.mobile-nav-links a');
  mobileNavLinks.forEach(link => {
    link.addEventListener('click', () => {
      hamburgerBtn?.classList.remove('active');
      mobileMenuOverlay?.classList.remove('open');
      document.body.style.overflow = '';
    });
  });

  // Close menu on resize to desktop
  window.addEventListener('resize', () => {
    if (window.innerWidth > 1024) {
      hamburgerBtn?.classList.remove('active');
      mobileMenuOverlay?.classList.remove('open');
      document.body.style.overflow = '';
    }
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
