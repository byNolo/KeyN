// KeyN Theme Management System

class ThemeManager {
  constructor() {
    this.init();
  }

  init() {
    // Get current theme from data attribute (already set by inline script)
    const currentTheme = document.documentElement.getAttribute('data-theme');
    this.currentTheme = currentTheme || 'light';
    
    // Check URL parameter to see if we need to update
    const urlParams = new URLSearchParams(window.location.search);
    const urlTheme = urlParams.get('theme');
    
    if (urlTheme && (urlTheme === 'light' || urlTheme === 'dark') && urlTheme !== this.currentTheme) {
      this.setTheme(urlTheme);
      localStorage.setItem('keyn-theme', urlTheme);
    }

    // Listen for system theme changes
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
      if (!localStorage.getItem('keyn-theme')) {
        this.setTheme(e.matches ? 'dark' : 'light');
      }
    });

    // Add theme toggle button
    this.createThemeToggle();
  }

  setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    this.currentTheme = theme;
    
    // Update theme toggle button if it exists
    const themeToggle = document.querySelector('.theme-toggle');
    if (themeToggle) {
      themeToggle.setAttribute('aria-label', `Switch to ${theme === 'light' ? 'dark' : 'light'} mode`);
    }
  }

  toggleTheme() {
    const newTheme = this.currentTheme === 'light' ? 'dark' : 'light';
    this.setTheme(newTheme);
    localStorage.setItem('keyn-theme', newTheme);
  }

  createThemeToggle() {
    // Check if a theme toggle already exists
    let themeToggle = document.querySelector('.theme-toggle');
    
    if (!themeToggle) {
      // Create new theme toggle button
      themeToggle = document.createElement('button');
      themeToggle.className = 'theme-toggle';
      document.body.appendChild(themeToggle);
    }
    
    // Set up the button content and event listener
    themeToggle.setAttribute('aria-label', 'Toggle theme');
    themeToggle.innerHTML = `
      <span class="sun-icon">☀️</span>
      <span class="moon-icon">🌙</span>
    `;
    
    // Remove any existing event listeners and add new one
    themeToggle.replaceWith(themeToggle.cloneNode(true));
    themeToggle = document.querySelector('.theme-toggle');
    
    themeToggle.addEventListener('click', () => {
      this.toggleTheme();
    });
  }

  // Method to get current theme
  getCurrentTheme() {
    return this.currentTheme;
  }

  // Method to force a specific theme (useful for URL parameters)
  forceTheme(theme) {
    if (theme === 'light' || theme === 'dark') {
      this.setTheme(theme);
      localStorage.setItem('keyn-theme', theme);
    }
  }
}

// Don't auto-initialize - let the page handle it
// Initialize theme manager when DOM is loaded
// document.addEventListener('DOMContentLoaded', () => {
//   window.themeManager = new ThemeManager();
// });

// Utility function to get theme parameter from URL
function getThemeFromUrl() {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get('theme');
}

// Utility function to set theme parameter in URL
function setThemeInUrl(theme) {
  const url = new URL(window.location);
  if (theme && (theme === 'light' || theme === 'dark')) {
    url.searchParams.set('theme', theme);
  } else {
    url.searchParams.delete('theme');
  }
  window.history.replaceState({}, '', url);
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ThemeManager, getThemeFromUrl, setThemeInUrl };
}
