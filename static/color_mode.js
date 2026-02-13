function toggleTheme() {
    const html = document.documentElement;
    const isDark = html.classList.toggle('dark');


    if (localStorage.getItem('animations') !== 'true') {
        disableTransitionsTemporarily();
    }

    localStorage.setItem('theme', isDark ? 'dark' : 'light');
    updateThemeIcon(isDark);
}

function loadTheme() {
    const savedTheme = localStorage.getItem('theme');
    const isDark = savedTheme !== 'light';

    if (localStorage.getItem('animations') !== 'true') {
        disableTransitionsTemporarily();
    }

    if (isDark) {
        document.documentElement.classList.add('dark');
    } else {
        document.documentElement.classList.remove('dark');
    }
    updateThemeIcon(isDark);
}

function updateThemeIcon(isDark) {
    const baseClass = 'theme-icon fa-solid text-sm';
    document.querySelectorAll('.theme-icon').forEach(el => {
        el.className = isDark ? `${baseClass} fa-moon` : `${baseClass} fa-sun text-yellow-500`;
    });
}

function disableTransitionsTemporarily() {
  const style = document.createElement('style');
  style.id = 'disable-transitions';
  style.textContent = `
    * {
      transition: none !important;
    }
  `;
  document.head.appendChild(style);

  window.setTimeout(() => {
    document.getElementById('disable-transitions')?.remove();
  }, 1000)
}

// Apply saved theme on every page that includes this script
document.addEventListener('DOMContentLoaded', loadTheme);