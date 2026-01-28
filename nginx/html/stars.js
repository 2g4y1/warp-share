// Stars animation for WARP SHARE pages
// CSS-based animation = GPU accelerated, minimal CPU usage
(function() {
    const container = document.getElementById('stars');
    if (!container) return;

    const count = Math.min(120, Math.floor(window.innerWidth * window.innerHeight / 10000));

    for (let i = 0; i < count; i++) {
        const star = document.createElement('div');
        star.className = 'star';
        star.style.left = Math.random() * 100 + '%';
        star.style.top = Math.random() * 100 + '%';

        // Vary star sizes
        const size = Math.random() < 0.7 ? 1 : (Math.random() < 0.7 ? 2 : 3);
        star.style.width = size + 'px';
        star.style.height = size + 'px';

        // Random drift animation (20-60 seconds, very slow)
        const duration = 20 + Math.random() * 40;
        const delay = Math.random() * -duration; // Start at random point in animation
        star.style.animation = `drift ${duration}s linear ${delay}s infinite, twinkle ${1.5 + Math.random() * 2}s ease-in-out infinite`;

        container.appendChild(star);
    }

    // Inject CSS animation if not exists
    if (!document.getElementById('star-drift-css')) {
        const style = document.createElement('style');
        style.id = 'star-drift-css';
        style.textContent = `
            @keyframes drift {
                from { transform: translate(0, 0); }
                to { transform: translate(-100px, 50px); }
            }
        `;
        document.head.appendChild(style);
    }
})();
