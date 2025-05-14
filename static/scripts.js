document.addEventListener('DOMContentLoaded', () => {
    const hamburger = document.querySelector('.hamburger');
    const nav = document.querySelector('nav');

    if (hamburger && nav) {
        hamburger.addEventListener('click', () => {
            nav.classList.toggle('active');
        });
    }

    // Переключение языка
    const langToggle = document.getElementById('lang-toggle');
    if (langToggle) {
        langToggle.addEventListener('click', () => {
            const currentLang = document.body.classList.contains('lang-ru') ? 'ru' : 'en';
            const newLang = currentLang === 'ru' ? 'en' : 'ru';
            document.cookie = `language=lang-${newLang}; path=/`;
            location.reload();
        });
    }

    const updateLanguage = () => {
        const lang = document.body.classList.contains('lang-ru') ? 'ru' : 'en';
        document.querySelectorAll('[data-en][data-ru]').forEach(element => {
            element.textContent = element.getAttribute(`data-${lang}`);
        });
        if (langToggle) {
            langToggle.textContent = lang === 'en' ? 'RU' : 'EN';
        }
    };
    updateLanguage();

    adjustContentPadding();
    window.addEventListener('resize', adjustContentPadding);
});