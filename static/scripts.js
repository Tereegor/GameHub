document.addEventListener('DOMContentLoaded', () => {
    const langToggle = document.getElementById('lang-toggle');
    const body = document.body;
    const hamburger = document.querySelector('.hamburger');
    const nav = document.querySelector('nav');
    const tabs = document.querySelectorAll('.tab-btn');

    function updateLanguage() {
        const lang = body.classList.contains('lang-ru') ? 'ru' : 'en';
        document.querySelectorAll('[data-en], [data-ru]').forEach(el => {
            const text = el.getAttribute(`data-${lang}`);
            if (text) {
                el.textContent = text;
            }
        });
        langToggle.textContent = lang === 'en' ? 'RU' : 'EN';
    }

    langToggle.addEventListener('click', () => {
        body.classList.toggle('lang-ru');
        body.classList.toggle('lang-en');
        updateLanguage();
    });

    hamburger.addEventListener('click', () => {
        nav.classList.toggle('active');
    });

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn.active, .tab-content.active').forEach(el => el.classList.remove('active'));
            tab.classList.add('active');
            document.getElementById(tab.dataset.tab).classList.add('active');
        });
    });

    updateLanguage();
});