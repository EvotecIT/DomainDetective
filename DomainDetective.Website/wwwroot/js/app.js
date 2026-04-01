(function () {
    'use strict';

    var themes = ['dark', 'light'];

    function applyTheme(theme) {
        var nextTheme = theme === 'light' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', nextTheme);
        document.documentElement.style.colorScheme = nextTheme;
    }

    window.domainDetectiveTools = {
        initTheme: function () {
            var current = localStorage.getItem('dd-theme') || 'dark';
            applyTheme(current);
        },
        toggleTheme: function () {
            var current = localStorage.getItem('dd-theme') || 'dark';
            var idx = themes.indexOf(current);
            var next = themes[(idx + 1) % themes.length];
            localStorage.setItem('dd-theme', next);
            applyTheme(next);
        },
        copyText: async function (text) {
            if (!text) {
                return false;
            }

            try {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    await navigator.clipboard.writeText(text);
                    return true;
                }
            } catch (error) {
                // Fall back to document.execCommand below.
            }

            try {
                var element = document.createElement('textarea');
                element.value = text;
                element.setAttribute('readonly', 'readonly');
                element.style.position = 'fixed';
                element.style.opacity = '0';
                element.style.pointerEvents = 'none';
                document.body.appendChild(element);
                element.focus();
                element.select();
                var copied = document.execCommand('copy');
                document.body.removeChild(element);
                return copied;
            } catch (error) {
                return false;
            }
        }
    };
})();
