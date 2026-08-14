(function () {
  'use strict';

  // Fade the page in once its stylesheet/fonts have had a beat to settle,
  // rather than flashing the fully-styled page in instantly.
  function ready() {
    document.body.classList.add('is-ready');
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', ready);
  } else {
    ready();
  }

  // Gentle scroll-reveal for essay sections, if any are present on this page.
  var sections = document.querySelectorAll('.essay section');
  if (sections.length && 'IntersectionObserver' in window) {
    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add('in-view');
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.15, rootMargin: '0px 0px -60px 0px' }
    );
    sections.forEach(function (s) { observer.observe(s); });
  } else if (sections.length) {
    sections.forEach(function (s) { s.classList.add('in-view'); });
  }
})();
