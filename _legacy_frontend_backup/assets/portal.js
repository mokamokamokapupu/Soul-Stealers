(function () {
  'use strict';

  var form = document.getElementById('gate-form');
  var input = document.getElementById('password');
  var errorEl = document.getElementById('error');
  var submitBtn = document.getElementById('submit-btn');
  var card = document.getElementById('card');
  var csrfToken = null;

  function setError(msg) { errorEl.textContent = msg || ''; }

  function goTo(url) {
    // A brief, smooth transition out rather than an abrupt jump.
    card.classList.add('is-leaving');
    setTimeout(function () { window.location.href = url; }, 280);
  }

  async function bootstrap() {
    var res = await fetch('/api/session', { credentials: 'same-origin' });
    var data = await res.json();
    csrfToken = data.csrfToken;
    // UX-only redirect. Real enforcement happens server-side per request.
    if (data.stage === 'password_ok') {
      window.location.href = '/setup';
    } else if (data.stage === 'active') {
      window.location.href = '/chat';
    }
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    setError('');
    submitBtn.disabled = true;
    try {
      var res = await fetch('/api/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ password: input.value }),
      });
      var data = await res.json();
      if (res.ok) {
        submitBtn.textContent = 'Entering…';
        goTo('/setup');
        return;
      } else if (res.status === 429) {
        setError('Too many attempts. Try again in ' + Math.ceil((data.retryAfterSec || 60) / 60) + ' min.');
      } else {
        setError(data.error || 'That is not the word.');
        input.value = '';
        input.focus();
      }
    } catch (err) {
      setError('Something went wrong. Try again.');
    } finally {
      if (!card.classList.contains('is-leaving')) submitBtn.disabled = false;
    }
  });

  bootstrap();
})();
