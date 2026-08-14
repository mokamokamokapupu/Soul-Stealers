(function () {
  'use strict';

  var form = document.getElementById('setup-form');
  var input = document.getElementById('username');
  var errorEl = document.getElementById('error');
  var submitBtn = document.getElementById('submit-btn');
  var csrfToken = null;

  function setError(msg) { errorEl.textContent = msg || ''; }

  async function bootstrap() {
    var res = await fetch('/api/session', { credentials: 'same-origin' });
    var data = await res.json();
    csrfToken = data.csrfToken;
    if (data.stage === 'none') {
      window.location.href = '/portal';
    } else if (data.stage === 'active') {
      window.location.href = '/chat';
    }
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    setError('');
    submitBtn.disabled = true;
    try {
      var res = await fetch('/api/username', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ username: input.value.trim() }),
      });
      var data = await res.json();
      if (res.ok) {
        window.location.href = '/chat';
      } else {
        setError(data.error || 'Could not use that name.');
      }
    } catch (err) {
      setError('Something went wrong. Try again.');
    } finally {
      submitBtn.disabled = false;
    }
  });

  bootstrap();
})();
