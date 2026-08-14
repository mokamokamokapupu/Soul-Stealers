(function () {
  'use strict';

  var form = document.getElementById('setup-form');
  var input = document.getElementById('username');
  var errorEl = document.getElementById('error');
  var submitBtn = document.getElementById('submit-btn');
  var card = document.getElementById('card');
  var csrfToken = null;

  function setError(msg) { errorEl.textContent = msg || ''; }

  function goTo(url) {
    card.classList.add('is-leaving');
    setTimeout(function () { window.location.href = url; }, 280);
  }

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
        submitBtn.textContent = 'Entering…';
        goTo('/chat');
        return;
      } else {
        setError(data.error || 'Could not use that name.');
      }
    } catch (err) {
      setError('Something went wrong. Try again.');
    } finally {
      if (!card.classList.contains('is-leaving')) submitBtn.disabled = false;
    }
  });

  bootstrap();
})();
