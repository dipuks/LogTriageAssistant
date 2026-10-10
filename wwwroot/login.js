const loginForm = document.getElementById('loginForm');
const loginButton = document.getElementById('loginButton');
const loginStatus = document.getElementById('loginStatus');

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  loginButton.disabled = true;
  loginStatus.textContent = '';

  try {
    const csrfResponse = await fetch('/api/auth/csrf');
    if (!csrfResponse.ok) {
      throw new Error('Sign-in is temporarily unavailable. Try again later.');
    }
    const csrf = await csrfResponse.json();
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-TOKEN': csrf.token
      },
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: document.getElementById('password').value
      })
    });

    if (!response.ok) {
      loginStatus.textContent = response.status === 429
        ? 'Too many sign-in attempts. Wait a minute and try again.'
        : 'The username or password is incorrect.';
      return;
    }

    window.location.assign('/');
  } catch {
    loginStatus.textContent = 'Sign-in is temporarily unavailable. Try again later.';
  } finally {
    loginButton.disabled = false;
  }
});
