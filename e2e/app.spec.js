const { test, expect } = require('@playwright/test');

async function signIn(page) {
  await page.goto('/login.html');
  await page.locator('#username').fill('e2e-admin');
  await page.locator('#password').fill('e2e-test-password-123!');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL('/');
}

test('analyze a log and reopen its saved result', async ({ page }) => {
  await signIn(page);
  await page.locator('#logInput').fill('ERROR database browser-e2e-analysis');
  await page.getByRole('button', { name: 'Analyze Log' }).click();

  await expect(page.locator('#resultContent')).toContainText('Database');
  await page.locator('#historySearch').fill('browser-e2e-analysis');
  await expect(page.locator('#historyCount')).toContainText('of 1 matching analyses');
  await page.getByRole('button', { name: 'View analysis' }).click();
  await expect(page.locator('#resultContent')).toContainText('browser-e2e-analysis');
});

test('searches and pages through retained analyses in the browser', async ({ page }) => {
  await signIn(page);
  const csrfResponse = await page.request.get('/api/auth/csrf');
  const { token } = await csrfResponse.json();
  for (let index = 0; index < 21; index++) {
    const response = await page.request.post('/api/analyze', {
      headers: { 'X-CSRF-TOKEN': token },
      data: {
        logText: `ERROR database e2e-page-marker`,
        fileName: `browser-page-${String(index).padStart(2, '0')}.log`
      }
    });
    expect(response.ok()).toBeTruthy();
  }

  await page.locator('#historySearch').fill('e2e-page-marker');
  await expect(page.locator('#historyCount')).toContainText('of 21 matching analyses');
  await expect(page.getByText('browser-page-20.log')).toBeVisible();
  await expect(page.getByText('browser-page-00.log')).toHaveCount(0);
  await page.getByRole('button', { name: 'Next' }).click();
  await expect(page.getByText('browser-page-00.log')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Next' })).toBeDisabled();
});

test('generates an AI brief and renders model content as text', async ({ page }) => {
  await signIn(page);
  await page.route('**/api/ai/analyze', async route => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        provider: 'Local Ollama',
        model: 'test-model',
        summary: '<img src=x onerror=alert(1)> incident summary',
        likelyCause: 'Database unavailable',
        impact: 'Requests may fail',
        evidence: ['connection refused'],
        nextSteps: ['Check database health'],
        caveat: 'Verify using service metrics.'
      })
    });
  });

  await page.locator('#logInput').fill('ERROR database browser-ai-analysis');
  await page.getByRole('button', { name: 'Generate brief' }).click();
  await expect(page.locator('#aiResults')).toContainText('<img src=x onerror=alert(1)> incident summary');
  await expect(page.locator('#aiResults img')).toHaveCount(0);
  await expect(page.locator('#aiResults')).toContainText('Check database health');
});

test('signs out and redirects protected pages back to sign-in', async ({ page }) => {
  await signIn(page);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page).toHaveURL(/\/login\.html$/);
  await page.goto('/');
  await expect(page).toHaveURL(/\/login\.html/);
});

test('registers a new account and opens its private workspace', async ({ page }) => {
  await page.goto('/register.html');
  await page.locator('#username').fill(`new-${Date.now().toString(36)}`);
  await page.locator('#password').fill('strong-browser-registration-password');
  await page.locator('#confirmPassword').fill('strong-browser-registration-password');
  await page.getByRole('button', { name: 'Create your account' }).click();
  await expect(page).toHaveURL('/');
  await expect(page.getByRole('heading', { name: 'Recent analyses' })).toBeVisible();
  await expect(page.locator('#historyCount')).toContainText('Showing 0 of 0 saved analyses');
});
