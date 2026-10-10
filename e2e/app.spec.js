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

test('signs out and redirects protected pages back to sign-in', async ({ page }) => {
  await signIn(page);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page).toHaveURL(/\/login\.html$/);
  await page.goto('/');
  await expect(page).toHaveURL(/\/login\.html/);
});
