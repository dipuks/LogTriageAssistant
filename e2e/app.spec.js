const { test, expect } = require('@playwright/test');

test('analyze a log and reopen its saved result', async ({ page }) => {
  await page.goto('/');
  await page.locator('#logInput').fill('ERROR database browser-e2e-analysis');
  await page.getByRole('button', { name: 'Analyze Log' }).click();

  await expect(page.locator('#resultContent')).toContainText('Database');
  await page.locator('#historySearch').fill('browser-e2e-analysis');
  await expect(page.locator('#historyCount')).toContainText('of 1 matching analyses');
  await page.getByRole('button', { name: 'View analysis' }).click();
  await expect(page.locator('#resultContent')).toContainText('browser-e2e-analysis');
});

test('searches and pages through retained analyses in the browser', async ({ page, request }) => {
  for (let index = 0; index < 21; index++) {
    const response = await request.post('/api/analyze', {
      data: {
        logText: `ERROR database e2e-page-marker`,
        fileName: `browser-page-${String(index).padStart(2, '0')}.log`
      }
    });
    expect(response.ok()).toBeTruthy();
  }

  await page.goto('/');
  await page.locator('#historySearch').fill('e2e-page-marker');
  await expect(page.locator('#historyCount')).toContainText('of 21 matching analyses');
  await expect(page.getByText('browser-page-20.log')).toBeVisible();
  await expect(page.getByText('browser-page-00.log')).toHaveCount(0);
  await page.getByRole('button', { name: 'Next' }).click();
  await expect(page.getByText('browser-page-00.log')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Next' })).toBeDisabled();
});
