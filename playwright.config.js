const os = require('node:os');
const path = require('node:path');
const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './e2e',
  workers: 1,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:5173',
    browserName: 'chromium'
  },
  webServer: {
    command: 'dotnet run --no-build --configuration Release --urls http://127.0.0.1:5173',
    url: 'http://127.0.0.1:5173/health/ready',
    reuseExistingServer: !process.env.CI,
    timeout: 60000,
    env: {
      Storage__DatabasePath: path.join(os.tmpdir(), `logtriage-e2e-${process.pid}.db`)
    }
  }
});
