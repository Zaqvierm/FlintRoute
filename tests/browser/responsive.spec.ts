import { test, expect } from '@playwright/test';
import { mockAPI } from './mock-api';

const viewports = [
  [360, 800], [390, 844], [430, 932],
  [768, 1024], [1080, 1920],
  [1366, 768], [1920, 1080],
  [2560, 1440], [3440, 1440], [3840, 2160]
] as const;

test('overview and topology remain usable across the supported viewport matrix', async ({ page }) => {
  await mockAPI(page);
  for (const [width, height] of viewports) {
    await page.setViewportSize({ width, height });
    await page.goto('/?screen=Обзор');
    await expect(page.locator('main')).toBeVisible();
    await expect(page.locator('.network-map')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
    if (width <= 1199) {
      await expect(page.locator('.network-map-mobile')).toBeVisible();
    } else {
      await expect(page.locator('.map-router')).toBeVisible();
      const router = await page.locator('.map-router').boundingBox();
      expect(router).not.toBeNull();
      expect(router!.x + router!.width / 2).toBeGreaterThan(0);
      expect(router!.x + router!.width / 2).toBeLessThan(width);
    }
    if (width <= 640) await expect(page.locator('.mobile-nav')).toBeVisible();
  }
});
