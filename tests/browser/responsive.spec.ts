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

test('keeps a dense Ethernet topology readable without overlapping port cards', async ({ page }) => {
  await mockAPI(page, { topologyPortCount: 12 });
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.goto('/?screen=%D0%9E%D0%B1%D0%B7%D0%BE%D1%80');
  const ports = page.locator('.map-port');
  await expect(ports).toHaveCount(12);
  const boxes = (await ports.evaluateAll((elements) => elements
    .map((element) => {
      const rect = element.getBoundingClientRect();
      return { left: rect.left, right: rect.right };
    })
    .sort((a, b) => a.left - b.left))) as Array<{ left: number; right: number }>;
  for (let index = 1; index < boxes.length; index += 1) {
    expect(boxes[index].left).toBeGreaterThanOrEqual(boxes[index - 1].right - 0.5);
  }
});

test('keeps mobile navigation keyboard-visible and touch-sized', async ({ page }) => {
  await mockAPI(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/?screen=%D0%9E%D0%B1%D0%B7%D0%BE%D1%80');
  const navButtons = page.locator('.mobile-nav button');
  await expect(navButtons).toHaveCount(5);
  for (const box of await navButtons.evaluateAll((elements) => elements.map((element) => {
    const rect = element.getBoundingClientRect();
    return { width: rect.width, height: rect.height };
  }))) {
    expect(box.width).toBeGreaterThanOrEqual(44);
    expect(box.height).toBeGreaterThanOrEqual(44);
  }
  await page.keyboard.press('Tab');
  const focused = page.locator(':focus-visible');
  await expect(focused).toHaveCount(1);
  expect(await focused.evaluate((element) => getComputedStyle(element).outlineStyle)).not.toBe('none');
});
