// SPDX-License-Identifier: BUSL-1.1
import {test,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
const tags=['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa'];
test('accessibility scanner accepts a good control and detects seeded violations',async({page})=>{
  await page.setContent('<!doctype html><html lang="en"><title>Owned good control</title><main><h1>Control</h1><button>Action</button></main></html>');
  expect((await new AxeBuilder({page}).withTags(tags).analyze()).violations).toEqual([]);
  await page.setContent('<!doctype html><html lang="en"><title>Owned bad control</title><main><h1>Control</h1><button></button><input type="text"><p style="color:#aaa;background:white">Insufficient contrast</p><img width="24"height="24"src="data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%2224%22 height=%2224%22/%3E"></main></html>');
  const result=await new AxeBuilder({page}).withTags(tags).analyze();
  expect(result.violations.map(v=>v.id)).toEqual(expect.arrayContaining(['button-name','color-contrast','image-alt','label','target-size']));
});
