// SPDX-License-Identifier: BUSL-1.1
import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'./tests',timeout:180000,workers:1,fullyParallel:false,retries:0,reporter:[['list'],['json']],outputDir:'../.cache/console-playwright-output',use:{browserName:'chromium',channel:'chromium',headless:true,viewport:{width:1440,height:1000},trace:'off',video:'off',screenshot:'off',ignoreHTTPSErrors:false}});
