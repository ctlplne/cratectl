// SPDX-License-Identifier: BUSL-1.1
import {defineConfig} from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({base:'/console/',plugins:[react()],build:{outDir:'../internal/consoleui/dist',emptyOutDir:true,sourcemap:false,assetsInlineLimit:0,chunkSizeWarningLimit:350},server:{host:'127.0.0.1',strictPort:true}});
