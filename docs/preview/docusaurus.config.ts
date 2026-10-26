// Copyright 2026 Anapaya Systems
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Minimal, standalone Docusaurus config for previewing the SCION SDK developer
// guide.

import fs from 'fs';
import path from 'path';

import type * as Preset from '@docusaurus/preset-classic';
import type { Config } from '@docusaurus/types';
import { themes as prismThemes } from 'prism-react-renderer';

import codeImport from '@anapaya/docusaurus-code-import';

const sdkRoot = path.resolve(__dirname, '../..');

// A checkout of the chat example application, from SCION_SDK_CHAT_DIR. With it, the `@chat`
// snippets resolve, and a missing file or anchor fails the build. Without it, each `@chat`
// snippet is a placeholder.
const chatRoot = process.env.SCION_SDK_CHAT_DIR
    ? path.resolve(process.env.SCION_SDK_CHAT_DIR)
    : undefined;
if (chatRoot && !fs.existsSync(path.join(chatRoot, 'docs/anchors.txt'))) {
    throw new Error(`SCION_SDK_CHAT_DIR=${chatRoot} is not a checkout of scion-sdk-chat`);
}

const codeImportOptions = chatRoot
    ? { aliases: { '@sdk': sdkRoot, '@chat': chatRoot } }
    : { aliases: { '@sdk': sdkRoot }, placeholderAliases: ['@chat'] };

const config: Config = {
    title: 'SCION SDK Developer Documenation',

    url: 'http://localhost',
    baseUrl: '/',

    // Local preview: don't fail the whole run on a stray link while drafting.
    onBrokenLinks: 'warn',

    markdown: {
        mermaid: true,
        hooks: {
            onBrokenMarkdownLinks: 'warn',
        },
    },

    i18n: { defaultLocale: 'en', locales: ['en'] },

    presets: [
        [
            'classic',
            {
                docs: {
                    path: '../content',
                    routeBasePath: '/',
                    sidebarPath: './sidebars.ts',
                    beforeDefaultRemarkPlugins: [[codeImport, codeImportOptions]],
                },
                blog: false,
                theme: { customCss: './src/css/custom.css' },
            } satisfies Preset.Options,
        ],
    ],

    themes: ['@docusaurus/theme-mermaid'],

    themeConfig: {
        navbar: {
            title: 'SCION SDK',
            items: [
                {
                    href: 'https://github.com/Anapaya/scion-sdk',
                    label: 'GitHub',
                    position: 'right',
                },
            ],
        },
        prism: {
            theme: prismThemes.github,
            darkTheme: prismThemes.dracula,
            additionalLanguages: ['rust', 'toml', 'bash', 'kotlin', 'swift'],
        },
    } satisfies Preset.ThemeConfig,
};

export default config;
