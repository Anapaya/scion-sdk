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

import path from 'path';

import type * as Preset from '@docusaurus/preset-classic';
import type { Config } from '@docusaurus/types';
import { themes as prismThemes } from 'prism-react-renderer';

import codeImport from '@anapaya/docusaurus-code-import';

const sdkRoot = path.resolve(__dirname, '..');

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
                    path: '../docs',
                    routeBasePath: '/',
                    sidebarPath: './sidebars.ts',
                    beforeDefaultRemarkPlugins: [
                        [codeImport, { aliases: { '@sdk': sdkRoot } }],
                    ],
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
            additionalLanguages: ['rust', 'toml', 'bash'],
        },
    } satisfies Preset.ThemeConfig,
};

export default config;
