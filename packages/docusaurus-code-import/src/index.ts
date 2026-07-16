// Copyright 2026 Anapaya Systems

/**
 * remark-code-import: pull code samples into guide pages *by reference* from
 * real source files, so snippets are compiled/tested at their origin and can
 * never rot in the prose.
 *
 * SOURCE OF TRUTH. This package (`@anapaya/docusaurus-code-import`) is the one
 * canonical home of the code-include plugin. It is consumed by:
 *   - this repo's `docs-preview/` app, via a pnpm workspace dependency, and
 *   - learn.anapaya.net (the Anapaya monorepo), which vendors this `.ts` source
 *     into `documentation/public/src/remark/codeImport.ts`.
 * Do not edit any vendored copy directly — change it here.
 *
 * Usage in an `.md`/`.mdx` page — an empty fenced code block whose meta carries
 * a `reference="<path>[#selector]"` attribute:
 *
 *   ```rust reference="@sdk/scion-stack/examples/udp_echo.rs#server" title="udp_echo.rs"
 *   ```
 *
 * The `<path>` is resolved as follows:
 *   - if it begins with a configured alias prefix (e.g. `@sdk`), the prefix is
 *     replaced by the alias' target directory. Author references as alias-based
 *     so the SAME string resolves both in this repo's local preview (alias ->
 *     the repo root) and in the vendored `learn.anapaya.net` build (alias -> the
 *     vendored source dir), even though the two layouts differ; otherwise
 *   - it is resolved relative to the page file (handy for co-located snippets).
 *
 * Configure aliases when registering the plugin:
 *
 *   codeImport({ aliases: { '@sdk': '/abs/path/to/sdk-sources' } })
 *
 * The optional `#selector` is either:
 *   - a named anchor:  `#server`  -> the lines between the mdBook-style markers
 *     `// ANCHOR: server` and `// ANCHOR_END: server` (anchor lines and any
 *     nested anchor markers are stripped), or
 *   - a line range:    `#L10-L20`   -> 1-indexed inclusive line range.
 *
 * Named anchors are preferred: they survive edits above/below the snippet,
 * whereas line ranges drift. The extracted block is dedented to its own
 * minimum indentation. This plugin runs *before* the default remark plugins so
 * the resolved code participates in normal syntax highlighting.
 */

import fs from 'fs';
import path from 'path';

interface MdastCode {
    type: 'code';
    lang?: string | null;
    meta?: string | null;
    value: string;
}

interface MdastNode {
    type: string;
    children?: MdastNode[];
    [key: string]: unknown;
}

/** Options for the code-import remark plugin. */
export interface CodeImportOptions {
    /**
     * Map of alias prefix -> absolute target directory. A reference of
     * `@sdk/scion-stack/examples/foo.rs` with `{ '@sdk': '/x' }` resolves to
     * `/x/scion-stack/examples/foo.rs`.
     */
    aliases?: Record<string, string>;
}

const REFERENCE_RE = /(?:^|\s)reference="([^"]+)"/;

function resolvePath(
    rawPath: string,
    pageFile: string,
    aliases: Record<string, string>,
): string {
    for (const [prefix, target] of Object.entries(aliases)) {
        if (rawPath === prefix || rawPath.startsWith(`${prefix}/`)) {
            const rest = rawPath.slice(prefix.length).replace(/^\/+/, '');
            return path.resolve(target, rest);
        }
    }
    // No alias matched: resolve relative to the page that referenced it.
    return path.resolve(path.dirname(pageFile), rawPath);
}

function extractAnchor(source: string, anchor: string, file: string): string {
    const lines = source.split('\n');
    const start = lines.findIndex((l) => l.includes(`ANCHOR: ${anchor}`));
    const end = lines.findIndex((l) => l.includes(`ANCHOR_END: ${anchor}`));
    if (start === -1 || end === -1 || end < start) {
        throw new Error(
            `codeImport: anchor "${anchor}" not found (need "ANCHOR: ${anchor}" and ` +
                `"ANCHOR_END: ${anchor}") in ${file}`,
        );
    }
    // Keep lines strictly between the markers, dropping any nested anchor markers.
    return lines
        .slice(start + 1, end)
        .filter((l) => !/ANCHOR(_END)?:/.test(l))
        .join('\n');
}

function extractLineRange(source: string, selector: string, file: string): string {
    const m = selector.match(/^L(\d+)-L(\d+)$/);
    if (!m) {
        throw new Error(`codeImport: invalid selector "#${selector}" in ${file}`);
    }
    const from = Number(m[1]);
    const to = Number(m[2]);
    const lines = source.split('\n');
    if (from < 1 || to > lines.length || from > to) {
        throw new Error(
            `codeImport: line range ${from}-${to} out of bounds (1-${lines.length}) in ${file}`,
        );
    }
    return lines.slice(from - 1, to).join('\n');
}

function dedent(block: string): string {
    const lines = block.split('\n');
    const indents = lines
        .filter((l) => l.trim().length > 0)
        .map((l) => l.match(/^\s*/)![0].length);
    const min = indents.length ? Math.min(...indents) : 0;
    return lines.map((l) => l.slice(min)).join('\n');
}

function resolveReference(
    reference: string,
    pageFile: string,
    aliases: Record<string, string>,
): string {
    const [rawPath, selector] = reference.split('#');
    const abs = resolvePath(rawPath, pageFile, aliases);
    let source: string;
    try {
        source = fs.readFileSync(abs, 'utf8');
    } catch {
        throw new Error(`codeImport: cannot read referenced file ${abs} (from ${pageFile})`);
    }
    let block: string;
    if (!selector) {
        // Whole file, minus any anchor bookkeeping lines.
        block = source
            .split('\n')
            .filter((l) => !/ANCHOR(_END)?:/.test(l))
            .join('\n');
    } else if (/^L\d+-L\d+$/.test(selector)) {
        block = extractLineRange(source, selector, abs);
    } else {
        block = extractAnchor(source, selector, abs);
    }
    return dedent(block).replace(/\n+$/, '');
}

export default function codeImport(options: CodeImportOptions = {}) {
    const aliases = options.aliases ?? {};
    return (tree: MdastNode, vfile: { path?: string; history?: string[] }) => {
        const pageFile = vfile.path ?? vfile.history?.[0];
        if (!pageFile) {
            return;
        }
        const walk = (node: MdastNode) => {
            if (node.type === 'code') {
                const code = node as unknown as MdastCode;
                const match = code.meta?.match(REFERENCE_RE);
                if (match) {
                    code.value = resolveReference(match[1], pageFile, aliases);
                    // Strip our custom attribute; leave the rest (e.g. title=) intact.
                    code.meta = (code.meta ?? '').replace(REFERENCE_RE, '').trim() || null;
                }
            }
            node.children?.forEach(walk);
        };
        walk(tree);
    };
}
