# SCION SDK docs — local preview

A minimal, standalone Docusaurus app for previewing the SCION SDK developer
guide **from within this repo**.

```bash
pnpm install
pnpm start          # http://localhost:3000  (live reload)
```

The example application pages quote the
[chat example application](https://github.com/Anapaya/scion-sdk-chat) with `@chat` snippets. By
default, the preview shows a placeholder for each of them. To show the real code, point
`SCION_SDK_CHAT_DIR` at a checkout of the chat:

```bash
SCION_SDK_CHAT_DIR=~/scion-sdk-chat pnpm start
```

With the variable set, a snippet whose file or anchor does not exist in the checkout fails the
build. Use it before you push a change to a page that quotes the chat.
