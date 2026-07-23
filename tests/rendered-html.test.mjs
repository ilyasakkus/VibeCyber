import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const templateRoot = new URL("../", import.meta.url);
const previewRoot = new URL("../app/_sites-preview/", import.meta.url);

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request("http://localhost/", {
      headers: { accept: "text/html" },
    }),
    {
      ASSETS: {
        fetch: async () => new Response("Not found", { status: 404 }),
      },
    },
    {
      waitUntil() {},
      passThroughOnException() {},
    },
  );
}

test("server-renders the WebCyber operations dashboard", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<html[^>]*\blang=["']tr["']/i);
  assert.match(html, /<title>WebCyber \| Güvenlik Operasyon Merkezi<\/title>/i);
  assert.match(html, /Güvenlik sınırları etkin/);
  assert.match(html, /Yeni tarama oluştur/);
  assert.match(html, /Örnek bulgular/);
  assert.match(html, /Masaüstü ajanı/);
  assert.match(html, /property=["']og:image["'][^>]*content=["']https:\/\/webcyber\.dev\/og\.png["']/i);
  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton|Your site is taking shape/i);
});

test("removes starter assets and ships a real social card", async () => {
  const [page, layout, packageJson, socialCard] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
    readFile(new URL("../public/og.png", import.meta.url)),
  ]);

  await assert.rejects(access(previewRoot));
  assert.match(page, /^"use client";/);
  assert.match(page, /Active profil.*yazılı hedef yetkisi/s);
  assert.match(layout, /generateMetadata/);
  assert.match(layout, /\/og\.png/);
  assert.equal(JSON.parse(packageJson).name, "webcyber");
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  assert.deepEqual([...socialCard.subarray(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10]);

  await assert.rejects(
    access(new URL("../public/favicon.svg", import.meta.url)),
  );
  await access(new URL("LICENSE", templateRoot));
  await access(new URL("SECURITY.md", templateRoot));
});
