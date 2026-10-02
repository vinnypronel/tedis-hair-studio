import { spawnSync } from "node:child_process";
import { rmSync, writeFileSync } from "node:fs";

rmSync(".open-next", { recursive: true, force: true });

const env = { ...process.env, CLOUDFLARE_BUILD: "1" };
for (const [entry, args] of [
  ["node_modules/next/dist/bin/next", ["build"]],
  ["node_modules/@opennextjs/cloudflare/dist/cli/index.js", ["build", "--skipNextBuild"]],
]) {
  const result = spawnSync(process.execPath, [entry, ...args], { env, stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

// The old standalone website is kept in public for reference, but must never
// become the deployment's index page. Only exclude generated deployment copies.
for (const file of [
  "admin-history.html",
  "admin-reviews.html",
  "admin.html",
  "artists.html",
  "book.html",
  "gallery.html",
  "header.html",
  "index.html",
  "login.html",
  "services.html",
  "testimonials.html",
  "styles.css",
  "header.js",
  "include.js",
  "click-spark.js",
]) {
  rmSync(`.open-next/assets/${file}`, { force: true });
}

writeFileSync(".open-next/assets/.assetsignore", "/*.html\n/styles.css\n/header.js\n/include.js\n/click-spark.js\n");
writeFileSync(".open-next/assets/_headers", "/_next/static/*\n  Cache-Control: public, max-age=31536000, immutable\n");
