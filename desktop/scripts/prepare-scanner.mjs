import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const desktopDirectory = path.dirname(scriptDirectory);
const repositoryRoot = path.dirname(desktopDirectory);
const binaryName = process.platform === "win32" ? "webcyber.exe" : "webcyber";
const outputDirectory = path.join(desktopDirectory, "resources", "bin");
const outputPath = path.join(outputDirectory, binaryName);
const buildCache = path.join(repositoryRoot, ".cache", "go-build");
const moduleCache = path.join(repositoryRoot, ".cache", "go-mod");

mkdirSync(outputDirectory, { recursive: true });
mkdirSync(buildCache, { recursive: true });
mkdirSync(moduleCache, { recursive: true });

const build = spawnSync(
  "go",
  ["build", "-trimpath", "-o", outputPath, "./cmd/webcyber"],
  {
    cwd: repositoryRoot,
    env: {
      ...process.env,
      GOCACHE: process.env.GOCACHE || buildCache,
      GOMODCACHE: process.env.GOMODCACHE || moduleCache,
    },
    shell: false,
    stdio: "inherit",
  },
);

if (build.error) throw build.error;
if (build.status !== 0) {
  throw new Error(`Go tarama motoru derlenemedi (çıkış: ${build.status ?? "yok"}).`);
}

if (process.platform !== "win32") chmodSync(outputPath, 0o755);

const digest = createHash("sha256").update(readFileSync(outputPath)).digest("hex");
writeFileSync(`${outputPath}.sha256`, `${digest}\n`, {
  encoding: "utf8",
  mode: 0o644,
});

console.log(`WebCyber scanner hazır: ${outputPath}`);
