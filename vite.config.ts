import { chmodSync, existsSync } from "node:fs";
import { builtinModules } from "node:module";
import { resolve } from "node:path";
import devServer from "@hono/vite-dev-server";
import { defineConfig, type Plugin } from "vitest/config";
import pkg from "./package.json" with { type: "json" };

const externals = [
  ...builtinModules,
  ...builtinModules.map((m) => `node:${m}`),
  ...Object.keys(pkg.dependencies),
];

const isExternal = (id: string) => externals.some((dep) => id === dep || id.startsWith(`${dep}/`));

/** Makes the CLI entry executable after the build. */
function chmodCli(): Plugin {
  return {
    name: "chmod-cli",
    apply: "build",
    writeBundle(options) {
      const file = resolve(options.dir ?? "dist", "cli.js");
      if (existsSync(file)) chmodSync(file, 0o755);
    },
  };
}

export default defineConfig(({ command }) => ({
  plugins: [
    chmodCli(),
    // `npm run dev`: serve the Hono app with HMR (see src/dev.ts)
    command === "serve" && !process.env.VITEST ? devServer({ entry: "src/dev.ts" }) : undefined,
  ],
  build: {
    ssr: true,
    target: "node20",
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: true,
    minify: false,
    lib: {
      entry: {
        index: resolve(import.meta.dirname, "src/index.ts"),
        cli: resolve(import.meta.dirname, "src/cli.ts"),
      },
      formats: ["es"],
    },
    rollupOptions: {
      external: isExternal,
      output: { entryFileNames: "[name].js" },
    },
  },
  test: {
    include: ["test/**/*.test.ts"],
    testTimeout: 20_000,
  },
}));
