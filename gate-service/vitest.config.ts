import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        compatibilityDate: "2026-08-22",
        bindings: {
          ACTIVATION_MODE: "active",
          GITHUB_APP_ID: "111",
          GITHUB_APP_INSTALLATION_ID: "222",
          GITHUB_REPOSITORY: "example-owner/example-repository",
          GITHUB_REPOSITORY_ID: "123456789",
          GITHUB_APP_KEY_FINGERPRINT: "0".repeat(64),
          GITHUB_APP_PRIVATE_KEY_PEM: "invalid-test-key",
        },
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
  },
});
