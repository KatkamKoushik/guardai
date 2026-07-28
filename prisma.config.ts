import { loadEnvConfig } from '@next/env';
import { defineConfig } from '@prisma/config';

const projectDir = process.cwd();
loadEnvConfig(projectDir);

export default defineConfig({
  earlyAccess: true,
  datasource: {
    url: process.env.DATABASE_URL,
  }
});
