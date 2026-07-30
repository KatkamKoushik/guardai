import { loadEnvConfig } from '@next/env';
import { defineConfig } from '@prisma/config';

const projectDir = process.cwd();
loadEnvConfig(projectDir);

export default defineConfig({
  datasource: {
    url: process.env.DATABASE_URL,
    directUrl: process.env.DIRECT_URL,
  }
});
