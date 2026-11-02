# Contributing to GuardAI

Thank you for your interest in contributing to GuardAI. We welcome contributions from the cybersecurity, open-source, and engineering communities.

To ensure our codebase remains robust, secure, and production-ready, all contributors must follow these engineering standards.

---

## 🛠️ Prerequisites & Local Setup

1. **System Requirements:**
   - **Node.js:** `v22.x` (LTS recommended)
   - **Package Manager:** `npm >= 11.0.0`
   - **Database:** PostgreSQL 16+ (or Docker)

2. **Clone & Install Dependencies:**
   ```bash
   git clone https://github.com/KatkamKoushik/guardai.git
   cd guardai
   npm ci
   ```

3. **Configure Environment:**
   ```bash
   cp .env.example .env
   # Update DATABASE_URL with your local PostgreSQL credentials
   ```

4. **Initialize Database:**
   ```bash
   npx prisma generate
   npx prisma db push
   ```

---

## 🚀 Development Workflow

- Run development server with Turbopack:
  ```bash
  npm run dev
  ```
- Run static type verification:
  ```bash
  npm run typecheck
  ```
- Run automated Vitest test suite:
  ```bash
  npm test
  ```
- Run production build verification:
  ```bash
  npm run build
  ```

---

## 🛡️ Security Guidelines

- **Never bypass SSRF defenses:** Egress calls must route through [`validateTargetForSSRF`](file:///d:/guardai/src/lib/ssrf.ts) and [`safeFetch`](file:///d:/guardai/src/lib/ssrf.ts).
- **No plaintext secrets:** API keys, webhook URLs, and database connection strings must never be logged or exposed to client-side bundles.
- **Fail closed:** External provider failures or timeouts must never be silently marked as "clean" or "safe".

---

## 📝 Commit Conventions

We strictly enforce [Conventional Commits](https://www.conventionalcommits.org/):

- `feat(scope): ...` for new features
- `fix(scope): ...` for bug fixes
- `refactor(scope): ...` for code refactoring without behavior change
- `test(scope): ...` for adding or improving unit/integration tests
- `chore(scope): ...` for dependencies, build configs, or maintenance

---

## 📦 Pull Request Checklist

Before submitting a pull request, ensure:
- [ ] `npm run typecheck` passes with 0 errors.
- [ ] `npm test` passes with 100% test success rate.
- [ ] `npm audit` reports 0 vulnerabilities.
- [ ] `npm run build` succeeds cleanly.
- [ ] New features include corresponding unit tests in `tests/`.

