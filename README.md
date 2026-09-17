# GuardAI: Next-Generation Cybersecurity and Threat Intelligence Platform

I designed and engineered GuardAI as a comprehensive, real-time threat intelligence and digital defense platform. My goal with this project was to bridge the gap between high-performance heuristic security scanning, live global threat telemetry, and immersive data visualization. 

By combining modern web technologies, WebGL shaders, Three.js 3D modeling, streaming architectures, and statistical lexical algorithms, I created a security dashboard that delivers actionable threat intelligence alongside a responsive, modern interface.

---

## Architecture Overview

I structured GuardAI around a decoupled, full-stack Next.js architecture utilizing the App Router, React 19, Server-Sent Events (SSE), and Prisma ORM backed by PostgreSQL. The system processes inputs across three core pipelines:

1. Deep URL Scanning Pipeline: An asynchronous multi-stage analysis pipeline that inspects domain DNS, TLS/SSL certificates, VirusTotal intelligence, Google Safe Browsing registries, and heuristic lexical patterns via SSE streams.
2. Global Threat Telemetry Pipeline: An automated ingestion mechanism that consumes threat indicators from URLhaus feeds, persists them to a database, and broadcasts them live to an interactive 3D WebGL globe.
3. Event Logging and Notification Pipeline: An audit-compliant record system tracking scanning actions, authentication events, and dispatching webhook alerts to Discord and Telegram.

```
                      +------------------------------------------+
                      |               Client Browser             |
                      |  React 19 / Three.js / GSAP / Lenis     |
                      +--------------------+---------------------+
                                           |
                   HTTP Requests / SSE Subscriptions
                                           |
                                           v
                      +--------------------+---------------------+
                      |         Next.js App Server Engine        |
                      +--------------------+---------------------+
                                           |
         +-----------------+---------------+-----------------+
         |                 |               |                 |
         v                 v               v                 v
  +--------------+  +--------------+  +----------+    +--------------+
  |  Deep Scan   |  | Threat Map   |  | Alerts   |    | Auth & User  |
  |  Engine      |  | SSE Stream   |  | Webhooks |    | NextAuth v5  |
  +-------+------+  +-------+------+  +----+-----+    +-------+------+
          |                 |              |                  |
          |                 +-------+------+                  |
          |                         |                         |
          v                         v                         v
+-------------------+      +-----------------------------------------+
| External APIs     |      |          Database & Persistence         |
| - VirusTotal      |      |          Prisma ORM / PostgreSQL        |
| - Google Safe     |      | - Users, Accounts, Sessions             |
|   Browsing        |      | - Scans, ThreatTelemetry, Audits        |
| - URLhaus Feed    |      +-----------------------------------------+
+-------------------+
```

---

## Core Features and Implementation Details

### 1. Real-Time Deep Scan Engine
I implemented the URL scanner as a live streaming diagnostic tool rather than a static REST request. When a user submits a URL, the client opens an EventSource connection to `/api/scan/stream`, which progressively pushes diagnostics:
- Network Reconnaissance: I used Node.js `dns/promises` to resolve A and AAAA records, detecting NXDOMAIN errors and invalid host resolutions.
- SSL/TLS Certificate Analysis: Using Node.js `tls.connect`, I extracted and parsed peer certificates to verify cipher validity, issuing authorities, and expiration dates.
- Threat Intelligence Aggregation: The engine queries VirusTotal API v3, Google Safe Browsing API v4, and AbuseIPDB to check if the target hostname or resolved IP address has been blacklisted or reported for malicious activity.
- GeoIP and Security Header Inspection: Resolves server geolocations (country, city, coordinates) and inspects critical HTTP security headers including HSTS, Content-Security-Policy, and X-Frame-Options.
- Lexical and Heuristic Detection: In `src/lib/heuristics.ts`, I created a mathematical evaluation model that calculates domain Shannon entropy to identify algorithmic domain generation (DGA), evaluates IP-based hostnames, detects excessive length, counts subdomains, monitors suspicious keyword frequencies, and flags credential masking syntax (such as `@` symbols).
- Severity Override Matrix: I structured a weighted scoring algorithm that normalizes risk from 0 to 100 and applies critical overrides when external databases flag known malware or phishing campaigns.
- Client-Side Report Generation: I integrated `jsPDF` and `html2canvas` into the scanning interface, allowing security analysts to export audit-ready PDF reports with a single click.

### 2. Interactive 3D WebGL Threat Map
To visualize attacks globally, I built an interactive 3D globe using `@react-three/fiber`, `@react-three/drei`, and `three`:
- Procedural Continents: Instead of relying on heavy raster textures, I generated 15,000 points arranged on a Fibonacci sphere. I applied multi-octave Simplex noise (`simplex-noise`) to procedurally compute landmass boundaries and ocean grids directly on the GPU.
- Custom Shaders: I wrote GLSL vertex and fragment shaders for the atmospheric glow, calculating normal vectors against camera angles to produce a realistic Fresnel halo.
- Dynamic Attack Arcs: In `ThreatArcs.tsx`, I mapped latitude and longitude coordinates into 3D Cartesian vectors. Using quadratic bezier curves, the system renders arcs from origin cyber hubs to target locations, animating glowing particle light sources and terminal impact ripples.
- Real-Time SSE Feed: The map connects to `/api/telemetry/stream` via my custom React hook `useRealtimeThreats`. It polls the database every two seconds, updating live telemetry metrics, connection latencies, and active threat logs.
- Map HUD Controls: Analysts can filter visible attacks by type (Malware, Phishing, Botnet) or pause the simulation to inspect active telemetry snapshots.

### 3. Automated Threat Ingestion
I developed an ingestion endpoint at `/api/cron/ingest` designed to run on a scheduled cron trigger:
- It queries the abuse.ch URLhaus API for recently reported malicious URLs.
- The payload is sanitized and mapped into the Prisma `ThreatTelemetry` model.
- Batch inserts are written to PostgreSQL, keeping the threat database populated with fresh telemetry data.

### 4. Enterprise Audit Logging
In `AuditLog.tsx`, I created a comprehensive activity feed that monitors scan outcomes, configuration adjustments, and user authentications:
- Interactive Physics: Table rows utilize `framer-motion` spring physics to react with smooth 3D tilt angles based on cursor movement.
- Severity Filtering: Logs can be filtered by execution status (Success, Failed, Pending) and severity levels (Low, Medium, High, Critical).

### 5. Multi-Platform Alert Dispatcher
In `NotificationSetup.tsx` and `/api/notifications`, I built alert integrations for operations teams:
- Discord Webhooks: Sends formatted rich embeds with operational status codes and timestamps directly to configured channels.
- Telegram Bot API: Delivers encrypted push notifications to designated chat IDs using official bot tokens.
- Interactive Setup Wizard: Includes a step-by-step verification process that sends test payloads to validate webhook configurations before activation.

### 6. Design System and Visual Engineering
I crafted the user experience to feel responsive, aesthetic, and professional:
- WebGL Particle Background: Built with custom shaders in `ShaderBackground.tsx`, rendering 15,000 interactive particles that react to cursor coordinates, propagate wave equations, and blend neon gradients.
- Glassmorphism UI: Encapsulated inside `GlassCard.tsx`, combining backdrop blur, subtle borders, and optional cursor-following 3D perspective tilts.
- Physics-Based Controls: Designed `MagneticButton.tsx` with spring physics and light-sweep animations that gravitate toward user hover states.
- Performance Smooth Scrolling: Synchronized Lenis smooth scroll with the GSAP ticker in `LenisProvider.tsx`. I disabled touch synchronization on mobile devices to retain native hardware scrolling performance.
- Kinetic Typography: Engineered text-scramble decoders in `HeroSection.tsx` and a startup preloader in `Preloader.tsx` using GSAP timelines.

---

## Tech Stack

### Core Framework and Language
- Next.js 16 (App Router)
- React 19
- TypeScript 5
- Node.js runtime with native `dns` and `tls` modules

### 3D Graphics and Shaders
- Three.js
- React Three Fiber (`@react-three/fiber`)
- React Three Drei (`@react-three/drei`)
- Simplex Noise (`simplex-noise`)
- Custom GLSL Shaders

### Animations and Styling
- Tailwind CSS v4
- GSAP 3 with ScrollTrigger
- Framer Motion 12
- Lenis (Smooth scroll orchestrator)

### Database and Authentication
- PostgreSQL (Hosted via Supabase or Neon)
- Prisma ORM 7 (`@prisma/client`)
- NextAuth.js v5 (Auth.js beta)
- Google and GitHub OAuth providers

### Reporting and Utilities
- jsPDF and html2canvas (PDF export engine)
- clsx and tailwind-merge (Class composition)
- date-fns (Date formatting)

---

## Repository Structure

```
guardai/
├── prisma/
│   ├── schema.prisma              # Database schema definitions
│   └── prisma.config.ts           # Prisma CLI runtime configuration
├── public/                        # Static assets and icons
├── src/
│   ├── app/                       # Next.js App Router routes
│   │   ├── api/                   # Server endpoints
│   │   │   ├── cron/ingest/       # Automated threat feed ingestion
│   │   │   ├── notifications/     # Webhook dispatcher (Discord, Telegram)
│   │   │   ├── scan/              # URL scanning (POST handler)
│   │   │   │   └── stream/        # Real-time SSE deep scan pipeline
│   │   │   ├── telemetry/stream/  # Real-time SSE threat telemetry stream
│   │   │   └── threats/           # Static threat endpoints
│   │   ├── audit/                 # Audit logging dashboard page
│   │   ├── auth/                  # Authentication pages (login, signup)
│   │   ├── notifications/         # Notification integration management page
│   │   ├── scan/                  # Deep scan interface page
│   │   ├── threats/               # 3D telemetry threat map page
│   │   ├── globals.css            # Tailwind theme tokens and custom styling
│   │   ├── layout.tsx             # Root layout with fonts, preloader, background
│   │   └── page.tsx               # Landing page with capabilities and metrics
│   ├── components/                # React component library
│   │   ├── audit/                 # AuditLog and AuditRow components
│   │   ├── auth/                  # AuthForm and social login triggers
│   │   ├── hero/                  # HeroSection with text scramble animations
│   │   ├── layout/                # Navbar and responsive navigation drawers
│   │   ├── notifications/         # NotificationSetup integration wizard
│   │   ├── preloader/             # Asset decryption initialization screen
│   │   ├── providers/             # Lenis smooth scroll provider
│   │   ├── scan/                  # ScanInterface and PDF generation
│   │   ├── threatmap/             # CyberGlobe, ThreatArcs, and ThreatMap HUD
│   │   ├── ui/                    # GlassCard and MagneticButton primitives
│   │   └── webgl/                 # ShaderBackground particle canvas
│   ├── hooks/                     # Custom React hooks
│   │   └── useRealtimeThreats.ts  # SSE consumer for threat telemetry
│   └── lib/                       # Utility libraries and services
│       ├── auth.ts                # NextAuth provider configurations
│       ├── db.ts                  # Prisma Client singleton
│       ├── gsap.ts                # GSAP registration and helpers
│       ├── heuristics.ts          # Lexical entropy and pattern analysis engine
│       └── utils.ts               # Class merging and interpolation helpers
├── .env.local                     # Local environment configurations
├── next.config.ts                 # Next.js compiler settings
├── package.json                   # Project dependencies and script declarations
├── postcss.config.mjs             # PostCSS plugins
├── tsconfig.json                  # TypeScript compiler configuration
└── README.md                      # Project documentation
```

---

## Database Architecture

I defined the database schema in `prisma/schema.prisma` using PostgreSQL:

- User: Stores credentials, profile details, and account relationships.
- Account: Manages OAuth provider bindings for Google and GitHub accounts.
- Session: Handles active authentication sessions for NextAuth.
- VerificationToken: Secures passwordless or token-based verification workflows.
- Scan: Persists historical scan executions, associated user IDs, risk scores, threat levels, and detailed JSON outputs.
- Notification: Records webhook configurations and operational statuses for Discord and Telegram.
- ThreatTelemetry: Stores geographical coordinates, threat categories, timestamps, and domain names captured from threat feeds.
- ScansAudit: Logs compliance entries, timestamps, and scan execution statuses.

---

## Environment Configuration

To run this platform, I configure the following environment variables in `.env.local`:

```env
# Database Connection
DATABASE_URL="postgresql://user:password@host:port/dbname"

# NextAuth Configuration
NEXTAUTH_URL="http://localhost:3000"
NEXTAUTH_SECRET="your-generated-jwt-secret"

# OAuth Authentication Providers
GOOGLE_CLIENT_ID="your-google-client-id"
GOOGLE_CLIENT_SECRET="your-google-client-secret"
GITHUB_CLIENT_ID="your-github-client-id"
GITHUB_CLIENT_SECRET="your-github-client-secret"

# Threat Intelligence External APIs
VIRUSTOTAL_API_KEY="your-virustotal-api-v3-key"
GOOGLE_SAFE_BROWSING_API_KEY="your-google-safe-browsing-api-key"
ABUSEIPDB_API_KEY="your-abuseipdb-api-key"
```

---

## Getting Started

### Prerequisites
- Node.js 20.x or higher
- pnpm package manager (`pnpm -v`)
- PostgreSQL database instance

### Installation and Setup

1. Clone the repository:
```bash
git clone https://github.com/KatkamKoushik/guardai.git
cd guardai
```

2. Install project dependencies:
```bash
pnpm install
```

3. Generate the Prisma database client:
```bash
pnpm db:generate
```

4. Apply database migrations:
```bash
pnpm db:push
# or
pnpm db:migrate
```

5. Start the development server:
```bash
pnpm dev
```

6. Open your browser and navigate to:
```
http://localhost:3000
```

---

## Available Scripts

I defined several scripts in `package.json` to simplify maintenance:

- `pnpm dev`: Boots the Next.js development server with Turbopack support.
- `pnpm build`: Runs Prisma client generation followed by the Next.js production build.
- `pnpm start`: Launches the compiled production application.
- `pnpm db:generate`: Regenerates the Prisma client library.
- `pnpm db:migrate`: Executes Prisma migration scripts against the configured database.
- `pnpm db:push`: Synchronizes the Prisma schema directly to the database without generating migrations.
- `pnpm db:studio`: Launches Prisma Studio GUI for exploring and managing records.

---

## Security and Engineering Standards

Throughout this project, I prioritized defensive development patterns:
- Zero Hardcoded Secrets: All API keys and connection strings are managed strictly through environment variables.
- Safe Stream Lifecycle: Every Server-Sent Event endpoint includes abort event listeners to release open socket connections and prevent memory leaks.
- Client-Side Hardware Efficiency: WebGL buffers and particle arrays avoid per-frame allocations by pre-allocating typed arrays (`Float32Array`).
- Touch-Safe Scroll Architecture: Smooth scrolling libraries are decoupled from touch events on mobile platforms to prevent GPU overhead and UI jank.
