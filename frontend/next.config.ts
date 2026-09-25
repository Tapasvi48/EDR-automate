import type { NextConfig } from "next";

const isDev = process.env.NODE_ENV === "development";
const API = process.env.API_ORIGIN || "http://127.0.0.1:8765";

// Production: static export (frontend/out) served by FastAPI on one port.
// Development: `npm run dev` on :3000 proxies /api to the FastAPI backend.
const nextConfig: NextConfig = isDev
  ? {
      async rewrites() {
        return [{ source: "/api/:path*", destination: `${API}/api/:path*` }];
      },
    }
  : {
      output: "export",
      trailingSlash: true,
      images: { unoptimized: true },
      typescript: { ignoreBuildErrors: true },
    };

export default nextConfig;
