import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { headers } from "next/headers";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

const title = "Vibe Cyber V.1.0 | Vibe Coders Security Hand Tool";
const description = "Vibe Coders Security Hand Tool";

function requestOrigin(requestHeaders: Headers) {
  const directHost = requestHeaders.get("host")?.trim();
  const forwardedHost = requestHeaders.get("x-forwarded-host")?.split(",")[0];
  const host = (directHost || forwardedHost || "").trim();
  const validHost = /^(?:localhost|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::\d{1,5})?$/i.test(
    host,
  );

  if (!validHost) return "https://webcyber.dev";

  const forwardedProto = requestHeaders
    .get("x-forwarded-proto")
    ?.split(",")[0]
    .trim();
  const protocol =
    forwardedProto === "http" || forwardedProto === "https"
      ? forwardedProto
      : host.startsWith("localhost")
        ? "http"
        : "https";

  return `${protocol}://${host}`;
}

export async function generateMetadata(): Promise<Metadata> {
  const requestHeaders = await headers();
  const socialImage = new URL("/og.png", requestOrigin(requestHeaders)).href;

  return {
    title,
    description,
    applicationName: "Vibe Cyber V.1.0",
    openGraph: {
      type: "website",
      locale: "en_US",
      siteName: "Vibe Cyber V.1.0",
      title,
      description,
      images: [
        {
          url: socialImage,
          width: 1731,
          height: 909,
          alt: "Vibe Cyber V.1.0 - Vibe Coders Security Hand Tool",
        },
      ],
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      images: [socialImage],
    },
  };
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable}`}>
        {children}
      </body>
    </html>
  );
}
