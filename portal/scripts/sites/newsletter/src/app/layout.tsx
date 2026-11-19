import type { Metadata } from "next";
import { Fredoka, Nunito } from "next/font/google";
import "./globals.css";

const display = Fredoka({
  subsets: ["latin"],
  variable: "--font-display",
  weight: ["400", "500", "600", "700"],
});

const body = Nunito({
  subsets: ["latin"],
  variable: "--font-body",
  weight: ["400", "600", "700", "800"],
});

export const metadata: Metadata = {
  title: "Sunshine Second Grade",
  description: "Family website for our second grade class — gated with 2FA.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${display.variable} ${body.variable} font-[family-name:var(--font-body)] antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
