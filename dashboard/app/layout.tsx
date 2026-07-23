import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "rasmalaaiPi // pwner_telemetry",
  description: "live bare-metal ssh honeypot intercepts",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="bg-black text-green-500 font-mono antialiased min-h-screen">
        {children}
      </body>
    </html>
  );
}
