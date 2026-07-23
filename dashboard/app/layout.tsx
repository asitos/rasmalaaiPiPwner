import "./globals.css";

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <title>rasmalaaiPi // pwner_telemetry</title>
      </head>
      <body className="bg-black text-green-500 font-mono antialiased min-h-screen">
        {children}
      </body>
    </html>
  );
}
