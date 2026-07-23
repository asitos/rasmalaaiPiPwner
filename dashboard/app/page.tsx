'use client';
import { useEffect, useState } from 'react';

interface Capture {
  id: number;
  ip: string;
  username: string;
  password: string;
  timestamp: string;
}

export default function HoneypotDashboard() {
  const [captures, setCaptures] = useState<Capture[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchTelemetry = async () => {
      try {
        const res = await fetch(`https://raw.githubusercontent.com/asitos/rasmalaaiPiPwner/main/captures.json?t=${Date.now()}`, {
          cache: 'no-store'
        });
        const data = await res.json();
        setCaptures(data);
      } catch (error) {
        console.error("failed to fetch honeypot state", error);
      } finally {
        setLoading(false);
      }
    };
    
    fetchTelemetry();
    const interval = setInterval(fetchTelemetry, 15000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-black text-green-500 font-mono text-sm animate-pulse">
        [+] establishing secure connection to edge telemetry...
      </div>
    );
  }

  return (
    <div className="relative min-h-screen bg-black text-green-500 font-mono p-4 md:p-8 selection:bg-green-500 selection:text-black overflow-hidden">
      {/* subtle crt scanline overlay */}
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_4px,3px_100%] z-50 opacity-20"></div>
      
      <div className="max-w-6xl mx-auto relative z-10">
        <header className="mb-10 border-b border-green-900/60 pb-6">
          <h1 className="text-3xl md:text-4xl font-bold tracking-tighter" style={{ textShadow: '0 0 10px rgba(34, 197, 94, 0.4)' }}>
            rasmalaaiPi // pwner_telemetry
          </h1>
          <p className="text-green-600/80 mt-2 text-sm tracking-wide">live daemon intercepts from bare-metal edge network.</p>
        </header>

        <div className="overflow-x-auto border border-green-900/60 rounded bg-black shadow-[0_0_15px_rgba(34,197,94,0.05)]">
          <table className="w-full text-left border-collapse whitespace-nowrap">
            <thead>
              <tr className="bg-green-950/20 text-green-500/80 text-xs uppercase tracking-widest border-b border-green-900/60">
                <th className="p-5 font-semibold">id</th>
                <th className="p-5 font-semibold">timestamp (utc)</th>
                <th className="p-5 font-semibold">source ip</th>
                <th className="p-5 font-semibold">username</th>
                <th className="p-5 font-semibold">password</th>
              </tr>
            </thead>
            <tbody className="text-sm">
              {captures.map((cap) => (
                <tr key={cap.id} className="border-b border-green-900/30 hover:bg-green-900/20 transition-colors duration-150">
                  <td className="p-5 text-green-700/70">#{cap.id}</td>
                  <td className="p-5 text-green-600">{cap.timestamp}</td>
                  <td className="p-5 font-medium">{cap.ip}</td>
                  {/* regex cleans the existing dirty database entries on the fly */}
                  <td className="p-5 font-bold text-green-400">{cap.username.replace(/^\.+|\.+$/g, '')}</td>
                  <td className="p-5 text-red-500/90 tracking-wide font-medium">{cap.password.replace(/^\.+|\.+$/g, '')}</td>
                </tr>
              ))}
            </tbody>
          </table>
          
          {captures.length === 0 && (
            <div className="p-10 text-center text-green-800/60 text-sm animate-pulse tracking-widest">
              [ buffer empty : waiting for incoming threats ]
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
