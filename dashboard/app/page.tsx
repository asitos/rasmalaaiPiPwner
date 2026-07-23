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
    // this url pulls the live json directly from your github repo's main branch
    const fetchTelemetry = async () => {
      try {
        const res = await fetch('https://raw.githubusercontent.com/asitos/rasmalaaiPiPwner/main/captures.json', {
          cache: 'no-store' // bypass next.js aggressive caching
        });
        const data = await res.json();
        setCaptures(data);
      } catch (error) {
        console.error("failed to fetch honeypot state", error);
      } finally {
        setLoading(false);
      }
    };
    
    // fetch immediately, then poll every 15 seconds
    fetchTelemetry();
    const interval = setInterval(fetchTelemetry, 15000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-black text-green-500 font-mono text-sm">
        [+] establishing secure connection to edge telemetry...
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-green-500 font-mono p-4 md:p-8 selection:bg-green-500 selection:text-black">
      <div className="max-w-6xl mx-auto">
        <header className="mb-8 border-b border-green-900/50 pb-4">
          <h1 className="text-2xl md:text-3xl font-bold tracking-tighter">rasmalaaiPi // pwner_telemetry</h1>
          <p className="text-green-700/80 mt-2 text-sm">live daemon intercepts from bare-metal edge network.</p>
        </header>

        <div className="overflow-x-auto border border-green-900/50 rounded-sm bg-[#050505]">
          <table className="w-full text-left border-collapse whitespace-nowrap">
            <thead>
              <tr className="bg-green-950/30 text-green-600 text-xs uppercase tracking-widest border-b border-green-900/50">
                <th className="p-4 font-semibold">id</th>
                <th className="p-4 font-semibold">timestamp (utc)</th>
                <th className="p-4 font-semibold">source ip</th>
                <th className="p-4 font-semibold">username</th>
                <th className="p-4 font-semibold">password</th>
              </tr>
            </thead>
            <tbody className="text-sm">
              {captures.map((cap) => (
                <tr key={cap.id} className="border-b border-green-900/20 hover:bg-green-900/10 transition-colors">
                  <td className="p-4 text-green-700/60">#{cap.id}</td>
                  <td className="p-4 text-green-600/80">{cap.timestamp}</td>
                  <td className="p-4">{cap.ip}</td>
                  <td className="p-4 font-bold text-green-400">{cap.username}</td>
                  <td className="p-4 text-red-500/90">{cap.password}</td>
                </tr>
              ))}
            </tbody>
          </table>
          
          {captures.length === 0 && (
            <div className="p-8 text-center text-green-800/50 text-sm animate-pulse">
              [ buffer empty : waiting for incoming threats ]
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
