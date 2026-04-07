"use client";

import { useEffect, useState } from "react";
import io from "socket.io-client";
import { AreaChart, Activity, Shield, ShieldAlert, Cpu } from "lucide-react";

// @ts-ignore
import { Chart as ChartJS, ArcElement, Tooltip as ChartTooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, Title } from "chart.js";
// @ts-ignore
import { Doughnut, Line } from "react-chartjs-2";

ChartJS.register(ArcElement, ChartTooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, Title);

export default function Home() {
  const [stats, setStats] = useState({
    total_packets: 0,
    intrusion_count: 0,
    intrusion_rate: 0,
    attack_types: {},
    recent_alerts: [],
    system_load: 0,
  });

  const [activeTab, setActiveTab] = useState("dashboard");
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const socket = io("http://127.0.0.1:5055");

    socket.on("connect", () => {
      setConnected(true);
      console.log("Connected to Flask backend.");
    });

    socket.on("disconnect", () => {
      setConnected(false);
    });

    socket.on("dashboard_update", (data) => {
      setStats(data);
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  const attackData = {
    labels: Object.keys(stats.attack_types || {}),
    datasets: [
      {
        data: Object.values(stats.attack_types || {}),
        backgroundColor: ["#00f0ff", "#39ff14", "#ff2a2a", "#a855f7", "#eab308"],
        borderColor: "#000",
        borderWidth: 2,
      },
    ],
  };

  return (
    <main className="min-h-screen text-slate-200 uppercase font-mono selection:bg-cyan-500 selection:text-black">
      {/* HEADER */}
      <header className="flex items-center justify-between px-8 py-6 border-b border-cyan-500/20 bg-black/40 backdrop-blur-md">
        <div>
          <h1 className="text-4xl font-black drop-shadow-[0_0_15px_rgba(0,240,255,0.4)] tracking-wide">
            <span className="text-cyan-400">NET</span>SENTINEL
          </h1>
          <p className="text-xs text-gray-500 mt-2 tracking-[0.3em] font-sans font-bold">
            ML-Driven Network Defense Engine // V.Next
          </p>
        </div>
        <div className="flex gap-4">
          <div className="flex items-center gap-2 bg-black/40 border border-cyan-500/20 px-4 py-2 rounded-full shadow-lg">
            <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500 shadow-[0_0_8px_#22c55e]' : 'bg-red-500 shadow-[0_0_8px_#ef4444]'} animate-pulse`}></div>
            <span className="text-xs">BACKEND</span>
          </div>
        </div>
      </header>

      {/* NAV */}
      <nav className="flex px-8 py-3 bg-black/30 backdrop-blur-md border-b border-cyan-500/10 gap-2 overflow-x-auto">
        {["dashboard", "events", "traffic", "history"].map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-sm font-bold tracking-wider transition-all duration-300 ${
              activeTab === tab
                ? "text-cyan-400 border-b-2 border-cyan-400 bg-cyan-400/10 shadow-[0_0_10px_rgba(0,240,255,0.2)]"
                : "text-slate-500 hover:text-white"
            }`}
          >
            {tab}
          </button>
        ))}
      </nav>

      {/* CONTENT */}
      <div className="p-8 max-w-7xl mx-auto animate-in fade-in slide-in-from-bottom-4 duration-500">
        {activeTab === "dashboard" && (
          <div className="space-y-6">
            {/* STATS */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <StatCard title="Packets Analyzed" value={stats.total_packets} icon={<Activity />} color="text-green-400" />
              <StatCard title="Intrusions Detected" value={stats.intrusion_count} icon={<ShieldAlert />} color="text-red-500" />
              <StatCard title="Intrusion Rate" value={`${(stats.intrusion_rate || 0).toFixed(2)}%`} icon={<AreaChart />} color="text-cyan-400" />
            </div>

            {/* CHARTS */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-white/5 border border-cyan-500/20 backdrop-blur-lg rounded-xl p-6 shadow-2xl hover:border-cyan-500/50 transition-colors">
                <h2 className="text-sm text-slate-400 mb-4 font-bold flex items-center gap-2">
                  <Shield size={16} /> ATTACK VECTOR DISTRIBUTION
                </h2>
                <div className="h-64 flex justify-center">
                  {Object.keys(stats.attack_types || {}).length > 0 ? (
                    <Doughnut data={attackData} options={{ maintainAspectRatio: false }} />
                  ) : (
                    <div className="text-slate-500 h-full flex items-center">NO DATA</div>
                  )}
                </div>
              </div>
              <div className="bg-white/5 border border-cyan-500/20 backdrop-blur-lg rounded-xl p-6 shadow-2xl hover:border-cyan-500/50 transition-colors">
                <h2 className="text-sm text-slate-400 mb-4 font-bold flex items-center gap-2">
                  <Cpu size={16} /> SYSTEM LOAD OVERVIEW
                </h2>
                <div className="h-64 flex justify-center items-center text-4xl text-cyan-500 font-bold drop-shadow-[0_0_10px_rgba(0,240,255,0.4)]">
                  {stats.system_load ? stats.system_load.toFixed(2) : "OPTIMAL"}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === "events" && (
          <div className="bg-white/5 border border-cyan-500/20 backdrop-blur-xl p-6 rounded-xl">
            <h2 className="text-xl text-cyan-400 mb-4 font-black">SECURITY EVENT LOG</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm whitespace-nowrap">
                <thead className="bg-black/50 text-cyan-500 border-b-2 border-cyan-500/40">
                  <tr>
                    <th className="p-4 rounded-tl-lg">TIME</th>
                    <th className="p-4">RESULT</th>
                    <th className="p-4">ATTACK TYPE</th>
                    <th className="p-4">SOURCE IP</th>
                    <th className="p-4">LOCATION</th>
                  </tr>
                </thead>
                <tbody>
                  {(stats.recent_alerts || []).map((alert: any, i: number) => (
                    <tr key={i} className={`border-b border-white/5 hover:bg-white/5 transition-colors ${alert.event_type === 'Intrusion' ? 'bg-red-500/10 text-red-400' : ''}`}>
                      <td className="p-4 text-xs">{alert.timestamp}</td>
                      <td className="p-4 font-bold">{alert.result}</td>
                      <td className="p-4">{alert.attack_type}</td>
                      <td className="p-4">{alert.src_ip}</td>
                      <td className="p-4">{alert.src_country || 'N/A'}</td>
                    </tr>
                  ))}
                  {(!stats.recent_alerts || stats.recent_alerts.length === 0) && (
                    <tr><td colSpan={5} className="p-8 text-center text-slate-500">AWAITING LIVE FEED...</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Similar tabs for traffic and history left simple for demonstration */}
        {(activeTab === "traffic" || activeTab === "history") && (
          <div className="flex h-96 items-center justify-center border border-dashed border-cyan-500/20 text-cyan-500/50 rounded-xl bg-white/5 backdrop-blur-sm">
            [ DATA MODULE INITIALIZING ]
          </div>
        )}
      </div>
    </main>
  );
}

function StatCard({ title, value, icon, color }: any) {
  return (
    <div className="bg-white/5 border border-cyan-500/20 backdrop-blur-lg rounded-xl p-6 relative overflow-hidden group hover:border-cyan-400 transition-all shadow-xl hover:shadow-[0_8px_30px_rgba(0,240,255,0.15)] hover:-translate-y-1">
      <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-cyan-400 to-transparent opacity-0 group-hover:opacity-100 transition-opacity"></div>
      <div className="flex justify-between items-start mb-4">
        <h3 className="text-xs text-slate-400 font-bold tracking-widest">{title}</h3>
        <div className={`p-2 bg-white/5 rounded-lg ${color}`}>{icon}</div>
      </div>
      <div className={`text-5xl font-black drop-shadow-md tracking-tighter ${color} drop-shadow-[0_0_15px_currentColor]`}>{value}</div>
    </div>
  );
}
