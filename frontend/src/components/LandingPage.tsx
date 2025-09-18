import React from "react";
import { Link } from "react-router-dom";

/**
 * Polished landing page with a glass "arc" hero, Framer Motion micro‑interactions,
 * and a focused CTA (Ready to dive in?). Teacher badge + old footer removed.
 *
 * Drop-in Tailwind only. No external CSS.
 */

const btn =
  "inline-flex items-center justify-center rounded-xl px-5 py-3 font-semibold shadow-sm ring-1 ring-slate-200 hover:shadow transition focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-blue-500";
const btnPrimary = "bg-blue-600 text-white ring-0 hover:bg-blue-700 active:bg-blue-800";
const btnGhost = "bg-white text-slate-800";

const GlassArc: React.FC = () => (
  <div className="relative isolate mx-auto max-w-6xl px-6 pt-20 md:pt-26">
    {/* Radial glow background */}
    <div
      className="pointer-events-none absolute inset-0 -z-10 [mask-image:radial-gradient(60%_60%_at_50%_20%,black,transparent)]"
      aria-hidden
    >
      <div className="absolute left-1/2 top-[-20rem] h-[48rem] w-[48rem] -translate-x-1/2 rounded-full bg-gradient-to-tr from-blue-300/60 via-indigo-200/50 to-cyan-200/50 blur-3xl" />
    </div>

    {/* Glass arc frame */}
    <div className="relative overflow-hidden rounded-[2rem] border border-white/60 bg-white/30 p-[1px] shadow-[0_8px_30px_rgba(0,0,0,0.08)] backdrop-blur-xl">
      <div className="rounded-[2rem] bg-white/65 p-8 md:p-12">
        {/* Arc top using SVG */}
        <div className="relative mx-auto mb-8 h-24 w-full max-w-3xl">
          <svg viewBox="0 0 1200 240" className="absolute inset-0 h-full w-full" aria-hidden>
            <defs>
              <linearGradient id="arc" x1="0" x2="1" y1="0" y2="0">
                <stop offset="0%" stopColor="#93c5fd" stopOpacity="0.9" />
                <stop offset="50%" stopColor="#a5b4fc" stopOpacity="0.9" />
                <stop offset="100%" stopColor="#67e8f9" stopOpacity="0.9" />
              </linearGradient>
            </defs>
            <path
              d="M 50 220 C 350 10 850 10 1150 220"
              fill="none"
              stroke="url(#arc)"
              strokeWidth="18"
              strokeLinecap="round"
              opacity="0.9"
            />
          </svg>
        </div>

        {/* Heading + subcopy */}
        <h1 className="text-center text-4xl font-extrabold tracking-tight text-slate-900 md:text-5xl">
          Hello Sir Abdur Raafay 👋
        </h1>
        <p className="mx-auto mt-4 max-w-3xl text-center text-lg text-slate-600 md:text-xl">
          Welcome to <span className="font-semibold text-slate-900">Haseeb's Vulnerable Web Application</span> — a professional lab built to explore and secure real‑world web vulnerabilities.
        </p>

        {/* Feature chips */}
        <ul className="mx-auto mt-6 flex flex-wrap justify-center gap-2">
          {["SQLi", "XSS", "IDOR", "Session", "SSRF/LFI"].map((t) => (
            <li
              key={t}
              className="rounded-full border border-slate-200 bg-white/80 px-3 py-1 text-sm text-slate-700 backdrop-blur"
            >
              {t}
            </li>
          ))}
        </ul>

        {/* CTA – Ready to dive in? */}
        <div className="mt-8 text-center">
          <h2 className="text-2xl font-bold text-slate-900">Ready to dive in?</h2>
          <p className="mt-2 text-slate-600">Start with the labs or jump straight to your account.</p>
          <div className="mt-6 flex flex-wrap justify-center gap-3">
            <Link to="/security-lab" className={`${btn} ${btnPrimary}`}>
              Open Security Lab
            </Link>
            <Link to="/login" className={`${btn} ${btnGhost}`}>
              Go to Login
            </Link>
          </div>
        </div>
      </div>

      {/* Decorative bottom arc shimmer */}
      <div
        aria-hidden
        className="pointer-events-none mt-10 h-10 w-full"
      >
        <div className="mx-auto h-full w-2/3 rounded-full bg-gradient-to-r from-blue-200/50 via-indigo-200/50 to-cyan-200/50 blur-2xl" />
      </div>
    </div>
  </div>
);

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-slate-50">
      {/* HERO with glass arc */}
      <section className="relative overflow-hidden pb-10">
        <GlassArc />
      </section>

      {/* Feature highlight cards under the arc */}
      <section className="mx-auto max-w-6xl px-6 pb-20">
        <div className="grid gap-6 md:grid-cols-2">
          

          
        </div>
      </section>
    </div>
  );
}
