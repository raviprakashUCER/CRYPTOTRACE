import React from 'react';

export function CyberBackground() {
  return (
    <div 
      className="fixed inset-0 pointer-events-none z-0 overflow-hidden" 
      aria-hidden="true"
    >
      {/* Subtle Atmospheric Gradient Glows */}
      <div className="absolute top-0 left-1/4 w-[600px] h-[400px] bg-sky-500/5 dark:bg-sky-400/5 rounded-full blur-3xl transform -translate-y-1/2" />
      <div className="absolute bottom-0 right-1/4 w-[500px] h-[500px] bg-indigo-500/4 dark:bg-cyan-500/4 rounded-full blur-3xl transform translate-y-1/3" />
      <div className="absolute top-1/2 right-10 w-[300px] h-[300px] bg-blue-600/3 dark:bg-blue-400/3 rounded-full blur-2xl" />

      {/* High-Tech Vector Grid Pattern */}
      <svg 
        className="absolute inset-0 w-full h-full opacity-[0.035] dark:opacity-[0.065] text-slate-800 dark:text-sky-400"
        xmlns="http://www.w3.org/2000/svg"
        width="100%"
        height="100%"
      >
        <defs>
          <pattern id="cyber-grid" width="48" height="48" patternUnits="userSpaceOnUse">
            <path d="M 48 0 L 0 0 0 48" fill="none" stroke="currentColor" strokeWidth="0.8" />
            <circle cx="48" cy="0" r="1.5" fill="currentColor" />
            <circle cx="0" cy="48" r="1.5" fill="currentColor" />
          </pattern>
          <pattern id="circuit-nodes" width="192" height="192" patternUnits="userSpaceOnUse">
            <path d="M 24 24 L 72 24 L 96 48 L 144 48 L 168 24" fill="none" stroke="currentColor" strokeWidth="1" strokeDasharray="4 2" />
            <circle cx="24" cy="24" r="2.5" fill="currentColor" />
            <circle cx="168" cy="24" r="2.5" fill="currentColor" />
            <path d="M 96 144 L 96 96 L 144 96 L 168 120" fill="none" stroke="currentColor" strokeWidth="1" />
            <circle cx="96" cy="144" r="2" fill="currentColor" />
            <circle cx="168" cy="120" r="2" fill="currentColor" />
            <path d="M 48 120 L 48 168 L 120 168" fill="none" stroke="currentColor" strokeWidth="0.8" />
            <circle cx="48" cy="120" r="2" fill="currentColor" />
            <circle cx="120" cy="168" r="2" fill="currentColor" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#cyber-grid)" />
        <rect width="100%" height="100%" fill="url(#circuit-nodes)" />
      </svg>
    </div>
  );
}
