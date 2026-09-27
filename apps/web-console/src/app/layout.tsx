import type { Metadata } from "next";
import "./globals.css";
import { Sidebar } from "@/components/Sidebar";
import { ThemeProvider } from "@/components/theme-provider";
import { ThemeToggle } from "@/components/theme-toggle";
import { CyberBackground } from "@/components/CyberBackground";
import { Bell, UserCheck } from "lucide-react";

export const metadata: Metadata = {
  title: "Document Attribution Platform - Government of India",
  description: "Cryptographic Document Security & Forensic Leak Attribution Platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className="h-full antialiased"
    >
      <body className="min-h-full flex flex-col bg-(--gov-bg) text-(--gov-text-primary) font-sans relative selection:bg-sky-500/20 selection:text-sky-900 dark:selection:text-sky-200">
        <ThemeProvider
          attribute="class"
          defaultTheme="light"
          enableSystem
          disableTransitionOnChange
        >
          {/* Cyber Ambient Background Layer */}
          <CyberBackground />

          {/* Official GOI Top Command Header */}
          <header 
            className="relative z-10 flex justify-between items-center px-6 py-2.5 shrink-0 bg-slate-950 text-slate-100 border-b-2 border-(--gov-saffron) shadow-md"
          >
            <div className="flex items-center gap-4">
              <div className="flex flex-col">
                <div className="flex items-center gap-2">
                  <span className="text-white font-bold text-base tracking-wide flex items-center gap-1.5">
                    🇮🇳 Government of India
                  </span>
                  <span className="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase bg-emerald-950/80 text-emerald-400 border border-emerald-500/30">
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    SOC-1 SECURE
                  </span>
                </div>
                <span className="text-slate-400 text-xs font-medium tracking-wider">
                  CRYPTOGRAPHIC DOCUMENT SECURITY & ATTRIBUTION PLATFORM
                </span>
              </div>
            </div>

            <div className="flex items-center gap-3 text-slate-200 text-xs font-medium">
              <ThemeToggle />
              
              <button 
                type="button"
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-900/80 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 transition-colors"
                title="System Notifications"
              >
                <Bell className="w-3.5 h-3.5 text-sky-400" />
                <span>Alerts (0)</span>
              </button>

              <div className="flex items-center gap-2 border-l border-slate-800 pl-3">
                <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-slate-200">
                  <div className="p-1 rounded bg-sky-950 text-sky-400 border border-sky-800/50">
                    <UserCheck className="w-3.5 h-3.5" />
                  </div>
                  <div className="flex flex-col text-left">
                    <span className="font-semibold text-xs text-slate-100">Document Officer</span>
                    <span className="text-[10px] font-mono text-slate-400">Clearance: TopSecret</span>
                  </div>
                </div>
              </div>
            </div>
          </header>

          {/* Core Shell Layout */}
          <div className="relative z-10 flex flex-1 overflow-hidden">
            <Sidebar />

            {/* Main Content Area */}
            <main className="flex-1 overflow-y-auto p-6 lg:p-8">
              {children}
            </main>
          </div>
        </ThemeProvider>
      </body>
    </html>
  );
}
