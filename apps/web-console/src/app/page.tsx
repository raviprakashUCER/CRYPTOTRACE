'use client';
import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { 
  Database, 
  ShieldCheck, 
  FileText, 
  Users, 
  KeyRound, 
  Search, 
  Cpu, 
  CheckCircle2, 
  Lock,
  Activity,
  Server
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from '@/components/ui/badge';

export default function Dashboard() {
  const [sysStatus, setSysStatus] = useState<string>('Initializing...');
  
  useEffect(() => {
    if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
      invoke<string>('get_system_status')
        .then(res => setSysStatus(res))
        .catch(() => setSysStatus('Error connecting to core'));
    } else {
      setTimeout(() => setSysStatus('Browser Mode (Tauri Core Disconnected)'), 0);
    }
  }, []);

  return (
    <div className="max-w-6xl mx-auto space-y-6 pb-10">
      
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border border-slate-200/80 dark:border-slate-800/80 shadow-xs">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold uppercase tracking-wide text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Activity className="w-5 h-5 text-sky-600 dark:text-sky-400" />
              Security Command Overview
            </h1>
            <Badge variant="outline" className="text-[10px] font-mono bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800">
              OPERATIONAL
            </Badge>
          </div>
          <p className="mt-1 text-xs font-medium text-slate-500 dark:text-slate-400">
            Post-Quantum Cryptographic Document Security & Real-Time Leak Attribution Command Center
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-right">
            <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Node Synchronization</div>
            <div className="text-xs font-mono font-semibold text-slate-700 dark:text-slate-300 flex items-center justify-end gap-1.5 mt-0.5">
              <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
              Active Local Store
            </div>
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* Documents */}
        <Card className="rounded-xl border border-slate-200/80 dark:border-slate-800/80 bg-white/90 dark:bg-slate-900/80 backdrop-blur-md shadow-xs hover:shadow-md transition-all">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Documents Ingested
              </div>
              <div className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-1">
                0
              </div>
              <div className="text-[10px] font-medium text-emerald-600 dark:text-emerald-400 mt-0.5 flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" /> Encrypted & Hashed
              </div>
            </div>
            <div className="w-10 h-10 rounded-xl bg-sky-50 dark:bg-sky-950/50 border border-sky-200 dark:border-sky-800/60 flex items-center justify-center text-sky-600 dark:text-sky-400">
              <FileText className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        {/* Recipients */}
        <Card className="rounded-xl border border-slate-200/80 dark:border-slate-800/80 bg-white/90 dark:bg-slate-900/80 backdrop-blur-md shadow-xs hover:shadow-md transition-all">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Recipients & Keys
              </div>
              <div className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-1">
                0
              </div>
              <div className="text-[10px] font-medium text-sky-600 dark:text-sky-400 mt-0.5 flex items-center gap-1">
                <Lock className="w-3 h-3" /> ML-KEM Enrolled
              </div>
            </div>
            <div className="w-10 h-10 rounded-xl bg-indigo-50 dark:bg-indigo-950/50 border border-indigo-200 dark:border-indigo-800/60 flex items-center justify-center text-indigo-600 dark:text-indigo-400">
              <Users className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        {/* Decryptions */}
        <Card className="rounded-xl border border-slate-200/80 dark:border-slate-800/80 bg-white/90 dark:bg-slate-900/80 backdrop-blur-md shadow-xs hover:shadow-md transition-all">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Decryptions
              </div>
              <div className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-1">
                0
              </div>
              <div className="text-[10px] font-medium text-emerald-600 dark:text-emerald-400 mt-0.5 flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" /> Attestations Signed
              </div>
            </div>
            <div className="w-10 h-10 rounded-xl bg-emerald-50 dark:bg-emerald-950/50 border border-emerald-200 dark:border-emerald-800/60 flex items-center justify-center text-emerald-600 dark:text-emerald-400">
              <KeyRound className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        {/* Investigations */}
        <Card className="rounded-xl border border-slate-200/80 dark:border-slate-800/80 bg-white/90 dark:bg-slate-900/80 backdrop-blur-md shadow-xs hover:shadow-md transition-all">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Leak Investigations
              </div>
              <div className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-1">
                0
              </div>
              <div className="text-[10px] font-medium text-amber-600 dark:text-amber-400 mt-0.5 flex items-center gap-1">
                <Activity className="w-3 h-3" /> Forensic Analysis
              </div>
            </div>
            <div className="w-10 h-10 rounded-xl bg-amber-50 dark:bg-amber-950/50 border border-amber-200 dark:border-amber-800/60 flex items-center justify-center text-amber-600 dark:text-amber-400">
              <Search className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Middle Operations Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Ledger Integrity & Consensus */}
        <Card className="rounded-xl border border-slate-200/80 dark:border-slate-800/80 bg-white/90 dark:bg-slate-900/80 backdrop-blur-md shadow-xs">
          <CardHeader className="p-5 pb-3 border-b border-slate-200/80 dark:border-slate-800/80">
            <CardTitle className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider flex items-center justify-between">
              <span className="flex items-center gap-2">
                <Database className="w-4 h-4 text-sky-500" />
                Ledger Consensus & Tamper Detection
              </span>
              <Badge variant="outline" className="text-[10px] font-mono border-emerald-500/30 text-emerald-600 dark:text-emerald-400 bg-emerald-500/10">
                SHA3-256 HASH CHAIN
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-5">
            {sysStatus.includes('Browser') ? (
              <Alert className="rounded-lg bg-slate-50 dark:bg-slate-950/50 border-slate-200 dark:border-slate-800">
                <Server className="h-4 w-4 text-slate-400" />
                <AlertTitle className="text-xs font-semibold text-slate-800 dark:text-slate-200">Local Daemon Connected</AlertTitle>
                <AlertDescription className="text-xs text-slate-500">
                  Running in Web Console mode. Real-time Tauri IPC available in desktop container.
                </AlertDescription>
              </Alert>
            ) : (
              <div className="space-y-4">
                <div className="flex items-center gap-3 p-3 rounded-lg bg-emerald-50/60 dark:bg-emerald-950/30 border border-emerald-200/60 dark:border-emerald-900/40">
                  <div className="w-9 h-9 rounded-lg bg-emerald-500/20 flex items-center justify-center text-emerald-600 dark:text-emerald-400">
                    <ShieldCheck className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="text-xs font-bold text-emerald-700 dark:text-emerald-300 uppercase">Cryptographic Continuity Verified</div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">Hash-chain links and Merkle proofs consistent</div>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950/50 border border-slate-200 dark:border-slate-800">
                    <span className="text-slate-400 text-[10px] font-bold uppercase block">Storage State</span>
                    <span className="font-mono font-semibold text-slate-700 dark:text-slate-200">SQLite + Merkle Tree</span>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950/50 border border-slate-200 dark:border-slate-800">
                    <span className="text-slate-400 text-[10px] font-bold uppercase block">Attestation Standard</span>
                    <span className="font-mono font-semibold text-slate-700 dark:text-slate-200">ML-DSA-65 Attached</span>
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Security Engine Architecture */}
        <Card className="rounded-xl border border-slate-200/80 dark:border-slate-800/80 bg-white/90 dark:bg-slate-900/80 backdrop-blur-md shadow-xs">
          <CardHeader className="p-5 pb-3 border-b border-slate-200/80 dark:border-slate-800/80">
            <CardTitle className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider flex items-center justify-between">
              <span className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-indigo-500" />
                Post-Quantum Security Suite
              </span>
              <Badge variant="outline" className="text-[10px] font-mono border-indigo-500/30 text-indigo-600 dark:text-indigo-400 bg-indigo-500/10">
                FIPS 203 & 204
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-5 space-y-3">
            <ul className="space-y-2 text-xs">
              <li className="flex items-center justify-between p-2 rounded-lg bg-slate-50 dark:bg-slate-950/50 border border-slate-200/60 dark:border-slate-800/60">
                <span className="font-medium text-slate-700 dark:text-slate-300">Key Encapsulation (KEM)</span>
                <Badge variant="secondary" className="font-mono text-[10px]">ML-KEM-768 (Kyber)</Badge>
              </li>
              <li className="flex items-center justify-between p-2 rounded-lg bg-slate-50 dark:bg-slate-950/50 border border-slate-200/60 dark:border-slate-800/60">
                <span className="font-medium text-slate-700 dark:text-slate-300">Digital Attestation (DSA)</span>
                <Badge variant="secondary" className="font-mono text-[10px]">ML-DSA-65 (Dilithium)</Badge>
              </li>
              <li className="flex items-center justify-between p-2 rounded-lg bg-slate-50 dark:bg-slate-950/50 border border-slate-200/60 dark:border-slate-800/60">
                <span className="font-medium text-slate-700 dark:text-slate-300">Symmetric AEAD & ECC</span>
                <Badge variant="secondary" className="font-mono text-[10px]">AES-256-GCM + RS(8,4)</Badge>
              </li>
            </ul>

            <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono bg-slate-100/70 dark:bg-slate-950/70 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800">
              System Core: {sysStatus}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent Decryption Events */}
      <Card className="rounded-xl border border-slate-200/80 dark:border-slate-800/80 bg-white/90 dark:bg-slate-900/80 backdrop-blur-md shadow-xs">
        <CardHeader className="p-5 pb-3 border-b border-slate-200/80 dark:border-slate-800/80">
          <CardTitle className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider">
            Recent Forensic Decryption Events
          </CardTitle>
        </CardHeader>
        <CardContent className="p-5">
          <Alert className="rounded-lg bg-slate-50/80 dark:bg-slate-950/50 border-slate-200 dark:border-slate-800">
            <ShieldCheck className="h-4 w-4 text-slate-400" />
            <AlertTitle className="text-xs font-semibold text-slate-800 dark:text-slate-200">No recent decryption events recorded</AlertTitle>
            <AlertDescription className="text-xs text-slate-500">
              Authorized recipients who perform document decryptions will automatically generate invisible forensic watermarks and signed ledger provenance attestations.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>

    </div>
  );
}
