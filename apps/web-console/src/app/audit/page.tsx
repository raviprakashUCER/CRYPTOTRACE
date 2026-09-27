'use client';
import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { RefreshCw, ShieldCheck, FileSpreadsheet, Lock, Clock, User, CheckCircle, AlertTriangle } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

interface AuditLogRecord {
  id: number;
  action: string;
  actor_id: string;
  target_resource: string;
  details: string;
  timestamp: string;
  status: string;
}

export default function AuditPage() {
  const [logs, setLogs] = useState<AuditLogRecord[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
        const res = await invoke<AuditLogRecord[]>('get_audit_logs');
        setLogs(res);
      }
    } catch (e) {
      console.error(e);
    }
    setLoading(false);
  };

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    fetchLogs();
  }, []);

  return (
    <div className="max-w-6xl mx-auto space-y-6 pb-10">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border border-slate-200/80 dark:border-slate-800/80 shadow-xs">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold uppercase tracking-wide text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
              System Audit & Governance Trail
            </h1>
            <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-300 border border-sky-300 dark:border-sky-800">
              IMMUTABLE LOG
            </span>
          </div>
          <p className="mt-1 text-xs font-medium text-slate-500 dark:text-slate-400">
            Append-only cryptographic audit trail documenting document ingestions, key distributions, decryptions, and forensic investigations.
          </p>
        </div>
        <Button
          onClick={fetchLogs}
          disabled={loading}
          variant="outline"
          className="text-xs flex items-center gap-1.5 border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 shadow-xs"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh Trail
        </Button>
      </div>

      {/* Main Audit Trail Card */}
      <Card className="rounded-xl border border-slate-200/80 dark:border-slate-800/80 overflow-hidden bg-white/90 dark:bg-slate-900/80 backdrop-blur-md shadow-xs">
        <CardContent className="p-0">
          {loading ? (
            <div className="p-16 flex flex-col items-center justify-center text-center space-y-3">
              <RefreshCw className="w-8 h-8 text-sky-500 animate-spin" />
              <div className="text-sm font-medium text-slate-600 dark:text-slate-400 font-mono">
                Loading cryptographic audit records from persistent store...
              </div>
            </div>
          ) : logs.length === 0 ? (
            <div className="p-16 flex flex-col items-center justify-center text-center max-w-md mx-auto space-y-4">
              <div className="w-16 h-16 rounded-2xl bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 flex items-center justify-center shadow-inner">
                <FileSpreadsheet className="w-8 h-8 text-slate-400 dark:text-slate-500" />
              </div>
              <div className="space-y-1">
                <h3 className="text-sm font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
                  No Audit Log Records Found
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                  System operations, recipient key resolutions, document dispatches, and forensic leak verifications will be immutably recorded in this tamper-evident trail.
                </p>
              </div>
              <Button
                onClick={fetchLogs}
                variant="outline"
                size="sm"
                className="text-xs flex items-center gap-1.5 border-slate-300 dark:border-slate-700 mt-2"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                Query Ledger Events
              </Button>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/60">
                  <TableHead className="text-slate-600 dark:text-slate-400 font-bold uppercase tracking-wider text-[11px] py-3.5">
                    <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> Timestamp</span>
                  </TableHead>
                  <TableHead className="text-slate-600 dark:text-slate-400 font-bold uppercase tracking-wider text-[11px] py-3.5">
                    <span className="flex items-center gap-1"><User className="w-3 h-3" /> Actor</span>
                  </TableHead>
                  <TableHead className="text-slate-600 dark:text-slate-400 font-bold uppercase tracking-wider text-[11px] py-3.5">
                    <span className="flex items-center gap-1"><Lock className="w-3 h-3" /> Action</span>
                  </TableHead>
                  <TableHead className="text-slate-600 dark:text-slate-400 font-bold uppercase tracking-wider text-[11px] py-3.5">
                    Target Resource
                  </TableHead>
                  <TableHead className="text-slate-600 dark:text-slate-400 font-bold uppercase tracking-wider text-[11px] py-3.5">
                    Status
                  </TableHead>
                  <TableHead className="text-slate-600 dark:text-slate-400 font-bold uppercase tracking-wider text-[11px] py-3.5">
                    Details
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {logs.map((log) => (
                  <TableRow key={log.id} className="border-b border-slate-200/70 dark:border-slate-800/70 hover:bg-slate-50/60 dark:hover:bg-slate-800/40 text-xs transition-colors">
                    <TableCell className="font-mono text-slate-500 dark:text-slate-400 whitespace-nowrap py-3">
                      {log.timestamp.substring(0, 19).replace('T', ' ')}
                    </TableCell>
                    <TableCell className="font-semibold text-slate-900 dark:text-slate-100 py-3">
                      {log.actor_id}
                    </TableCell>
                    <TableCell className="py-3">
                      <Badge variant="outline" className="font-mono text-[11px] bg-slate-50 dark:bg-slate-900 border-slate-300 dark:border-slate-700">
                        {log.action}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-slate-600 dark:text-slate-300 py-3">
                      {log.target_resource}
                    </TableCell>
                    <TableCell className="py-3">
                      <Badge className={
                        log.status === 'SUCCESS' || log.status === 'COMPLETED'
                          ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800'
                          : log.status === 'FAILED' || log.status === 'ERROR'
                          ? 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300 border-rose-300 dark:border-rose-800'
                          : 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border-amber-300 dark:border-amber-800'
                      }>
                        {log.status === 'SUCCESS' || log.status === 'COMPLETED' ? (
                          <CheckCircle className="w-3 h-3 mr-1 inline" />
                        ) : (
                          <AlertTriangle className="w-3 h-3 mr-1 inline" />
                        )}
                        {log.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-slate-600 dark:text-slate-300 py-3 max-w-xs truncate" title={log.details}>
                      {log.details}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
