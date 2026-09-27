'use client';
import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Download, Search, SearchCode, AlertTriangle } from 'lucide-react';

interface EvidenceItem {
  code: string;
  description: string;
  passed: boolean;
  impact: string;
}

interface WatermarkRecoveryMetrics {
  shards_total: number;
  shards_recovered: number;
  shards_erased: number;
  recovery_rate_percent: number;
  layers_detected: string[];
  redundancy_level: string;
}

interface ForensicConfidence {
  score: number;
  band: 'High' | 'Medium' | 'Low' | 'None';
  explanation: string[];
}

interface ForensicReport {
  is_match: boolean;
  status: 'VerifiedAttribution' | 'DegradedEvidence' | 'InsufficientEvidence' | 'TamperedEvidence' | 'NoAttributionFound' | string;
  investigation_id: string;
  investigated_file: string;
  file_hash: string;
  watermark_status: string;
  event_id: string;
  recipient_id: string;
  document_matched: boolean;
  signature_valid: boolean;
  ledger_valid: boolean;
  key_status: string;
  current_key_status: string;
  event_time_key_status: string;
  merkle_proof_valid?: boolean;
  watermark_metrics: WatermarkRecoveryMetrics;
  confidence_score: string;
  confidence: ForensicConfidence;
  evidence: EvidenceItem[];
  warnings: string[];
  limitations: string[];
  investigation_timestamp: string;
}

export default function Forensics() {
  const [filename, setFilename] = useState('DEFENCE_PLAN.md');
  const [leakedText, setLeakedText] = useState('');
  const [expectedHash, setExpectedHash] = useState('');
  const [report, setReport] = useState<ForensicReport | null>(null);
  const [pipelineState, setPipelineState] = useState<'IDLE' | 'RUNNING' | 'DONE'>('IDLE');

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setFilename(file.name);
      const reader = new FileReader();
      reader.onload = (event) => {
        setLeakedText(event.target?.result as string || '');
      };
      reader.readAsText(file);
    }
  };

  const handleVerify = async () => {
    setPipelineState('RUNNING');
    setReport(null);
    try {
      if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
        const result = await invoke<ForensicReport>('verify_leak', {
          leakedText,
          expectedHash: expectedHash.trim() || 'unknown_hash',
          filename: filename.trim() || 'leaked_artifact.txt',
        });
        setReport(result);
        setPipelineState('DONE');
      } else {
        alert("Cannot verify leak: Tauri API disconnected.");
        setPipelineState('IDLE');
      }
    } catch (e) {
      console.error(e);
      alert('Error verifying document: ' + e);
      setPipelineState('IDLE');
    }
  };

  const handleExportJson = async () => {
    if (!report) return;
    try {
      let jsonStr = '';
      if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
        jsonStr = await invoke<string>('export_forensic_report_json', { report });
      } else {
        jsonStr = JSON.stringify(report, null, 2);
      }

      const blob = new Blob([jsonStr], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `FORENSIC_REPORT_${report.investigation_id || 'DOSSIER'}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error(e);
      alert('Export failed: ' + e);
    }
  };

  const formatStatus = (st: string) => {
    switch (st) {
      case 'VerifiedAttribution':
        return 'VERIFIED ATTRIBUTION';
      case 'DegradedEvidence':
        return 'DEGRADED EVIDENCE';
      case 'InsufficientEvidence':
        return 'INSUFFICIENT EVIDENCE';
      case 'TamperedEvidence':
        return 'TAMPERED / INVALID EVIDENCE';
      default:
        return st.toUpperCase().replace(/_/g, ' ');
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'VerifiedAttribution':
        return 'text-emerald-600 dark:text-emerald-400';
      case 'DegradedEvidence':
        return 'text-amber-600 dark:text-amber-400';
      case 'InsufficientEvidence':
        return 'text-slate-500 dark:text-slate-400';
      default:
        return 'text-rose-600 dark:text-rose-400';
    }
  };

  const getStatusBorder = (status: string) => {
    switch (status) {
      case 'VerifiedAttribution':
        return 'border-l-emerald-600';
      case 'DegradedEvidence':
        return 'border-l-amber-600';
      case 'InsufficientEvidence':
        return 'border-l-slate-400';
      default:
        return 'border-l-rose-600';
    }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6 pb-10">
      
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border border-slate-200/80 dark:border-slate-800/80 shadow-xs">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold uppercase tracking-wide text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <SearchCode className="w-5 h-5 text-rose-600 dark:text-rose-400" />
              Forensic Investigation & Attribution Console
            </h1>
            <Badge variant="outline" className="text-[10px] font-mono bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300 border-rose-300 dark:border-rose-800">
              FORENSIC ENGINE
            </Badge>
          </div>
          <p className="mt-1 text-xs font-medium text-slate-500 dark:text-slate-400">
            Extract multi-layer invisible watermarks, execute Reed-Solomon erasure decoding, verify ML-DSA signatures, validate ledger consensus, and produce evidence-backed attribution reports.
          </p>
        </div>
      </div>

      {/* Input Panel Card */}
      <Card className="rounded-xl p-6 space-y-5 bg-white/90 dark:bg-slate-900/80 backdrop-blur-md border border-slate-200/80 dark:border-slate-800/80 shadow-xs">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-[11px] font-bold uppercase tracking-wider mb-1 text-slate-500 dark:text-slate-400">
              Investigated File Name
            </label>
            <Input
              type="text"
              className="bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-200 border-slate-300 dark:border-slate-800 font-mono text-xs"
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              placeholder="e.g. DEFENCE_PLAN.md"
            />
          </div>
          <div>
            <label className="block text-[11px] font-bold uppercase tracking-wider mb-1 text-slate-500 dark:text-slate-400">
              Upload Leaked File
            </label>
            <Input
              type="file"
              onChange={handleFileUpload}
              className="bg-slate-50 dark:bg-slate-950 text-slate-500 dark:text-slate-400 border-slate-300 dark:border-slate-800 text-xs"
            />
          </div>
        </div>

        <div>
          <label className="block text-[11px] font-bold uppercase tracking-wider mb-2 text-slate-500 dark:text-slate-400">
            Leaked Document Content (With Embedded Watermark Artifacts)
          </label>
          <textarea
            rows={5}
            className="w-full border border-slate-300 dark:border-slate-800 rounded-lg p-2.5 font-mono text-xs bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-200 focus:outline-hidden focus:ring-1 focus:ring-sky-500"
            value={leakedText}
            onChange={(e) => setLeakedText(e.target.value)}
            placeholder="Paste leaked artifact containing zero-width/structural watermark fragments here..."
            disabled={pipelineState === 'RUNNING'}
          />
        </div>

        <div>
          <label className="block text-[11px] font-bold uppercase tracking-wider mb-1 text-slate-500 dark:text-slate-400">
            Target Document SHA3-256 Hash (Optional Target Corroboration)
          </label>
          <Input
            type="text"
            className="bg-slate-50 dark:bg-slate-950 font-mono text-xs border-slate-300 dark:border-slate-800 text-slate-800 dark:text-slate-200"
            value={expectedHash}
            onChange={(e) => setExpectedHash(e.target.value)}
            placeholder="e.g. 9f8e7d... (Leave empty to autonomously resolve from recovered Event ID)"
            disabled={pipelineState === 'RUNNING'}
          />
        </div>

        <div className="pt-2 border-t border-slate-200 dark:border-slate-800 flex justify-end">
          <Button
            onClick={handleVerify}
            disabled={pipelineState === 'RUNNING' || !leakedText}
            className="bg-slate-900 hover:bg-slate-800 text-white dark:bg-rose-700 dark:hover:bg-rose-600 rounded-lg text-xs font-semibold px-4 py-2 flex items-center gap-2 shadow-xs"
          >
            <Search className="w-3.5 h-3.5" />
            {pipelineState === 'RUNNING' ? 'Executing Multi-Layer Forensics...' : 'Run Forensic Attribution Analysis'}
          </Button>
        </div>
      </Card>

      {/* Forensic Report Dossier */}
      {pipelineState === 'DONE' && report && (
        <div className="space-y-6">
          <Card className={`rounded-xl p-6 border-l-4 ${getStatusBorder(report.status)} bg-white/90 dark:bg-slate-900/80 backdrop-blur-md shadow-xs space-y-6`}>
            <div className="flex flex-col sm:flex-row justify-between items-start gap-4">
              <div>
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                  INVESTIGATION DOSSIER: {report.investigation_id}
                </span>
                <h2 className={`text-xl font-bold uppercase tracking-wide mt-2 ${getStatusColor(report.status)}`}>
                  {formatStatus(report.status)}
                </h2>
              </div>
              <div className="flex flex-col sm:items-end gap-2">
                <div className="text-left sm:text-right">
                  <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Forensic Confidence</div>
                  <div className={`text-lg font-bold font-mono ${getStatusColor(report.status)}`}>
                    {report.confidence?.band || 'None'} ({report.confidence_score})
                  </div>
                </div>
                <Button
                  onClick={handleExportJson}
                  size="sm"
                  variant="outline"
                  className="text-xs flex items-center gap-1.5 border-slate-300 dark:border-slate-700 rounded-lg"
                >
                  <Download className="w-3 h-3" />
                  Export JSON Dossier
                </Button>
              </div>
            </div>

            {/* Evidence Metrics Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 rounded-xl bg-slate-50/70 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 text-xs font-mono">
              <div>
                <div className="text-slate-400 text-[10px] font-bold uppercase">Investigated File:</div>
                <div className="font-semibold text-slate-800 dark:text-slate-200 mt-0.5 truncate">{report.investigated_file}</div>
              </div>

              <div>
                <div className="text-slate-400 text-[10px] font-bold uppercase">Document Hash:</div>
                <div className="text-slate-800 dark:text-slate-200 mt-0.5 truncate" title={report.file_hash}>
                  {report.file_hash ? `${report.file_hash.substring(0, 16)}...` : 'Unknown'}
                </div>
              </div>

              <div>
                <div className="text-slate-400 text-[10px] font-bold uppercase">Watermark Status:</div>
                <div className="mt-0.5">
                  <Badge className={
                    report.watermark_status === 'RECOVERED'
                      ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 text-[10px]'
                      : 'bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-300 text-[10px]'
                  }>
                    {report.watermark_status}
                  </Badge>
                </div>
              </div>

              <div>
                <div className="text-slate-400 text-[10px] font-bold uppercase">Event ID:</div>
                <div className="text-sky-600 dark:text-sky-400 font-bold mt-0.5 truncate" title={report.event_id}>
                  {report.event_id}
                </div>
              </div>

              <div>
                <div className="text-slate-400 text-[10px] font-bold uppercase">Attributed Recipient:</div>
                <div className="font-semibold text-slate-800 dark:text-slate-200 mt-0.5">{report.recipient_id || 'None (Insufficient)'}</div>
              </div>

              <div>
                <div className="text-slate-400 text-[10px] font-bold uppercase">Document Match:</div>
                <div className="mt-0.5 font-semibold">
                  {report.document_matched ? <span className="text-emerald-600 dark:text-emerald-400">✓ MATCHED</span> : <span className="text-rose-600 dark:text-rose-400">✕ MISMATCH</span>}
                </div>
              </div>

              <div>
                <div className="text-slate-400 text-[10px] font-bold uppercase">ML-DSA Signature:</div>
                <div className="mt-0.5 font-semibold">
                  {report.signature_valid ? <span className="text-emerald-600 dark:text-emerald-400">✓ VALID</span> : <span className="text-rose-600 dark:text-rose-400">✕ INVALID / FORGED</span>}
                </div>
              </div>

              <div>
                <div className="text-slate-400 text-[10px] font-bold uppercase">Ledger Hash Chain:</div>
                <div className="mt-0.5 font-semibold">
                  {report.ledger_valid ? <span className="text-emerald-600 dark:text-emerald-400">✓ VALID</span> : <span className="text-rose-600 dark:text-rose-400">✕ TAMPERED</span>}
                </div>
              </div>

              <div>
                <div className="text-slate-400 text-[10px] font-bold uppercase">Merkle Proof:</div>
                <div className="mt-0.5 font-semibold">
                  {report.merkle_proof_valid === true ? (
                    <span className="text-emerald-600 dark:text-emerald-400">✓ VALID IN ROOT</span>
                  ) : report.merkle_proof_valid === false ? (
                    <span className="text-rose-600 dark:text-rose-400">✕ INVALID PROOF</span>
                  ) : (
                    <span className="text-slate-500">N/A (PENDING)</span>
                  )}
                </div>
              </div>

              <div>
                <div className="text-slate-400 text-[10px] font-bold uppercase">Event-Time Key:</div>
                <div className="text-emerald-600 dark:text-emerald-400 font-semibold mt-0.5">{report.event_time_key_status}</div>
              </div>

              <div>
                <div className="text-slate-400 text-[10px] font-bold uppercase">Current Key Status:</div>
                <div className="mt-0.5">
                  <Badge className={report.current_key_status === 'ACTIVE' ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 text-[10px]' : 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300 text-[10px]'}>
                    {report.current_key_status}
                  </Badge>
                </div>
              </div>

              <div>
                <div className="text-slate-400 text-[10px] font-bold uppercase">Watermark Shards:</div>
                <div className="text-slate-800 dark:text-slate-200 font-semibold mt-0.5">
                  {report.watermark_metrics?.shards_recovered}/{report.watermark_metrics?.shards_total} ({report.watermark_metrics?.recovery_rate_percent}%)
                </div>
              </div>
            </div>

            {report.confidence?.explanation && report.confidence.explanation.length > 0 && (
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 text-xs font-mono text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-800">
                <div className="font-bold text-slate-800 dark:text-slate-200 mb-1 uppercase tracking-wider text-[11px]">Attribution Rationale:</div>
                <ul className="list-disc list-inside space-y-1">
                  {report.confidence.explanation.map((exp, i) => (
                    <li key={i}>{exp}</li>
                  ))}
                </ul>
              </div>
            )}
          </Card>

          {/* Evidence Checklist */}
          {report.evidence && report.evidence.length > 0 && (
            <Card className="rounded-xl p-6 bg-white/90 dark:bg-slate-900/80 backdrop-blur-md border border-slate-200/80 dark:border-slate-800/80 shadow-xs">
              <h2 className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider mb-4 border-b border-slate-200 dark:border-slate-800 pb-2">
                Forensic Evidence Verification Checklist
              </h2>
              <ul className="space-y-3 font-mono text-xs">
                {report.evidence.map((item, idx) => (
                  <li key={idx} className="flex gap-3 items-start">
                    <span className={item.passed ? "text-emerald-600 dark:text-emerald-400 font-bold" : "text-rose-600 dark:text-rose-400 font-bold"}>
                      {item.passed ? "✓" : "✕"}
                    </span>
                    <div>
                      <span className="font-bold text-slate-800 dark:text-slate-200">[{item.code}] {item.description}</span>
                      <div className="text-slate-500 dark:text-slate-400 text-[11px]">{item.impact}</div>
                    </div>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          {/* Warnings */}
          {report.warnings && report.warnings.length > 0 && (
            <Card className="rounded-xl p-6 border-l-4 border-l-amber-500 bg-white/90 dark:bg-slate-900/80 backdrop-blur-md shadow-xs">
              <h2 className="text-xs font-bold text-amber-600 dark:text-amber-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4" />
                Forensic Warnings & Anomalies
              </h2>
              <ul className="space-y-1.5 font-mono text-xs text-slate-600 dark:text-slate-400">
                {report.warnings.map((w, idx) => (
                  <li key={idx} className="flex gap-2 items-center">
                    <span>⚠</span> <span>{w}</span>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          {/* Limitations */}
          {report.limitations && report.limitations.length > 0 && (
            <Card className="rounded-xl p-6 bg-white/90 dark:bg-slate-900/80 backdrop-blur-md border border-slate-200/80 dark:border-slate-800/80 shadow-xs">
              <h2 className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider mb-2">
                Forensic Limitations & Methodological Boundary Statement
              </h2>
              <ul className="space-y-1 font-mono text-xs text-slate-500 dark:text-slate-400 list-disc list-inside">
                {report.limitations.map((lim, idx) => (
                  <li key={idx}>{lim}</li>
                ))}
              </ul>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
