'use client';
import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { ShieldCheck, CheckCircle2, XCircle, Layers, Link2, Search } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

interface LedgerVerificationResult {
  chain_valid: boolean;
  block_count: number;
  latest_hash: string;
  errors: string[];
}

interface MerkleProofResult {
  event_id: string;
  is_proven: boolean;
  merkle_root: string;
  proof_path_len: number;
}

export default function Ledger() {
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<LedgerVerificationResult | null>(null);
  const [merkleEventId, setMerkleEventId] = useState('');
  const [merkleResult, setMerkleResult] = useState<MerkleProofResult | null>(null);
  const [merkleLoading, setMerkleLoading] = useState(false);

  const handleVerifyChain = async () => {
    setVerifying(true);
    setVerificationResult(null);
    try {
      if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
        const result = await invoke<LedgerVerificationResult>('verify_ledger_chain');
        setVerificationResult(result);
      } else {
        alert("Tauri API disconnected.");
      }
    } catch (e) {
      console.error(e);
      alert('Verification failed: ' + e);
    }
    setVerifying(false);
  };

  const handleVerifyMerkle = async () => {
    if (!merkleEventId) {
      alert('Please enter an Event ID to verify Merkle inclusion proof.');
      return;
    }
    setMerkleLoading(true);
    setMerkleResult(null);
    try {
      if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
        const res = await invoke<MerkleProofResult>('verify_merkle_proof', {
          eventId: merkleEventId.trim(),
        });
        setMerkleResult(res);
      } else {
        alert("Tauri API disconnected.");
      }
    } catch (e) {
      console.error(e);
      alert('Merkle proof error: ' + e);
    }
    setMerkleLoading(false);
  };

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    handleVerifyChain();
  }, []);

  return (
    <div className="max-w-6xl mx-auto space-y-6 pb-10">
      
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border border-slate-200/80 dark:border-slate-800/80 shadow-xs">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold uppercase tracking-wide text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Link2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
              Cryptographic Evidence Ledger Explorer
            </h1>
            <Badge variant="outline" className="text-[10px] font-mono bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800">
              SHA3-256 CHAIN
            </Badge>
          </div>
          <p className="mt-1 text-xs font-medium text-slate-500 dark:text-slate-400">
            Immutable SHA3-256 hash-chain ledger with Merkle inclusion proofs for decentralized tamper detection and mathematical provenance audit.
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            onClick={handleVerifyChain}
            disabled={verifying}
            className="bg-slate-900 hover:bg-slate-800 text-white dark:bg-emerald-600 dark:hover:bg-emerald-500 text-xs font-semibold px-4 py-2 rounded-lg flex items-center gap-1.5 shadow-xs"
          >
            <ShieldCheck className={`w-4 h-4 ${verifying ? 'animate-spin' : ''}`} />
            {verifying ? 'Verifying Hash Chain...' : 'Verify Hash Chain'}
          </Button>
        </div>
      </div>

      {/* Hash-Chain Verification Result Card */}
      {verificationResult && (
        <Card className={`rounded-xl p-6 border-l-4 ${verificationResult.chain_valid ? 'border-l-emerald-600' : 'border-l-rose-600'} bg-white/90 dark:bg-slate-900/80 backdrop-blur-md shadow-xs`}>
          <div className="flex flex-col sm:flex-row justify-between items-start gap-4">
            <div className="space-y-1.5">
              <div className="flex items-center gap-2">
                {verificationResult.chain_valid ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0" />
                ) : (
                  <XCircle className="w-5 h-5 text-rose-600 shrink-0" />
                )}
                <h2 className="text-sm font-bold uppercase tracking-wide text-slate-900 dark:text-slate-100">
                  {verificationResult.chain_valid ? 'Ledger Hash-Chain Verified: Cryptographically Valid' : 'Ledger Hash-Chain Compromised / Tampered'}
                </h2>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                Total Blocks in Chain: <strong className="text-slate-800 dark:text-slate-200">{verificationResult.block_count}</strong> | Latest Block Hash: <span className="text-slate-800 dark:text-slate-200">{verificationResult.latest_hash ? `${verificationResult.latest_hash.substring(0, 24)}...` : 'Genesis'}</span>
              </p>
            </div>
            <Badge className={verificationResult.chain_valid ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800 text-[10px] font-mono" : "bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300 text-[10px] font-mono"}>
              {verificationResult.chain_valid ? "CONSENSUS VALID" : "CHAIN TAMPERED"}
            </Badge>
          </div>
        </Card>
      )}

      {/* Merkle Proof Verification Card */}
      <Card className="rounded-xl p-6 bg-white/90 dark:bg-slate-900/80 backdrop-blur-md border border-slate-200/80 dark:border-slate-800/80 shadow-xs space-y-4">
        <div className="flex items-center gap-2">
          <Layers className="w-5 h-5 text-sky-500" />
          <h2 className="text-sm font-bold uppercase tracking-wide text-slate-900 dark:text-slate-100">
            Merkle Tree Inclusion Proof Verification
          </h2>
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Verify mathematical membership of any decryption Event ID against the latest committed Merkle Batch Root using logarithmic inclusion proofs.
        </p>

        <div className="flex flex-col sm:flex-row gap-2">
          <input
            type="text"
            value={merkleEventId}
            onChange={(e) => setMerkleEventId(e.target.value)}
            placeholder="Enter Event ID (e.g. EVT-9f8e7d6c5b4a3928...)"
            className="flex-1 h-9 px-3 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 font-mono text-xs text-slate-800 dark:text-slate-200 focus:outline-hidden focus:ring-1 focus:ring-sky-500"
          />
          <Button
            onClick={handleVerifyMerkle}
            disabled={merkleLoading || !merkleEventId}
            className="bg-slate-900 hover:bg-slate-800 text-white dark:bg-sky-600 dark:hover:bg-sky-500 text-xs font-semibold px-4 h-9 rounded-lg flex items-center gap-1.5 shadow-xs"
          >
            <Search className={`w-3.5 h-3.5 ${merkleLoading ? 'animate-spin' : ''}`} />
            {merkleLoading ? 'Computing Proof...' : 'Verify Proof'}
          </Button>
        </div>

        {merkleResult && (
          <div className="p-4 bg-slate-50 dark:bg-slate-950/70 rounded-xl border border-slate-200 dark:border-slate-800 text-xs font-mono space-y-2">
            <div className="font-bold flex items-center gap-2 text-xs">
              {merkleResult.is_proven ? (
                <span className="text-emerald-600 dark:text-emerald-400 flex items-center gap-1">✓ INCLUSION MATHEMATICALLY PROVEN</span>
              ) : (
                <span className="text-rose-600 dark:text-rose-400 flex items-center gap-1">✕ INCLUSION FAILED / UNVERIFIED</span>
              )}
            </div>
            <div className="text-slate-500 dark:text-slate-400">Event ID: <span className="text-slate-800 dark:text-slate-200 font-semibold">{merkleResult.event_id}</span></div>
            <div className="text-slate-500 dark:text-slate-400">Merkle Root: <span className="text-slate-800 dark:text-slate-200 truncate">{merkleResult.merkle_root}</span></div>
            <div className="text-slate-500 dark:text-slate-400">Audit Path: <span className="text-slate-800 dark:text-slate-200 font-semibold">{merkleResult.proof_path_len} sibling hashes</span></div>
          </div>
        )}
      </Card>
    </div>
  );
}
