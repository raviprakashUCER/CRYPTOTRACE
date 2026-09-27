'use client';
import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Unlock, FileCheck, Copy, ArrowRight, KeyRound } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

interface UserResponse {
  id: string;
  name: string;
  department: string;
  clearance: string;
  role: string;
  status: string;
}

interface AuthorizedPackage {
  document_id: string;
  title: string;
  document_hash: string;
  classification: string;
  sender: string;
  distributed_at: string;
  key_status: string;
}

interface DecryptionResponse {
  watermarked_plaintext: string;
  event_id: string;
  recipient_id: string;
  document_hash: string;
  attestation_signature: string;
  ledger_committed: boolean;
  key_status_at_event: string;
}

export default function DecryptPage() {
  const [recipients, setRecipients] = useState<UserResponse[]>([]);
  const [selectedRecipientId, setSelectedRecipientId] = useState('');
  const [packages, setPackages] = useState<AuthorizedPackage[]>([]);
  const [selectedDocId, setSelectedDocId] = useState('');
  const [loading, setLoading] = useState(false);
  const [decrypting, setDecrypting] = useState(false);
  const [decryptionResult, setDecryptionResult] = useState<DecryptionResponse | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
      invoke<UserResponse[]>('get_users')
        .then(users => {
          setRecipients(users);
          if (users.length > 0) {
            setSelectedRecipientId(users[0].id);
          }
        })
        .catch(console.error);
    }
  }, []);

  const fetchPackages = async (recipId: string) => {
    if (!recipId) return;
    setLoading(true);
    try {
      if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
        const pkgs = await invoke<AuthorizedPackage[]>('get_authorized_packages_for_recipient', {
          recipientId: recipId,
        });
        setPackages(pkgs);
        if (pkgs.length > 0) {
          setSelectedDocId(pkgs[0].document_id);
        } else {
          setSelectedDocId('');
        }
      }
    } catch (e) {
      console.error(e);
    }
    setLoading(false);
  };

  useEffect(() => {
    if (selectedRecipientId) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      fetchPackages(selectedRecipientId);
    }
  }, [selectedRecipientId]);

  const handleDecrypt = async () => {
    if (!selectedDocId || !selectedRecipientId) {
      alert('Please select a document package to decrypt.');
      return;
    }

    setDecrypting(true);
    setDecryptionResult(null);
    try {
      if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
        const sessionId = `SES-${Date.now().toString(36).toUpperCase()}`;
        const resp = await invoke<DecryptionResponse>('decrypt_document', {
          documentId: selectedDocId,
          recipientId: selectedRecipientId,
          sessionId,
        });
        setDecryptionResult(resp);
      } else {
        alert('Tauri Core API disconnected.');
      }
    } catch (e) {
      console.error(e);
      alert('Decryption failed: ' + e);
    }
    setDecrypting(false);
  };

  const handleCopy = () => {
    if (decryptionResult) {
      navigator.clipboard.writeText(decryptionResult.watermarked_plaintext);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const selectedPkg = packages.find(p => p.document_id === selectedDocId);
  const selectedUser = recipients.find(r => r.id === selectedRecipientId);

  return (
    <div className="max-w-5xl mx-auto space-y-6 pb-10">
      
      {/* Header Card */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border border-slate-200/80 dark:border-slate-800/80 shadow-xs">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold uppercase tracking-wide text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Unlock className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
              Recipient Authorized Decryption Console
            </h1>
            <Badge variant="outline" className="text-[10px] font-mono bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800">
              ML-DSA ATTESTED
            </Badge>
          </div>
          <p className="mt-1 text-xs font-medium text-slate-500 dark:text-slate-400">
            Authenticate recipient identity, decapsulate ML-KEM key, sign ML-DSA-65 provenance attestation, and embed invisible forensic watermark.
          </p>
        </div>
      </div>

      {/* Main Decryption Card */}
      <Card className="rounded-xl p-6 space-y-6 bg-white/90 dark:bg-slate-900/80 backdrop-blur-md border border-slate-200/80 dark:border-slate-800/80 shadow-xs">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="block text-[11px] font-bold uppercase tracking-wider mb-2 text-slate-600 dark:text-slate-400">
              1. Select Recipient Identity (Active Session)
            </label>
            <select
              value={selectedRecipientId}
              onChange={(e) => setSelectedRecipientId(e.target.value)}
              className="w-full h-9 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-3 text-xs text-slate-800 dark:text-slate-200"
            >
              {recipients.map(r => (
                <option key={r.id} value={r.id}>
                  {r.name} ({r.department} - {r.clearance} - {r.status})
                </option>
              ))}
            </select>
            {selectedUser && (
              <div className="mt-2.5 flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400 font-mono">
                <span>Clearance: <strong className="text-slate-700 dark:text-slate-200">{selectedUser.clearance}</strong></span>
                <span>•</span>
                <span>Role: <strong className="text-slate-700 dark:text-slate-200">{selectedUser.role}</strong></span>
                <span>•</span>
                <span>Key: <strong className={selectedUser.status === 'ACTIVE' ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400'}>{selectedUser.status}</strong></span>
              </div>
            )}
          </div>

          <div>
            <label className="block text-[11px] font-bold uppercase tracking-wider mb-2 text-slate-600 dark:text-slate-400">
              2. Select Authorized Distribution Package
            </label>
            {loading ? (
              <div className="text-xs text-slate-500 font-mono p-2">Loading authorized packages...</div>
            ) : packages.length === 0 ? (
              <div className="p-3 bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 rounded-lg text-xs text-slate-500 dark:text-slate-400">
                No encrypted packages currently distributed to this recipient identity.
              </div>
            ) : (
              <select
                value={selectedDocId}
                onChange={(e) => setSelectedDocId(e.target.value)}
                className="w-full h-9 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-3 text-xs text-slate-800 dark:text-slate-200"
              >
                {packages.map(p => (
                  <option key={p.document_id} value={p.document_id}>
                    {p.title} ({p.classification} - From {p.sender})
                  </option>
                ))}
              </select>
            )}
          </div>
        </div>

        {selectedPkg && (
          <div className="p-4 bg-slate-50/70 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 rounded-xl space-y-2 text-xs font-mono">
            <div className="font-bold text-xs text-slate-800 dark:text-slate-200 flex items-center gap-2">
              <KeyRound className="w-3.5 h-3.5 text-sky-500" />
              Package Metadata Verification
            </div>
            <div className="grid grid-cols-2 gap-2 text-slate-500 dark:text-slate-400">
              <div>Document ID: <span className="text-slate-800 dark:text-slate-200 font-semibold">{selectedPkg.document_id}</span></div>
              <div>Document Hash: <span className="text-slate-800 dark:text-slate-200">{selectedPkg.document_hash.substring(0, 20)}...</span></div>
              <div>Classification: <span className="text-slate-800 dark:text-slate-200 font-semibold">{selectedPkg.classification}</span></div>
              <div>Dispatcher: <span className="text-slate-800 dark:text-slate-200 font-semibold">{selectedPkg.sender}</span></div>
            </div>
          </div>
        )}

        <div className="pt-2 flex justify-end">
          <Button
            onClick={handleDecrypt}
            disabled={decrypting || !selectedDocId || selectedUser?.status !== 'ACTIVE'}
            className="bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-xs font-semibold px-4 py-2 flex items-center gap-2 shadow-xs"
          >
            <Unlock className="w-3.5 h-3.5" />
            {decrypting ? 'Decapsulating & Signing Attestation...' : 'Decrypt Document & Commit Provenance'}
          </Button>
        </div>
      </Card>

      {decryptionResult && (
        <Card className="rounded-xl p-6 border-l-4 border-l-emerald-600 bg-white/90 dark:bg-slate-900/80 backdrop-blur-md shadow-xs space-y-5">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <FileCheck className="w-6 h-6 text-emerald-600 shrink-0" />
              <div>
                <h2 className="text-sm font-bold text-emerald-700 dark:text-emerald-300 uppercase tracking-wide">
                  Decryption & Attestation Succeeded
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Provenance record committed to immutable ledger and SQLite persistent store.
                </p>
              </div>
            </div>
            <Badge className="bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800 text-[10px] font-mono">
              LEDGER COMMITTED
            </Badge>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 p-3.5 bg-slate-50 dark:bg-slate-950/60 rounded-xl border border-slate-200 dark:border-slate-800 text-xs font-mono">
            <div>
              <div className="text-slate-400 text-[10px] font-bold uppercase">Unique Event ID:</div>
              <div className="text-sky-600 dark:text-sky-400 font-bold text-xs truncate mt-0.5">{decryptionResult.event_id}</div>
            </div>
            <div>
              <div className="text-slate-400 text-[10px] font-bold uppercase">Attestation Signature:</div>
              <div className="text-slate-700 dark:text-slate-300 truncate mt-0.5">{decryptionResult.attestation_signature.substring(0, 24)}... (ML-DSA-65)</div>
            </div>
            <div>
              <div className="text-slate-400 text-[10px] font-bold uppercase">Key Status at Event:</div>
              <div className="text-emerald-600 dark:text-emerald-400 font-bold mt-0.5">{decryptionResult.key_status_at_event}</div>
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <label className="text-[11px] font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">
                Decrypted Plaintext (With Invisible & Structural Provenance Watermark):
              </label>
              <Button size="sm" variant="outline" onClick={handleCopy} className="text-xs h-7 px-2.5 flex items-center gap-1 border-slate-300 dark:border-slate-700">
                <Copy className="w-3 h-3" />
                {copied ? 'Copied!' : 'Copy Leaked Copy'}
              </Button>
            </div>
            <div className="p-4 bg-slate-50 dark:bg-slate-950/80 rounded-xl border border-slate-200 dark:border-slate-800 text-xs font-mono whitespace-pre-wrap text-slate-800 dark:text-slate-200 max-h-60 overflow-y-auto">
              {decryptionResult.watermarked_plaintext}
            </div>
          </div>

          <div className="p-3.5 bg-amber-500/10 border border-amber-500/20 rounded-xl text-xs text-amber-800 dark:text-amber-300 flex justify-between items-center">
            <div>
              <strong>Simulate Document Leak: </strong>
              Copy the watermarked artifact above and test forensic attribution in the Leak Investigation Console.
            </div>
            <a href="/forensics">
              <Button size="sm" className="bg-slate-900 hover:bg-slate-800 text-white dark:bg-sky-600 dark:hover:bg-sky-500 text-xs flex items-center gap-1 rounded-lg">
                Investigate in Forensics <ArrowRight className="w-3 h-3" />
              </Button>
            </a>
          </div>
        </Card>
      )}
    </div>
  );
}
