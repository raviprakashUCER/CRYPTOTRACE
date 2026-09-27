'use client';
import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { ShieldAlert, CheckCircle2, Lock, ArrowRight, AlertCircle, Send } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

interface UserResponse {
  id: string;
  name: string;
  department: string;
  clearance: string;
  role: string;
  status: string;
}

interface DocumentRecord {
  id: string;
  title: string;
  hash: string;
  classification: string;
  size_bytes: number;
}

export default function Distribution() {
  const [documents, setDocuments] = useState<DocumentRecord[]>([]);
  const [selectedDocId, setSelectedDocId] = useState('');
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [classification, setClassification] = useState('Secret');
  const [selectedRecipients, setSelectedRecipients] = useState<string[]>([]);
  const [availableRecipients, setAvailableRecipients] = useState<UserResponse[]>([]);
  const [loading, setLoading] = useState(false);
  const [distributionResult, setDistributionResult] = useState<string | null>(null);

  useEffect(() => {
    if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
      invoke<UserResponse[]>('get_users')
        .then(users => setAvailableRecipients(users))
        .catch(console.error);

      invoke<DocumentRecord[]>('get_documents')
        .then(docs => setDocuments(docs))
        .catch(console.error);
    }
  }, []);

  const handleSelectDoc = (docId: string) => {
    setSelectedDocId(docId);
    const d = documents.find(doc => doc.id === docId);
    if (d) {
      setTitle(d.title);
      setClassification(d.classification);
    }
  };

  const handleToggleRecipient = (id: string) => {
    setSelectedRecipients(prev => 
      prev.includes(id) ? prev.filter(r => r !== id) : [...prev, id]
    );
  };

  const handleDistribute = async () => {
    if (selectedRecipients.length === 0) {
      alert('Please select at least one authorized recipient.');
      return;
    }
    
    setLoading(true);
    setDistributionResult(null);
    try {
      if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
        const result = await invoke<string>('distribute', {
          title: title || "CLASSIFIED_DISPATCH",
          content: content || `[STRATEGIC DISPATCH]\nTitle: ${title}\nClassification: ${classification}\nAuthorized Distribution Package.`,
          recipientIds: selectedRecipients,
          classificationStr: classification,
        });
        setDistributionResult(result);
      } else {
        alert("Cannot distribute: Tauri API disconnected.");
      }
    } catch (e) {
      console.error(e);
      alert('Distribution failed: ' + e);
    }
    setLoading(false);
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6 pb-10">
      
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border border-slate-200/80 dark:border-slate-800/80 shadow-xs">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold uppercase tracking-wide text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Send className="w-5 h-5 text-sky-600 dark:text-sky-400" />
              Multi-Recipient Cryptographic Dispatch
            </h1>
            <Badge variant="outline" className="text-[10px] font-mono bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 border-indigo-300 dark:border-indigo-800">
              ML-KEM-768 WRAPPED
            </Badge>
          </div>
          <p className="mt-1 text-xs font-medium text-slate-500 dark:text-slate-400">
            Wrap AES-256-GCM symmetric content keys using Post-Quantum ML-KEM-768 for each authorized recipient.
          </p>
        </div>
      </div>

      {/* Security Notice */}
      <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-xl flex items-start gap-3 text-xs text-amber-800 dark:text-amber-300 shadow-xs">
        <AlertCircle className="w-5 h-5 shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
        <div>
          <span className="font-bold">Cryptographic Separation Invariant: </span>
          Sender distribution encrypts and encapsulates keys for recipients. It <strong>never</strong> creates a decryption event or provenance record. Decryption events are created solely when an authorized recipient executes an explicit decryption session.
        </div>
      </div>

      {/* Main Form Card */}
      <Card className="rounded-xl p-6 space-y-6 bg-white/90 dark:bg-slate-900/80 backdrop-blur-md border border-slate-200/80 dark:border-slate-800/80 shadow-xs">
        <div>
          <label className="block text-[11px] font-bold uppercase tracking-wider mb-2 text-slate-600 dark:text-slate-400">
            Step 1: Select Document or Enter Dispatch Details
          </label>
          {documents.length > 0 && (
            <div className="mb-4">
              <select
                value={selectedDocId}
                onChange={(e) => handleSelectDoc(e.target.value)}
                className="w-full h-9 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-3 text-xs text-slate-800 dark:text-slate-200"
              >
                <option value="">-- Choose from Ingested Documents Vault --</option>
                {documents.map(d => (
                  <option key={d.id} value={d.id}>{d.title} ({d.classification} - {d.hash.substring(0, 12)}...)</option>
                ))}
              </select>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-[11px] font-bold uppercase text-slate-500 dark:text-slate-400 mb-1">Document Title</label>
              <Input 
                type="text" 
                className="text-xs bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-200 border-slate-300 dark:border-slate-800"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="e.g. DEFENCE_STRATEGY_2026.md"
              />
            </div>
            <div>
              <label className="block text-[11px] font-bold uppercase text-slate-500 dark:text-slate-400 mb-1">Classification Level</label>
              <select
                value={classification}
                onChange={(e) => setClassification(e.target.value)}
                className="w-full h-9 rounded-md border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-3 text-xs text-slate-800 dark:text-slate-200"
              >
                <option value="Confidential">Confidential</option>
                <option value="Secret">Secret</option>
                <option value="TopSecret">Top Secret</option>
              </select>
            </div>
          </div>
        </div>

        <div>
          <label className="block text-[11px] font-bold uppercase tracking-wider mb-2 text-slate-600 dark:text-slate-400">Document Payload</label>
          <textarea 
            rows={4}
            className="w-full bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-200 border border-slate-300 dark:border-slate-800 rounded-lg p-2.5 font-mono text-xs focus:outline-hidden focus:ring-1 focus:ring-sky-500"
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="Classified document content to encrypt and distribute..."
          />
        </div>

        <div>
          <label className="block text-[11px] font-bold uppercase tracking-wider mb-2 text-slate-600 dark:text-slate-400">
            Step 2: Select Authorized Recipients (Clearance & Key Status Checked)
          </label>
          
          {availableRecipients.length === 0 ? (
            <Alert className="rounded-lg bg-slate-50 dark:bg-slate-950/50 border-slate-200 dark:border-slate-800">
              <ShieldAlert className="h-4 w-4" />
              <AlertTitle className="text-xs font-semibold">No Registered Recipients</AlertTitle>
              <AlertDescription className="text-xs text-slate-500">
                Register identities in Recipient Management before dispatching documents.
              </AlertDescription>
            </Alert>
          ) : (
            <div className="space-y-2 border border-slate-200 dark:border-slate-800 p-3 rounded-lg bg-slate-50/60 dark:bg-slate-950/50">
              {availableRecipients.map(recipient => {
                const isActive = recipient.status.toUpperCase() === 'ACTIVE';
                return (
                  <label 
                    key={recipient.id} 
                    className={`flex items-center justify-between p-2.5 rounded-lg border border-transparent transition-all ${
                      isActive 
                        ? 'hover:bg-white dark:hover:bg-slate-900 hover:border-slate-200 dark:hover:border-slate-800 cursor-pointer shadow-2xs' 
                        : 'opacity-60 cursor-not-allowed bg-rose-500/5'
                    }`}
                  >
                    <div className="flex items-center space-x-3">
                      <input 
                        type="checkbox" 
                        disabled={!isActive}
                        checked={selectedRecipients.includes(recipient.id)}
                        onChange={() => handleToggleRecipient(recipient.id)}
                        className="w-4 h-4 rounded accent-sky-600"
                      />
                      <div>
                        <span className="text-xs font-semibold text-slate-900 dark:text-slate-100">{recipient.name}</span>
                        <span className="text-[11px] text-slate-500 dark:text-slate-400 ml-2">({recipient.department})</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="text-[10px] font-mono">{recipient.clearance}</Badge>
                      <Badge className={isActive ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800 text-[10px]" : "bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300 text-[10px]"}>
                        {recipient.status}
                      </Badge>
                    </div>
                  </label>
                );
              })}
            </div>
          )}
        </div>

        <div className="pt-4 border-t border-slate-200 dark:border-slate-800 flex justify-end">
          <Button
            onClick={handleDistribute}
            disabled={loading || !title || (!content && !selectedDocId) || selectedRecipients.length === 0}
            className="bg-slate-900 hover:bg-slate-800 text-white dark:bg-sky-600 dark:hover:bg-sky-500 rounded-lg text-xs font-semibold px-4 py-2 flex items-center gap-2 shadow-xs"
          >
            <Lock className="w-3.5 h-3.5" />
            {loading ? 'Performing ML-KEM Key Wrapping...' : `Encrypt & Dispatch to ${selectedRecipients.length} Recipient(s)`}
          </Button>
        </div>
      </Card>

      {distributionResult && (
        <Card className="rounded-xl p-6 border-l-4 border-l-emerald-600 bg-white/90 dark:bg-slate-900/80 backdrop-blur-md shadow-xs">
          <div className="flex items-start gap-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
            <div className="space-y-2">
              <h2 className="text-sm font-bold text-emerald-700 dark:text-emerald-300 uppercase tracking-wide">
                Distribution Packages Successfully Generated & Persisted
              </h2>
              <p className="text-xs text-slate-800 dark:text-slate-200 leading-relaxed">
                {distributionResult}
              </p>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Individual ML-KEM-768 ciphertexts and encrypted content keys have been committed to the encrypted database. Recipients can now decrypt their authorized packages.
              </p>
              <div className="pt-2">
                <a href="/decrypt">
                  <Button size="sm" variant="outline" className="text-xs border-slate-300 dark:border-slate-700 hover:bg-slate-900 hover:text-white dark:hover:bg-sky-600 flex items-center gap-1.5 rounded-lg">
                    Proceed to Recipient Decryption Console <ArrowRight className="w-3 h-3" />
                  </Button>
                </a>
              </div>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
