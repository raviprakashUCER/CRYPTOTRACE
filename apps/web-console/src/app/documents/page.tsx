'use client';
import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { FileText, Upload, Shield, AlertTriangle, CheckCircle2, Lock, FolderSync } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

interface DocumentRecord {
  id: string;
  title: string;
  hash: string;
  classification: string;
  encrypted_at: string;
  size_bytes: number;
  recipient_count: number;
  is_distributed: boolean;
}

interface IngestResponse {
  document_id: string;
  filename: string;
  mime_type: string;
  file_size: number;
  document_hash: string;
  classification: string;
  creator: string;
  format: string;
  watermarking_supported: boolean;
}

export default function Documents() {
  const [documents, setDocuments] = useState<DocumentRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [ingestModalOpen, setIngestModalOpen] = useState(false);
  const [isIngesting, setIsIngesting] = useState(false);

  // Ingestion Form State
  const [filename, setFilename] = useState('');
  const [content, setContent] = useState('');
  const [classification, setClassification] = useState('Secret');
  const [creator, setCreator] = useState('OFFICER_DISPATCH');
  const [lastIngested, setLastIngested] = useState<IngestResponse | null>(null);

  const fetchDocuments = async () => {
    try {
      if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
        const result = await invoke<DocumentRecord[]>('get_documents');
        setDocuments(result);
        setLoading(false);
      } else {
        setTimeout(() => {
          setDocuments([]);
          setLoading(false);
        }, 0);
      }
    } catch (e) {
      console.error(e);
      setLoading(false);
    }
  };

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    fetchDocuments();
  }, []);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setFilename(file.name);
      const reader = new FileReader();
      reader.onload = (event) => {
        setContent(event.target?.result as string || '');
      };
      reader.readAsText(file);
    }
  };

  const isFormatSupported = () => {
    const fn = filename.toLowerCase();
    return fn.endsWith('.txt') || fn.endsWith('.md') || fn.endsWith('.markdown');
  };

  const handleIngest = async () => {
    if (!filename || !content) {
      alert('Please specify a filename and document content.');
      return;
    }

    setIsIngesting(true);
    try {
      if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
        const resp = await invoke<IngestResponse>('ingest_document_command', {
          filename,
          mimeType: filename.endsWith('.md') ? 'text/markdown' : 'text/plain',
          content,
          classificationStr: classification,
          creator,
        });
        setLastIngested(resp);
        setIsIngesting(false);
        fetchDocuments();
      } else {
        alert('Tauri Core API disconnected.');
        setIsIngesting(false);
      }
    } catch (e) {
      console.error(e);
      alert('Ingestion error: ' + e);
      setIsIngesting(false);
    }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6 pb-10">
      
      {/* Top Header Card */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border border-slate-200/80 dark:border-slate-800/80 shadow-xs">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold uppercase tracking-wide text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Lock className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
              Secure Document Ingestion & Vault
            </h1>
            <Badge variant="outline" className="text-[10px] font-mono bg-sky-50 dark:bg-sky-950/60 text-sky-700 dark:text-sky-300 border-sky-300 dark:border-sky-800">
              SHA3-256 HASHED
            </Badge>
          </div>
          <p className="mt-1 text-xs font-medium text-slate-500 dark:text-slate-400">
            Ingest classified document payloads, compute byte-accurate SHA3-256 integrity hashes, and manage encrypted distribution packages.
          </p>
        </div>

        <Dialog open={ingestModalOpen} onOpenChange={setIngestModalOpen}>
          <DialogTrigger className="bg-slate-900 hover:bg-slate-800 text-white dark:bg-sky-600 dark:hover:bg-sky-500 text-xs font-semibold px-4 py-2 rounded-lg flex items-center gap-1.5 shadow-xs cursor-pointer">
            <Upload className="w-3.5 h-3.5" />
            Ingest Document
          </DialogTrigger>
          <DialogContent className="sm:max-w-[560px] rounded-xl bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 border border-slate-200 dark:border-slate-800 shadow-xl">
            <DialogHeader>
              <DialogTitle className="text-base font-bold flex items-center gap-2">
                <FileText className="w-4 h-4 text-sky-500" />
                Document Ingestion (SHA3-256 Byte Hashing)
              </DialogTitle>
              <DialogDescription className="text-xs text-slate-500 dark:text-slate-400">
                Upload actual document bytes. The system computes a byte-exact SHA3-256 hash and validates supported format boundaries.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4 py-2">
              <div>
                <label className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 block mb-1">
                  Select Local File
                </label>
                <Input type="file" onChange={handleFileUpload} className="text-xs bg-slate-50 dark:bg-slate-950 border-slate-300 dark:border-slate-800" />
              </div>

              <div>
                <label className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 block mb-1">
                  Document Filename
                </label>
                <Input
                  value={filename}
                  onChange={(e) => setFilename(e.target.value)}
                  placeholder="e.g. DEFENCE_STRATEGY_2026.md"
                  className="text-xs bg-slate-50 dark:bg-slate-950 border-slate-300 dark:border-slate-800 font-mono"
                />
              </div>

              {filename && (
                <div>
                  {isFormatSupported() ? (
                    <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs text-emerald-600 dark:text-emerald-400 flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 shrink-0" />
                      <span>Supported Watermark Format: <strong>{filename.endsWith('.md') ? 'Markdown (UTF-8)' : 'Plain Text (TXT)'}</strong></span>
                    </div>
                  ) : (
                    <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg text-xs text-amber-600 dark:text-amber-400 flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 shrink-0" />
                      <span><strong>UNSUPPORTED_WATERMARK_FORMAT:</strong> PDF/DOCX binary formats are rejected from text-layer watermarking.</span>
                    </div>
                  )}
                </div>
              )}

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 block mb-1">Classification</label>
                  <select
                    value={classification}
                    onChange={(e) => setClassification(e.target.value)}
                    className="flex h-9 w-full rounded-md border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-3 py-1.5 text-xs text-slate-800 dark:text-slate-200"
                  >
                    <option value="Confidential">Confidential</option>
                    <option value="Secret">Secret</option>
                    <option value="TopSecret">Top Secret</option>
                  </select>
                </div>
                <div>
                  <label className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 block mb-1">Creator / Department</label>
                  <Input
                    value={creator}
                    onChange={(e) => setCreator(e.target.value)}
                    placeholder="e.g. DISPATCH_OFFICER_01"
                    className="text-xs bg-slate-50 dark:bg-slate-950 border-slate-300 dark:border-slate-800"
                  />
                </div>
              </div>

              <div>
                <label className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 block mb-1">Document Content Payload</label>
                <textarea
                  rows={4}
                  value={content}
                  onChange={(e) => setContent(e.target.value)}
                  placeholder="Classified document text..."
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-800 rounded-lg p-2.5 text-xs font-mono text-slate-800 dark:text-slate-200 focus:outline-hidden focus:ring-1 focus:ring-sky-500"
                />
              </div>

              {lastIngested && (
                <div className="p-3 bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg text-xs space-y-1 font-mono">
                  <div className="font-bold text-emerald-600 dark:text-emerald-400">✓ Ingested: {lastIngested.document_id}</div>
                  <div className="text-slate-500">SHA3-256: {lastIngested.document_hash.substring(0, 32)}...</div>
                  <div className="text-slate-500">Size: {lastIngested.file_size} bytes</div>
                </div>
              )}
            </div>

            <DialogFooter>
              <Button
                disabled={isIngesting || !filename || !content}
                onClick={handleIngest}
                className="bg-slate-900 hover:bg-slate-800 text-white dark:bg-sky-600 dark:hover:bg-sky-500 text-xs"
              >
                {isIngesting ? 'Computing SHA3-256...' : 'Ingest Document'}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {loading ? (
        <div className="p-16 flex flex-col items-center justify-center text-center space-y-3">
          <FolderSync className="w-8 h-8 text-sky-500 animate-spin" />
          <div className="text-sm font-medium text-slate-600 dark:text-slate-400 font-mono">
            Scanning encrypted document vault...
          </div>
        </div>
      ) : documents.length === 0 ? (
        <Card className="rounded-xl border border-slate-200/80 dark:border-slate-800/80 bg-white/90 dark:bg-slate-900/80 backdrop-blur-md shadow-xs">
          <CardContent className="p-16 flex flex-col items-center justify-center text-center max-w-md mx-auto space-y-4">
            <div className="w-16 h-16 rounded-2xl bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 flex items-center justify-center shadow-inner">
              <FileText className="w-8 h-8 text-slate-400 dark:text-slate-500" />
            </div>
            <div className="space-y-1">
              <h3 className="text-sm font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
                No Documents Ingested
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                The secure cryptographic vault is currently empty. Ingest a document payload to begin classification and multi-recipient dispatch.
              </p>
            </div>
            <Button
              onClick={() => setIngestModalOpen(true)}
              variant="outline"
              size="sm"
              className="text-xs flex items-center gap-1.5 border-slate-300 dark:border-slate-700 mt-2"
            >
              <Upload className="w-3.5 h-3.5" />
              Ingest First Document
            </Button>
          </CardContent>
        </Card>
      ) : (
        <Card className="rounded-xl border border-slate-200/80 dark:border-slate-800/80 overflow-hidden bg-white/90 dark:bg-slate-900/80 backdrop-blur-md shadow-xs">
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/60">
                  <TableHead className="text-slate-600 dark:text-slate-400 font-bold uppercase tracking-wider text-[11px] py-3.5">Document ID</TableHead>
                  <TableHead className="text-slate-600 dark:text-slate-400 font-bold uppercase tracking-wider text-[11px] py-3.5">Title / Filename</TableHead>
                  <TableHead className="text-slate-600 dark:text-slate-400 font-bold uppercase tracking-wider text-[11px] py-3.5">Classification</TableHead>
                  <TableHead className="text-slate-600 dark:text-slate-400 font-bold uppercase tracking-wider text-[11px] py-3.5">SHA3-256 Hash</TableHead>
                  <TableHead className="text-slate-600 dark:text-slate-400 font-bold uppercase tracking-wider text-[11px] py-3.5">Recipients</TableHead>
                  <TableHead className="text-slate-600 dark:text-slate-400 font-bold uppercase tracking-wider text-[11px] py-3.5 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {documents.map((doc) => (
                  <TableRow key={doc.id} className="border-b border-slate-200/70 dark:border-slate-800/70 hover:bg-slate-50/60 dark:hover:bg-slate-800/40 text-xs transition-colors">
                    <TableCell className="font-mono text-slate-500 dark:text-slate-400 py-3">{doc.id}</TableCell>
                    <TableCell className="font-semibold text-slate-900 dark:text-slate-100 py-3">
                      <div className="flex items-center gap-2">
                        <FileText className="w-4 h-4 text-sky-500" />
                        <span>{doc.title}</span>
                      </div>
                    </TableCell>
                    <TableCell className="py-3">
                      <Badge variant="outline" className="font-mono text-[11px] bg-slate-50 dark:bg-slate-900 border-slate-300 dark:border-slate-700">
                        {doc.classification}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-slate-500 dark:text-slate-400 py-3">
                      {doc.hash.substring(0, 16)}...
                    </TableCell>
                    <TableCell className="py-3">
                      <Badge className={doc.recipient_count > 0 ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800" : "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300"}>
                        {doc.recipient_count} Recipient(s)
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right py-3">
                      <a href="/distribution">
                        <Button variant="outline" size="sm" className="text-xs rounded-lg border-slate-300 dark:border-slate-700 hover:bg-slate-900 hover:text-white dark:hover:bg-sky-600">
                          <Shield className="w-3.5 h-3.5 mr-1" />
                          Distribute
                        </Button>
                      </a>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
