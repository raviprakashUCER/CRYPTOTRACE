'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { 
  LayoutDashboard, 
  FileText, 
  Users, 
  Send, 
  Unlock, 
  SearchCode, 
  Link2, 
  ClipboardList,
  ShieldAlert
} from 'lucide-react';

export function Sidebar() {
  const pathname = usePathname();

  const navItemClass = (path: string) => {
    const isActive = pathname === path;
    return `group flex items-center gap-2.5 px-3 py-2 text-xs font-medium rounded-lg transition-all duration-150 ${
      isActive
        ? 'bg-slate-900 text-white dark:bg-sky-950/60 dark:text-sky-300 dark:border dark:border-sky-800/50 shadow-xs'
        : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/50 hover:text-slate-900 dark:hover:text-slate-200'
    }`;
  };

  const activeIconClass = (path: string) => {
    const isActive = pathname === path;
    return `w-4 h-4 transition-colors ${
      isActive 
        ? 'text-sky-400 dark:text-sky-300' 
        : 'text-slate-400 group-hover:text-slate-700 dark:text-slate-500 dark:group-hover:text-slate-300'
    }`;
  };

  return (
    <aside 
      className="w-64 shrink-0 overflow-y-auto border-r flex flex-col justify-between"
      style={{ backgroundColor: 'var(--gov-surface)', borderColor: 'var(--gov-border)' }}
    >
      <nav className="p-3.5 space-y-5">
        
        {/* Overview */}
        <div>
          <div className="flex items-center gap-1.5 px-3 mb-1.5 text-[10px] font-bold tracking-wider uppercase text-slate-400 dark:text-slate-500">
            <span className="h-1 w-1 rounded-full bg-sky-500" />
            Overview
          </div>
          <ul className="space-y-0.5">
            <li>
              <Link href="/" className={navItemClass('/')}>
                <LayoutDashboard className={activeIconClass('/')} />
                <span>Dashboard</span>
              </Link>
            </li>
          </ul>
        </div>

        {/* Document Security */}
        <div>
          <div className="flex items-center gap-1.5 px-3 mb-1.5 text-[10px] font-bold tracking-wider uppercase text-slate-400 dark:text-slate-500">
            <span className="h-1 w-1 rounded-full bg-indigo-500" />
            Document Security
          </div>
          <ul className="space-y-0.5">
            <li>
              <Link href="/documents" className={navItemClass('/documents')}>
                <FileText className={activeIconClass('/documents')} />
                <span>Documents & Ingestion</span>
              </Link>
            </li>
            <li>
              <Link href="/recipients" className={navItemClass('/recipients')}>
                <Users className={activeIconClass('/recipients')} />
                <span>Recipients & Keys</span>
              </Link>
            </li>
            <li>
              <Link href="/distribution" className={navItemClass('/distribution')}>
                <Send className={activeIconClass('/distribution')} />
                <span>Multi-Recipient Dispatch</span>
              </Link>
            </li>
            <li>
              <Link href="/decrypt" className={navItemClass('/decrypt')}>
                <Unlock className={activeIconClass('/decrypt')} />
                <span>Recipient Decryption</span>
              </Link>
            </li>
          </ul>
        </div>

        {/* Forensics */}
        <div>
          <div className="flex items-center gap-1.5 px-3 mb-1.5 text-[10px] font-bold tracking-wider uppercase text-slate-400 dark:text-slate-500">
            <span className="h-1 w-1 rounded-full bg-amber-500" />
            Forensics
          </div>
          <ul className="space-y-0.5">
            <li>
              <Link href="/forensics" className={navItemClass('/forensics')}>
                <SearchCode className={activeIconClass('/forensics')} />
                <span>Leak Investigation</span>
              </Link>
            </li>
          </ul>
        </div>

        {/* Evidence & Audit */}
        <div>
          <div className="flex items-center gap-1.5 px-3 mb-1.5 text-[10px] font-bold tracking-wider uppercase text-slate-400 dark:text-slate-500">
            <span className="h-1 w-1 rounded-full bg-emerald-500" />
            Evidence & Audit
          </div>
          <ul className="space-y-0.5">
            <li>
              <Link href="/ledger" className={navItemClass('/ledger')}>
                <Link2 className={activeIconClass('/ledger')} />
                <span>Evidence Ledger</span>
              </Link>
            </li>
            <li>
              <Link href="/audit" className={navItemClass('/audit')}>
                <ClipboardList className={activeIconClass('/audit')} />
                <span>Audit Log</span>
              </Link>
            </li>
          </ul>
        </div>
      </nav>

      {/* Security Engine Telemetry Footer */}
      <div className="p-3.5 border-t border-(--gov-border) bg-slate-50/50 dark:bg-slate-950/40">
        <div className="flex items-center gap-2 px-2 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-[11px]">
          <ShieldAlert className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400 shrink-0" />
          <div className="flex flex-col overflow-hidden">
            <span className="font-semibold text-slate-800 dark:text-slate-200 truncate">PQC Engine Active</span>
            <span className="font-mono text-[9px] text-slate-500 dark:text-slate-400 truncate">ML-KEM-768 • ML-DSA-65</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
