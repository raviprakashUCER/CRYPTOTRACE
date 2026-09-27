'use client';

import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Users, KeyRound, RefreshCw, CheckCircle, XCircle, AlertCircle, ShieldAlert, UserCheck } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

interface UserResponse {
  id: string;
  name: string;
  department: string;
  clearance: string;
  role: string;
  status: string;
}

export default function RecipientsPage() {
  const [users, setUsers] = useState<UserResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [isRegistering, setIsRegistering] = useState(false);

  // Form State
  const [name, setName] = useState('');
  const [department, setDepartment] = useState('');
  const [clearance, setClearance] = useState('Secret');
  const [role, setRole] = useState('Recipient');

  const fetchUsers = async () => {
    try {
      if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
        const result = await invoke<UserResponse[]>('get_users');
        setUsers(result);
        setLoading(false);
      } else {
        setTimeout(() => setLoading(false), 0);
      }
    } catch (e) {
      console.error(e);
      setLoading(false);
    }
  };

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    fetchUsers();
  }, []);

  const handleRegister = async () => {
    setIsRegistering(true);
    try {
      if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
        await invoke('register_user', { name, department, clearance, roleStr: role });
        setModalOpen(false);
        setName('');
        setDepartment('');
        fetchUsers();
      } else {
        alert("Cannot register: Tauri API disconnected.");
      }
    } catch (e) {
      console.error(e);
      alert('Error registering user: ' + e);
    }
    setIsRegistering(false);
  };

  const handleUpdateKeyStatus = async (userId: string, newStatus: string) => {
    try {
      if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
        await invoke('update_key_status', { identityId: userId, statusStr: newStatus });
        fetchUsers();
      }
    } catch (e) {
      console.error(e);
      alert('Failed to update key status: ' + e);
    }
  };

  const getKeyBadge = (status: string) => {
    switch (status.toUpperCase()) {
      case 'ACTIVE':
        return <Badge className="bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800 flex items-center gap-1"><CheckCircle className="w-3 h-3" /> ACTIVE</Badge>;
      case 'SUSPENDED':
        return <Badge className="bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border-amber-300 dark:border-amber-800 flex items-center gap-1"><AlertCircle className="w-3 h-3" /> SUSPENDED</Badge>;
      case 'REVOKED':
        return <Badge className="bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300 border-rose-300 dark:border-rose-800 flex items-center gap-1"><XCircle className="w-3 h-3" /> REVOKED</Badge>;
      case 'EXPIRED':
        return <Badge className="bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-300 flex items-center gap-1"><RefreshCw className="w-3 h-3" /> EXPIRED</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6 pb-10">
      {/* Header Card */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border border-slate-200/80 dark:border-slate-800/80 shadow-xs">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold uppercase tracking-wide text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Users className="w-5 h-5 text-sky-600 dark:text-sky-400" />
              Recipient & Identity Registry
            </h1>
            <Badge variant="outline" className="text-[10px] font-mono bg-sky-50 dark:bg-sky-950/60 text-sky-700 dark:text-sky-300 border-sky-300 dark:border-sky-800">
              PQC ENROLLED
            </Badge>
          </div>
          <p className="mt-1 text-xs font-medium text-slate-500 dark:text-slate-400">
            Manage RBAC roles, security clearances, Post-Quantum keys (ML-KEM-768 / ML-DSA-65), and key lifecycle states.
          </p>
        </div>
        
        <Dialog open={modalOpen} onOpenChange={setModalOpen}>
          <DialogTrigger className="bg-slate-900 hover:bg-slate-800 text-white dark:bg-sky-600 dark:hover:bg-sky-500 text-xs font-semibold px-4 py-2 rounded-lg flex items-center gap-1.5 shadow-xs cursor-pointer">
            <KeyRound className="w-3.5 h-3.5" />
            Register Recipient Identity
          </DialogTrigger>
          <DialogContent className="sm:max-w-[480px] rounded-xl bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 border border-slate-200 dark:border-slate-800 shadow-xl">
            <DialogHeader>
              <DialogTitle className="text-base font-bold flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-sky-500" />
                Enroll Cryptographic Recipient Identity
              </DialogTitle>
              <DialogDescription className="text-xs text-slate-500 dark:text-slate-400">
                Generates ML-KEM-768 key encapsulation and ML-DSA-65 post-quantum signing keypairs stored in the encrypted keystore.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-2">
              <div className="flex flex-col gap-1">
                <label className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Full Name / Rank</label>
                <Input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Col. Vikramaditya Rathore" className="text-xs bg-slate-50 dark:bg-slate-950 border-slate-300 dark:border-slate-800" />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Department / Agency</label>
                <Input value={department} onChange={e => setDepartment(e.target.value)} placeholder="e.g. Directorate General of Military Operations" className="text-xs bg-slate-50 dark:bg-slate-950 border-slate-300 dark:border-slate-800" />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Clearance Level</label>
                <select value={clearance} onChange={e => setClearance(e.target.value)} className="flex h-9 w-full rounded-md border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-3 py-1.5 text-xs text-slate-800 dark:text-slate-200">
                  <option value="Confidential">Confidential</option>
                  <option value="Secret">Secret</option>
                  <option value="TopSecret">Top Secret</option>
                </select>
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">RBAC Role</label>
                <select value={role} onChange={e => setRole(e.target.value)} className="flex h-9 w-full rounded-md border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-3 py-1.5 text-xs text-slate-800 dark:text-slate-200">
                  <option value="Recipient">Recipient</option>
                  <option value="Sender">Sender / Dispatcher</option>
                  <option value="Investigator">Forensic Investigator</option>
                  <option value="Auditor">Auditor</option>
                  <option value="Admin">Administrator</option>
                </select>
              </div>
            </div>
            <DialogFooter>
              <Button disabled={isRegistering || !name || !department} onClick={handleRegister} className="bg-slate-900 hover:bg-slate-800 text-white dark:bg-sky-600 dark:hover:bg-sky-500 text-xs">
                {isRegistering ? 'Generating ML-KEM & ML-DSA...' : 'Enroll Identity'}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Main Content */}
      <Card className="rounded-xl border border-slate-200/80 dark:border-slate-800/80 overflow-hidden bg-white/90 dark:bg-slate-900/80 backdrop-blur-md shadow-xs">
        <CardContent className="p-0">
          {loading ? (
            <div className="p-16 flex flex-col items-center justify-center text-center space-y-3">
              <RefreshCw className="w-8 h-8 text-sky-500 animate-spin" />
              <div className="text-sm font-medium text-slate-600 dark:text-slate-400 font-mono">
                Loading identities from encrypted keystore...
              </div>
            </div>
          ) : users.length === 0 ? (
            <div className="p-16 flex flex-col items-center justify-center text-center max-w-md mx-auto space-y-4">
              <div className="w-16 h-16 rounded-2xl bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 flex items-center justify-center shadow-inner">
                <Users className="w-8 h-8 text-slate-400 dark:text-slate-500" />
              </div>
              <div className="space-y-1">
                <h3 className="text-sm font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
                  No Recipients Enrolled
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                  There are currently no authorized cryptographic identities registered in the system. Register recipient keys to enable secure dispatch.
                </p>
              </div>
              <Button
                onClick={() => setModalOpen(true)}
                variant="outline"
                size="sm"
                className="text-xs flex items-center gap-1.5 border-slate-300 dark:border-slate-700 mt-2"
              >
                <KeyRound className="w-3.5 h-3.5" />
                Register First Recipient
              </Button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/60 text-slate-600 dark:text-slate-400 text-[11px] uppercase tracking-wider">
                    <th className="px-6 py-3.5 font-bold">Recipient ID</th>
                    <th className="px-6 py-3.5 font-bold">Name</th>
                    <th className="px-6 py-3.5 font-bold">Department</th>
                    <th className="px-6 py-3.5 font-bold">Clearance</th>
                    <th className="px-6 py-3.5 font-bold">Role</th>
                    <th className="px-6 py-3.5 font-bold">Key Lifecycle</th>
                    <th className="px-6 py-3.5 font-bold text-right">Lifecycle Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200/70 dark:divide-slate-800/70 text-xs">
                  {users.map(user => (
                    <tr key={user.id} className="hover:bg-slate-50/60 dark:hover:bg-slate-800/40 transition-colors">
                      <td className="px-6 py-3 font-mono text-slate-500 dark:text-slate-400">{user.id}</td>
                      <td className="px-6 py-3 font-semibold text-slate-900 dark:text-slate-100">
                        <div className="flex items-center gap-2">
                          <UserCheck className="w-4 h-4 text-sky-500" />
                          <span>{user.name}</span>
                        </div>
                      </td>
                      <td className="px-6 py-3 text-slate-600 dark:text-slate-300">{user.department}</td>
                      <td className="px-6 py-3">
                        <Badge variant="outline" className="font-mono text-[11px] bg-slate-50 dark:bg-slate-900 border-slate-300 dark:border-slate-700">
                          {user.clearance}
                        </Badge>
                      </td>
                      <td className="px-6 py-3">
                        <Badge className="bg-slate-900 text-white dark:bg-slate-800 dark:text-slate-200 text-[11px]">
                          {user.role}
                        </Badge>
                      </td>
                      <td className="px-6 py-3">
                        {getKeyBadge(user.status)}
                      </td>
                      <td className="px-6 py-3 text-right space-x-1">
                        {user.status.toUpperCase() === 'ACTIVE' ? (
                          <>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleUpdateKeyStatus(user.id, 'SUSPENDED')}
                              className="text-xs border-amber-500/40 text-amber-600 hover:bg-amber-500/10 rounded-lg h-7 px-2"
                            >
                              Suspend
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleUpdateKeyStatus(user.id, 'REVOKED')}
                              className="text-xs border-rose-500/40 text-rose-600 hover:bg-rose-500/10 rounded-lg h-7 px-2"
                            >
                              Revoke
                            </Button>
                          </>
                        ) : (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleUpdateKeyStatus(user.id, 'ACTIVE')}
                            className="text-xs border-emerald-500/40 text-emerald-600 hover:bg-emerald-500/10 rounded-lg h-7 px-2"
                          >
                            Activate
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
