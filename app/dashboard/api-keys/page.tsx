"use client";

import React, { useState, useEffect } from 'react';
import { Key, Plus, Trash2, Copy, Check, AlertTriangle, ShieldCheck, Terminal } from 'lucide-react';

interface ApiKeyItem {
  id: string;
  key_name: string;
  key_prefix: string;
  created_at: string;
  last_used_at: string | null;
}

export default function ApiKeysPage() {
  const [keys, setKeys] = useState<ApiKeyItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Modal State
  const [modalOpen, setModalOpen] = useState(false);
  const [newKeyName, setNewKeyName] = useState('Local Pre-Commit Hook Key');
  const [creating, setCreating] = useState(false);
  const [revealedKey, setRevealedKey] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);

  const fetchKeys = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/keys');
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to list API keys.');
      setKeys(data.keys || []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchKeys();
  }, []);

  const handleCreateKey = async () => {
    setCreating(true);
    setError(null);
    try {
      const res = await fetch('/api/keys', {
        method: 'POST',
        body: JSON.stringify({ name: newKeyName }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to create key.');

      setRevealedKey(data.key.plaintextSecret);
      fetchKeys();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteKey = async (id: string) => {
    if (!confirm('Are you sure you want to revoke this API key? This cannot be undone.')) return;

    try {
      const res = await fetch(`/api/keys?id=${id}`, { method: 'DELETE' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to delete key.');
      setKeys(keys.filter((k) => k.id !== id));
    } catch (err) {
      alert((err as Error).message);
    }
  };

  const copyPlaintext = async () => {
    if (!revealedKey) return;
    await navigator.clipboard.writeText(revealedKey);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Key className="w-5 h-5 text-indigo-400" />
            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              Developer API Keys
            </h1>
          </div>
          <p className="text-xs sm:text-sm text-slate-400">
            Authenticate the `aegis.py` CLI and Git pre-commit hooks against your personal cloud quota.
          </p>
        </div>

        <button
          onClick={() => {
            setRevealedKey(null);
            setModalOpen(true);
          }}
          className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs sm:text-sm transition flex items-center gap-2 shadow-lg shadow-cyan-500/20 self-start sm:self-auto"
        >
          <Plus className="w-4 h-4" />
          <span>Generate New Key</span>
        </button>
      </div>

      {/* CLI Instruction Banner */}
      <div className="p-4 rounded-2xl bg-[#060b18] border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-cyan-500/10 text-cyan-400 flex items-center justify-center flex-shrink-0">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xs font-bold text-white">Using with aegis.py CLI</div>
            <div className="text-[11px] text-slate-400">
              Export your key in your shell: <code className="text-cyan-300 font-mono">export AEGIS_API_KEY="aegis_live_..."</code>
            </div>
          </div>
        </div>
      </div>

      {/* Keys Table */}
      <div
        data-tour="api-keys-table"
        className="bg-[#060b18] border border-slate-800 rounded-2xl overflow-hidden shadow-xl"
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/80 border-b border-slate-800 text-[10px] uppercase font-bold text-slate-400 tracking-wider">
              <tr>
                <th className="p-3.5 pl-5">Key Name</th>
                <th className="p-3.5">Key Prefix</th>
                <th className="p-3.5">Created</th>
                <th className="p-3.5">Last Used</th>
                <th className="p-3.5 pr-5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {loading ? (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-slate-500 font-sans">
                    Loading developer keys...
                  </td>
                </tr>
              ) : keys.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-slate-400 font-sans">
                    No API keys created yet. Generate one above to configure your pre-commit hook.
                  </td>
                </tr>
              ) : (
                keys.map((k) => (
                  <tr key={k.id} className="hover:bg-slate-900/40 transition">
                    <td className="p-3.5 pl-5 font-sans font-semibold text-white">{k.key_name}</td>
                    <td className="p-3.5 text-cyan-400 font-mono">{k.key_prefix}...</td>
                    <td className="p-3.5 text-slate-400">
                      {new Date(k.created_at).toLocaleDateString()}
                    </td>
                    <td className="p-3.5 text-slate-400">
                      {k.last_used_at ? new Date(k.last_used_at).toLocaleDateString() : 'Never'}
                    </td>
                    <td className="p-3.5 pr-5 text-right font-sans">
                      <button
                        onClick={() => handleDeleteKey(k.id)}
                        className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-950/30 transition"
                        title="Revoke Key"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* GENERATE KEY MODAL */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#090f20] border border-slate-700 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Key className="w-4 h-4 text-cyan-400" />
              Generate Developer API Key
            </h3>

            {!revealedKey ? (
              <div className="space-y-3">
                <label className="text-xs text-slate-300 block">Key Identifier / Name</label>
                <input
                  type="text"
                  value={newKeyName}
                  onChange={(e) => setNewKeyName(e.target.value)}
                  placeholder="e.g. MacBook Pro Pre-Commit Hook"
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-xl text-xs text-white focus:outline-none focus:border-cyan-500"
                />

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    onClick={() => setModalOpen(false)}
                    className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 text-xs font-semibold hover:bg-slate-700 transition"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleCreateKey}
                    disabled={creating || !newKeyName.trim()}
                    className="px-5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold transition disabled:opacity-50"
                  >
                    {creating ? 'Hashing Key...' : 'Create Key'}
                  </button>
                </div>
              </div>
            ) : (
              /* One-time plaintext token reveal view */
              <div className="space-y-3">
                <div className="p-3 rounded-xl bg-amber-950/40 border border-amber-500/40 text-amber-200 text-xs flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 flex-shrink-0 text-amber-400 mt-0.5" />
                  <span>
                    Copy your API secret key now. You will not be able to view it again!
                  </span>
                </div>

                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between gap-2">
                  <span className="font-mono text-xs text-cyan-300 break-all select-all">
                    {revealedKey}
                  </span>
                  <button
                    onClick={copyPlaintext}
                    className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition flex-shrink-0"
                    title="Copy Secret"
                  >
                    {copiedKey ? (
                      <Check className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </button>
                </div>

                <div className="flex justify-end pt-2">
                  <button
                    onClick={() => {
                      setModalOpen(false);
                      setRevealedKey(null);
                    }}
                    className="px-5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold transition"
                  >
                    Done
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
