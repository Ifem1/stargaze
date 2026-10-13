'use client';
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { Check, ChevronDown, Copy, ExternalLink, Power, Wallet as WalletIcon } from 'lucide-react';
import { CHAIN_HEX, CHAIN_ID, EXPLORER_URL, type Eip1193 } from '@/lib/chain';

type WalletContextValue = { account: string | null; chainId: string | null; provider: Eip1193 | null; connect: () => Promise<void>; disconnect: () => void; switchNetwork: () => Promise<void> };
const WalletContext = createContext<WalletContextValue | null>(null);
export function useWallet() { const value = useContext(WalletContext); if (!value) throw new Error('WalletProvider is missing'); return value; }
export function WalletProvider({ children }: { children: React.ReactNode }) {
  const [account, setAccount] = useState<string | null>(null); const [chainId, setChainId] = useState<string | null>(null); const [provider, setProvider] = useState<Eip1193 | null>(null);
  const connect = useCallback(async () => {
    const injected = window.ethereum; if (!injected) throw new Error('No injected EIP-1193 wallet was detected.');
    const accounts = await injected.request({ method: 'eth_requestAccounts' }) as string[];
    const currentChain = await injected.request({ method: 'eth_chainId' }) as string;
    setProvider(injected); setAccount(accounts[0] ?? null); setChainId(currentChain);
  }, []);
  const disconnect = useCallback(() => { setAccount(null); setProvider(null); }, []);
  const switchNetwork = useCallback(async () => {
    if (!provider) { await connect(); return; }
    try { await provider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: CHAIN_HEX }] }); }
    catch (error) {
      const code = typeof error === 'object' && error !== null && 'code' in error ? (error as { code: number }).code : 0;
      if (code !== 4902) throw error;
      await provider.request({ method: 'wallet_addEthereumChain', params: [{ chainId: CHAIN_HEX, chainName: 'GenLayer Studionet', nativeCurrency: { name: 'GEN', symbol: 'GEN', decimals: 18 }, rpcUrls: ['https://studio.genlayer.com/api'], blockExplorerUrls: [EXPLORER_URL] }] });
      await provider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: CHAIN_HEX }] });
    }
  }, [connect, provider]);
  useEffect(() => {
    const injected = window.ethereum; if (!injected) return;
    const onAccounts = (value: unknown) => setAccount(Array.isArray(value) ? (value[0] as string ?? null) : null);
    const onChain = (value: unknown) => setChainId(String(value));
    const onConnect = async () => { const accounts = await injected.request({ method: 'eth_accounts' }) as string[]; setAccount(accounts[0] ?? null); setChainId(await injected.request({ method: 'eth_chainId' }) as string); setProvider(injected); };
    injected.on?.('accountsChanged', onAccounts); injected.on?.('chainChanged', onChain); injected.on?.('connect', onConnect);
    void onConnect();
    return () => { injected.removeListener?.('accountsChanged', onAccounts); injected.removeListener?.('chainChanged', onChain); injected.removeListener?.('connect', onConnect); };
  }, []);
  const value = useMemo(() => ({ account, chainId, provider, connect, disconnect, switchNetwork }), [account, chainId, provider, connect, disconnect, switchNetwork]);
  return <WalletContext.Provider value={value}>{children}</WalletContext.Provider>;
}

export function WalletControl() {
  const { account, chainId, connect, disconnect, switchNetwork } = useWallet(); const [open, setOpen] = useState(false); const [copied, setCopied] = useState(false); const [error, setError] = useState('');
  const correct = chainId?.toLowerCase() === CHAIN_HEX.toLowerCase();
  const short = account ? `${account.slice(0, 6)}…${account.slice(-4)}` : '';
  const handleConnect = async () => { setError(''); try { await connect(); } catch (e) { setError(e instanceof Error ? e.message : 'Wallet connection was rejected.'); } };
  const copy = async () => { if (account) { await navigator.clipboard.writeText(account); setCopied(true); window.setTimeout(() => setCopied(false), 1500); } };
  return <div className="relative flex items-center gap-2">
    {account && !correct && <button className="button-quiet text-amber-100" onClick={() => void switchNetwork().catch(e => setError(e instanceof Error ? e.message : 'Network switch rejected.'))} title="Switch to GenLayer Studionet">Wrong network · Switch</button>}
    {account && correct && <span className="hidden rounded-full border border-emerald-200/20 bg-emerald-300/5 px-3 py-2 text-xs text-emerald-100 sm:block">Studionet · {CHAIN_ID}</span>}
    {!account ? <button className="button-primary inline-flex items-center gap-2" onClick={() => void handleConnect()}><WalletIcon size={16}/> Connect wallet</button> : <button className="button-quiet inline-flex items-center gap-2" aria-expanded={open} onClick={() => setOpen(v => !v)}>{short}<ChevronDown size={14}/></button>}
    {open && account && <div role="menu" className="panel absolute right-0 top-12 z-50 w-60 rounded-2xl p-2 shadow-2xl">
      <button role="menuitem" onClick={() => void copy()} className="flex w-full items-center gap-3 rounded-xl px-3 py-3 text-sm hover:bg-white/5">{copied ? <Check size={15}/> : <Copy size={15}/>} {copied ? 'Copied' : 'Copy Address'}</button>
      <a role="menuitem" target="_blank" rel="noreferrer" href={`${EXPLORER_URL}/address/${account}`} className="flex items-center gap-3 rounded-xl px-3 py-3 text-sm hover:bg-white/5"><ExternalLink size={15}/> View in Explorer</a>
      <button role="menuitem" onClick={() => { disconnect(); setOpen(false); }} className="flex w-full items-center gap-3 rounded-xl px-3 py-3 text-sm text-rose-200 hover:bg-white/5"><Power size={15}/> Disconnect</button>
    </div>}
    {error && <span role="alert" className="absolute right-0 top-14 z-40 max-w-72 rounded-xl border border-rose-200/20 bg-[#2b1026] p-3 text-xs text-rose-100">{error}</span>}
  </div>;
}
