'use client';
import Link from 'next/link';
import Image from 'next/image';
import { usePathname } from 'next/navigation';
import { AnimatePresence, motion } from 'framer-motion';
import { useState } from 'react';
import { Menu, X } from 'lucide-react';
import { WalletControl } from './wallet';

const links = [
  ['/', 'Overview'], ['/releases', 'Releases'], ['/register', 'Register release'], ['/assessments', 'Advisory assessments'],
  ['/lineage', 'Release lineage'], ['/gate', 'Authorization gate'], ['/docs', 'Documentation'],
];
function Brand() { return <Link href="/" className="flex items-center gap-3"><Image src="/favicon.svg" alt="Stargaze S-in-star" width={36} height={36} priority/><span><span className="block font-display text-lg tracking-[.13em]">STARGAZE</span><span className="block text-[9px] uppercase tracking-[.21em] text-pink-100/50">Release intelligence</span></span></Link>; }
export function AppShell({ children }: { children: React.ReactNode }) {
  const path = usePathname(); const [menuOpen, setMenuOpen] = useState(false);
  return <div className="relative min-h-screen">
    <span className="spark left-[14%] top-[19%]"/><span className="spark left-[76%] top-[31%] [animation-delay:2s]"/><span className="spark left-[60%] top-[82%] [animation-delay:4s]"/>
    <aside className="fixed inset-y-0 left-0 z-30 hidden w-[254px] flex-col border-r border-pink-100/10 bg-[#1a0b1a]/75 px-6 py-7 backdrop-blur-xl lg:flex">
      <Brand/><nav className="mt-14 space-y-1" aria-label="Primary navigation">{links.map(([href, label]) => <Link key={href} href={href} className={`block rounded-xl px-4 py-3 text-sm transition ${path === href ? 'border border-rose-200/10 bg-rose-300/[.08] text-rose-50' : 'text-pink-100/60 hover:bg-white/[.035] hover:text-pink-50'}`}>{label}</Link>)}</nav>
      <div className="mt-auto rounded-2xl border border-pink-100/10 bg-white/[.025] p-4"><div className="text-[10px] uppercase tracking-[.19em] text-pink-100/50">Network</div><div className="mt-2 text-sm">GenLayer Studionet</div><div className="mt-1 text-xs text-pink-100/50">Chain 61999 · stable</div></div>
    </aside>
    <div className="lg:pl-[254px]">
      <header className="sticky top-0 z-20 flex h-[76px] items-center justify-between border-b border-pink-100/10 bg-[#1b0b1b]/75 px-5 backdrop-blur-xl sm:px-8">
        <div className="flex items-center gap-3 lg:hidden"><button aria-label={menuOpen ? 'Close menu' : 'Open menu'} className="button-quiet !p-2" onClick={() => setMenuOpen(v => !v)}>{menuOpen ? <X size={17}/> : <Menu size={17}/>}</button><Brand/></div>
        <div className="hidden text-xs uppercase tracking-[.16em] text-pink-100/45 lg:block">Know what is exposed before you ship</div><WalletControl/>
      </header>
      <AnimatePresence>{menuOpen && <motion.nav initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden border-b border-pink-100/10 bg-[#1a0b1a] px-5 lg:hidden">{links.map(([href, label]) => <Link key={href} onClick={() => setMenuOpen(false)} href={href} className={`block border-b border-white/5 py-3 text-sm ${path === href ? 'text-rose-200' : 'text-pink-50/70'}`}>{label}</Link>)}</motion.nav>}</AnimatePresence>
      <main className="relative z-10 mx-auto max-w-[1500px] px-5 py-8 sm:px-8 sm:py-11">{children}</main>
    </div>
  </div>;
}
