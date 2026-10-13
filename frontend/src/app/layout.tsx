import type { Metadata } from 'next';
import './globals.css';
import { WalletProvider } from '@/components/wallet';
import { AppShell } from '@/components/shell';

export const metadata: Metadata = {
  title: 'Stargaze — Release Intelligence',
  description: 'Advisory-scoped release intelligence and authorization on GenLayer Studionet.',
  icons: { icon: '/favicon.svg' },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body><WalletProvider><AppShell>{children}</AppShell></WalletProvider></body></html>;
}
