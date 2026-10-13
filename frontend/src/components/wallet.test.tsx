import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { WalletControl, WalletProvider } from './wallet';

const address = '0x1234567890123456789012345678901234567890';
function injected(chain = '0xf22f') {
  const handlers = new Map<string, (...args: unknown[]) => void>();
  const request = vi.fn(async ({ method }: {method:string}) => {
    if (method === 'eth_accounts' || method === 'eth_requestAccounts') return [address];
    if (method === 'eth_chainId') return chain;
    if (method === 'wallet_switchEthereumChain' || method === 'wallet_addEthereumChain') return null;
    throw new Error(`Unexpected ${method}`);
  });
  return { request, on: vi.fn((event:string, cb:(...args:unknown[])=>void)=>handlers.set(event,cb)),
    removeListener: vi.fn(), emit: (event:string,value:unknown)=>handlers.get(event)?.(value) };
}

describe('injected wallet control', () => {
  afterEach(() => { cleanup(); delete window.ethereum; });
  it('shows the connected wallet menu with copy, explorer and disconnect actions', async () => {
    const wallet = injected(); window.ethereum = wallet;
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: vi.fn().mockResolvedValue(undefined) } });
    render(<WalletProvider><WalletControl/></WalletProvider>);
    await waitFor(()=>expect(screen.getByText('0x1234…7890')).toBeTruthy());
    fireEvent.click(screen.getByText('0x1234…7890'));
    expect(screen.getByRole('menuitem', { name: 'Copy Address' })).toBeTruthy();
    expect(screen.getByRole('menuitem', { name: 'View in Explorer' }).getAttribute('href')).toContain(address);
    fireEvent.click(screen.getByRole('menuitem', { name: 'Disconnect' }));
    await waitFor(()=>expect(screen.getByText('Connect wallet')).toBeTruthy());
  });
  it('offers a switch and invokes the Studionet switch request on the wrong network', async () => {
    const wallet = injected('0x1'); window.ethereum = wallet;
    render(<WalletProvider><WalletControl/></WalletProvider>);
    const button = await screen.findByRole('button', { name: /Wrong network/ });
    fireEvent.click(button);
    await waitFor(()=>expect(wallet.request).toHaveBeenCalledWith({ method: 'wallet_switchEthereumChain', params: [{ chainId: '0xF22F' }] }));
  });
  it('reacts to account and chain changes without storing credentials', async () => {
    const wallet = injected(); window.ethereum = wallet;
    render(<WalletProvider><WalletControl/></WalletProvider>);
    await screen.findByText('0x1234…7890');
    wallet.emit('chainChanged', '0x1');
    await screen.findByRole('button', { name: /Wrong network/ });
    wallet.emit('accountsChanged', []);
    await screen.findByText('Connect wallet');
  });
  it('surfaces wallet connection rejection without retaining an account', async () => {
    const wallet = injected();
    wallet.request.mockImplementation(async ({ method }) => {
      if (method === 'eth_accounts') return [];
      if (method === 'eth_requestAccounts') throw new Error('User rejected the request.');
      if (method === 'eth_chainId') return '0xf22f';
      throw new Error(`Unexpected ${method}`);
    });
    window.ethereum = wallet;
    render(<WalletProvider><WalletControl/></WalletProvider>);
    fireEvent.click(await screen.findByText('Connect wallet'));
    expect((await screen.findByRole('alert')).textContent).toContain('User rejected the request.');
    expect(screen.getByText('Connect wallet')).toBeTruthy();
  });
  it('surfaces a rejected network switch and keeps the wallet gated', async () => {
    const wallet = injected('0x1');
    wallet.request.mockImplementation(async ({ method }) => {
      if (method === 'eth_accounts' || method === 'eth_requestAccounts') return [address];
      if (method === 'eth_chainId') return '0x1';
      if (method === 'wallet_switchEthereumChain') throw new Error('User rejected network switch.');
      throw new Error(`Unexpected ${method}`);
    });
    window.ethereum = wallet;
    render(<WalletProvider><WalletControl/></WalletProvider>);
    fireEvent.click(await screen.findByRole('button', { name: /Wrong network/ }));
    expect((await screen.findByRole('alert')).textContent).toContain('User rejected network switch.');
    expect(screen.getByRole('button', { name: /Wrong network/ })).toBeTruthy();
  });
});
