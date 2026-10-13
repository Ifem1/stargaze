import { Suspense } from 'react';
import { ReleaseDetail } from '@/components/pages';
export default function Page() { return <Suspense fallback={<div className="muted p-8">Loading release record…</div>}><ReleaseDetail/></Suspense>; }
