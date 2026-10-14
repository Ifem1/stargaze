import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { Wallet } from 'ethers';
import { createAccount, createClient } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';
import { TransactionHashVariant, TransactionStatus } from 'genlayer-js/types';
const rpc = 'https://studio.genlayer.com/api';
const address = process.env.STARGAZE_CONTRACT_ADDRESS, keyPath = process.env.STARGAZE_KEYSTORE_PATH;
if (!/^0x[0-9a-fA-F]{40}$/.test(address ?? '') || !keyPath) throw new Error('Set contract and encrypted keystore paths.');
if (studionet.id !== 61999 || studionet.rpcUrls.default.http[0] !== rpc) throw new Error('Wrong chain.');
if (!process.stdin.isTTY || !process.stdin.setRawMode) throw new Error('A local TTY is required for hidden unlock.');
process.stdout.write('Local keystore password (input hidden): ');
process.stdin.setRawMode(true); process.stdin.resume();
const password = await new Promise((resolve, reject) => {
 let value = '';
 const onData = chunk => { for (const byte of chunk) {
  if (byte === 3) { process.stdin.off('data', onData); process.stdin.setRawMode(false); reject(new Error('Cancelled')); return; }
  if (byte === 13 || byte === 10) { process.stdin.off('data', onData); process.stdin.setRawMode(false); process.stdin.pause(); process.stdout.write(String.fromCharCode(10)); resolve(value); return; }
  if (byte === 8 || byte === 127) value = value.slice(0, -1); else value += String.fromCharCode(byte);
 } };
 process.stdin.on('data', onData);
});
const wallet = await Wallet.fromEncryptedJson(await readFile(keyPath, 'utf8'), password), account = createAccount(wallet.privateKey);
const client = createClient({ chain: studionet, endpoint: rpc, account });
if (await client.getChainId() !== 61999) throw new Error('RPC chain mismatch.');
const read = (name, args=[]) => client.readContract({ address, functionName:name, args, transactionHashVariant:TransactionHashVariant.LATEST_FINAL });
const writes = [];
async function send(label, name, args) {
 const hash = await client.writeContract({account,address,functionName:name,args,value:0n});
 process.stdout.write('SUBMITTED '+label+' '+hash+String.fromCharCode(10));
 const r = await client.waitForTransactionReceipt({hash,status:TransactionStatus.FINALIZED,interval:5000,retries:120});
 const receipt = {label,hash,status:r.status_name,consensus:r.result_name,
  execution:r.consensus_data?.leader_receipt?.find(x=>x.mode==='leader')?.execution_result,votes:r.consensus_data?.votes??{}};
 writes.push(receipt); process.stdout.write(JSON.stringify(receipt)+String.fromCharCode(10));
 return receipt;
}
const release = await read('get_release',['rel-2']);
if (release.owner.toLowerCase() !== account.address.toLowerCase()) throw new Error('Signer must own rel-2.');
const requirements=[];
for (const name of ['multi-ghsa-xxjr-mmjv-4gpg','multi-ghsa-29mw-wpgm-hmr9','multi-ghsa-x5rq-j2xg-h7qm']) {
 const m=JSON.parse(await readFile('evidence/manifests/'+name+'.json','utf8'));
 const sources=[{url:m.primary_url,role:'PRIMARY'},{url:'https://registry.npmjs.org/lodash/4.18.0',role:'SUPPLEMENTAL'}].sort((a,b)=>a.url.localeCompare(b.url));
 const key=[release.id,m.advisory_id,m.revision], prior=await read('get_assessment_by_identity',key);
 let assessment=prior;
 if (!assessment?.id) {
  const reg=await send('register-'+m.advisory_id,'register_assessment',[release.id,m.advisory_id,m.revision,m.advisory_id,'npm','lodash','stargaze-live-multi-v1',JSON.stringify(sources)]);
  if(reg.status==='FINALIZED'&&reg.consensus==='MAJORITY_AGREE'&&reg.execution==='SUCCESS') assessment=await read('get_assessment_by_identity',key);
 }
 if (assessment?.state==='OPEN') {
  const ev=await send('evaluate-'+m.advisory_id,'evaluate_assessment',[assessment.id]);
  if(ev.status==='FINALIZED'&&ev.consensus==='MAJORITY_AGREE'&&ev.execution==='SUCCESS') assessment=await read('get_assessment',[''+assessment.id]);
  else assessment=await read('get_assessment',[''+assessment.id]);
 }
 requirements.push({advisory_id:m.advisory_id,revision:m.revision,assessment});
}
const pack=items=>Buffer.concat(items.map(x=>createHash('sha256').update(release.id+'|'+x.advisory_id+'|'+x.revision).digest()));
const one=await read('authorization_for_release_compact',[release.id,pack(requirements.slice(0,1))]);
const two=await read('authorization_for_release_compact',[release.id,pack(requirements.slice(0,2))]);
const result={checkedAt:new Date().toISOString(),chainId:61999,contract:address,release,transactions:writes,requirements,singleGate:one,twoRequirementGate:two};
await mkdir('evidence/live',{recursive:true}); await writeFile('evidence/live/multi-advisory.json',JSON.stringify(result,null,2)+String.fromCharCode(10));
console.log('MULTI_ADVISORY_PROOF '+JSON.stringify(result));
