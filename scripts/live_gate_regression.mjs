import { spawnSync } from 'node:child_process';
import { mkdir, writeFile, access } from 'node:fs/promises';
import { join, resolve } from 'node:path';
const address = process.env.STARGAZE_CONTRACT_ADDRESS;
if (!/^0x[0-9a-fA-F]{40}$/.test(address ?? '')) throw new Error('Set STARGAZE_CONTRACT_ADDRESS.');
const root = resolve('evidence/live/gate-regression');
await mkdir(root, {recursive:true});
const ghsa = {advisory_id:'GHSA-r5fr-rjxr-66jc',revision:'ghsa-sha256:3db586ba1c68306eb90349477e0491f239b1bba1c09e35c781529c5ff7bb10c4'};
const unresolved = {advisory_id:'GHSA-r5fr-rjxr-66jc',revision:'osv-sha256:6d94cb4483ee2659025e95633e85e3b5acde11b9013b2a126672eba03a36c457'};
async function run(name, releaseId, artifact, required, shouldRun) {
 const marker=join(root,name+'.marker'), policy=join(root,name+'.json');
 await writeFile(policy,JSON.stringify({chain_id:61999,contract_address:address,release_id:releaseId,artifact_digest:artifact,required},null,2));
 const code='require("node:fs").writeFileSync('+JSON.stringify(marker)+',"ran")';
 const proc=spawnSync(process.execPath,[resolve('node_modules/tsx/dist/cli.mjs'),'scripts/gate.ts',policy,'--',process.execPath,'-e',code],
  {encoding:'utf8',env:{...process.env,STARGAZE_CONTRACT_ADDRESS:address}});
 let markerExists=true; try{await access(marker)}catch{markerExists=false}
 const passed=shouldRun?proc.status===0&&markerExists:proc.status!==0&&!markerExists;
 const item={name,releaseId,exitCode:proc.status,protectedCommandExecuted:markerExists,stdout:proc.stdout,stderr:proc.stderr,passed};
 console.log(JSON.stringify(item));
 if(!passed) process.exitCode=1;
 return item;
}
const records=[
 await run('scenario-a-blocked','rel-1','9aba685f4b44d7a8e778cdf7085e9512143dabd78812df40e258375e1e8dceb4',[ghsa],false),
 await run('scenario-b-authorized','rel-2','aef19210308907f32d1b1d54f40e3cf461dbddae5605efe4027d6646c6967fb0',[ghsa],true),
 await run('two-requirements-hold','rel-2','aef19210308907f32d1b1d54f40e3cf461dbddae5605efe4027d6646c6967fb0',[ghsa,unresolved],false),
];
await writeFile(join(root,'result.json'),JSON.stringify({checkedAt:new Date().toISOString(),chainId:61999,contract:address,records},null,2));
