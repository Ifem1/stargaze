$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $cli = Join-Path $root 'node_modules\.bin\genlayer.cmd'
    if (-not (Test-Path -LiteralPath $cli)) { throw 'Repository-local GenLayer CLI is missing. Run npm ci first.' }
    $version = (& $cli --version | Out-String).Trim()
    if ($version -ne '0.39.1') { throw "Refusing deployment: repository-local GenLayer CLI is $version; expected 0.39.1." }
    $account = (& $cli account show | Out-String)
    if ($account -notmatch "name: 'stargaze-deployer'" -or $account -notmatch "address: '0xd6423ae82a975d55c6ceac222827a727325e0459'") {
        throw 'Refusing deployment: active wallet is not the previously designated STARGAZE throwaway account.'
    }
    $network = (& $cli network info | Out-String)
    if ($network -notmatch "chainId: '61999'" -or $network -notmatch "rpc: 'https://studio\.genlayer\.com/api'") {
        throw 'Refusing deployment: configured CLI network is not stable Studionet 61999 at the required RPC.'
    }
    $rpc = Invoke-RestMethod -Method Post -Uri 'https://studio.genlayer.com/api' -ContentType 'application/json' `
        -Body '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' -TimeoutSec 20
    if ($rpc.result -ne '0xf22f') { throw "Refusing deployment: RPC chain ID was $($rpc.result), expected 0xf22f." }
    $sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath 'contracts/stargaze.py').Hash.ToLowerInvariant()
    Write-Output "Verified stable Studionet 61999 with local GenLayer CLI 0.39.1."
    Write-Output "Contract source SHA-256: $sourceHash"
    Write-Output 'Submitting deployment to the explicitly pinned RPC...'
    & $cli deploy --contract 'contracts/stargaze.py' --rpc 'https://studio.genlayer.com/api'
    if ($LASTEXITCODE -ne 0) { throw "GenLayer deployment CLI exited with code $LASTEXITCODE." }
} finally {
    Pop-Location
}
