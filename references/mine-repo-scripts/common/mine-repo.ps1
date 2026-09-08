# mine-repo.ps1 - fetch everything a reference sweep needs, and KEEP it.
#
# ⭐ THE TWIN OF mine-repo.sh, and the one to prefer on Windows. A native
# PowerShell session is not Git Bash: measured on one Windows 11 machine it had
# no `sed` at all, and `sort` resolved to PowerShell's own `Sort-Object` alias
# rather than the coreutils binary. The sh twin needs `awk`, `grep`, `wc` and
# `find`; this one needs none of them.
#
# ⭐ A HELPER, NOT A CHECK. It writes. scripts/README.md's five-point contract
# is for checks; this is held to the header rule and the exit-code rule.
#
# ⚠ IT IS NOT COMPARED BY check-twins.sh, and scripts/README.md says why: a
# comparison would have to fetch a live third-party repository twice on every
# run, which makes a local check depend on somebody else's uptime, and the
# output is a directory of files rather than a verdict to diff. The pair is
# proved instead by running both against one target and comparing what landed.
# That was done on 2026-08-28 against pkgforge-dev/cross-libc-dlopen: both
# routes and both twins returned 26 issues, 13 comments, 0 review comments, 1
# release and 1 tag.
#
# -- THE DEFECT THIS EXISTS TO CATCH -----------------------------------------
#
# ⛔ TWO SWEEPS, TWO WAYS OF LOSING THE SAME WORK, BOTH OBSERVED. One kept the
# conclusions and threw away eleven clones, so every citation became a claim.
# One wrote its own fetchers in Python, produced real JSON, and deleted both on
# the way out because the clones were in a scratch directory and the scripts in
# a session-local scratchpad.
#
# ⭐ Both are the same defect: the DERIVED file was treated as the product and
# the EVIDENCE as scratch. It is the wrong way round.
#
# -- THE TWO ROUTES ----------------------------------------------------------
#
# ⚠ `gh` HAS BEEN PRESENT, ON PATH, AND HOLDING A DEAD TOKEN. The probe is
# `gh auth status` AND a real API call, not the binary existing.
#
# ⚠ ABOUT THE PUBLIC PROXY, measured here on 2026-08-28:
#   ⛔ It is NOT unauthenticated. It makes authenticated requests on behalf of
#      the PkgForge account. What it gives you is a route carrying none of YOUR
#      credentials. That is not the same as "cannot reach a private repository".
#   ⚠ The route set is wider than /repos/*: /users/*, /orgs/*, /search/* and
#      /rate_limit all answer. /user, the who-am-I endpoint, is refused.
#   ⛔ A browser-like or empty user-agent is refused with HTTP 420. Not 401,
#      not 403. Nothing has a branch for 420, so it reads as an unknown error.
#
# ⭐ A 404 IS EVIDENCE ONLY BESIDE A CONTROL. This hits a known-public control
# in the same run and writes which it was into PROVENANCE.md.
#
# ⛔ READS ONLY. No write verb reaches either route. docs/security/remote-ops.md.
#
# Usage:
#   pwsh -NoProfile -File scripts/common/mine-repo.ps1 OWNER/NAME
#   pwsh -NoProfile -File scripts/common/mine-repo.ps1 OWNER/NAME -Out references
#   pwsh -NoProfile -File scripts/common/mine-repo.ps1 OWNER/NAME -Route proxy -NoClone
#   pwsh -NoProfile -File scripts/common/mine-repo.ps1 -SelfTest   the joiner, offline
#
# Exit codes: 0 the subject was fetched, 1 it was not, 2 could not run.
#
# ⛔ Read the exit code from this process, unpiped.

# ⛔ PositionalBinding IS OFF for every named parameter, and Target is the one
# deliberate positional. A .ps1 invoked through `-File` receives whatever the
# calling shell expanded as separate arguments, and a stray one binds onto the
# next free parameter in declaration order. That shipped a commit under a
# fabricated author in a sibling script in this directory: four gate strings
# overflowed into -Name and -Email, and the identity check passed because
# author and committer were the same wrong string.
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Position = 0)]
    [string]$Target = '',
    [string]$Out = 'references',
    [ValidateSet('auto', 'gh', 'proxy')]
    [string]$Route = 'auto',
    [switch]$NoClone,
    [switch]$SelfTest,
    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$proxy = 'https://api.gh.pkgforge.dev'
$control = 'pkgforge-dev/reverse-proxies'

$gaps = New-Object System.Collections.ArrayList
function Add-Gap([string]$T) { [void]$gaps.Add('  - ' + $T) }
function Say([string]$T) { if (-not $Json) { Write-Output $T } }

# ⛔ JOIN PAGES WITH A REAL PARSER. EACH PAGE IS ITS OWN DOCUMENT.
#
# The sh twin shipped a joiner that concatenated the pages into one buffer and
# recovered the array bounds by counting bracket characters over the RAW TEXT,
# which counts the brackets inside string values too. It was reported by a
# consumer whose whole comment corpus arrived empty while the run printed "ok".
# This half never had that defect; it has this function so both halves have one
# joiner to prove and -SelfTest can drive it.
function Join-Pages {
    # ⚠ The attribute has to sit INSIDE the function, above its param block.
    # Written above `function` it is a parse error, not a suppression.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'It joins pages, plural. The defect it exists to prevent is a joiner that sees one array where there are several, so a singular name would describe it less accurately than the rule it satisfies.')]
    param([string]$OutFile, [string]$Label, [string[]]$Pages)
    $all = New-Object System.Collections.ArrayList
    foreach ($p in $Pages) {
        try {
            $items = @(Get-Content -Raw -LiteralPath $p -Encoding utf8 | ConvertFrom-Json)
        }
        catch {
            Add-Gap ($Label + ': a page did not parse as JSON. Pages are left as ' + $OutFile + '.page.N')
            return $false
        }
        foreach ($i in $items) { [void]$all.Add($i) }
    }
    # ⚠ -Depth 100. ConvertTo-Json truncates at depth 2 by default and writes a
    # type name where the object should be, which is a file that parses, looks
    # populated, and has lost the nesting a reader came for.
    #
    # ⛔ -InputObject, AND NO -AsArray. THIS EXACT FORM, and it took three wrong
    # ones to find it. Every alternative writes a file that PARSES and is wrong,
    # so nothing but comparing against the sh twin could catch it. Measured on
    # pwsh 7 with collections of 0, 1 and 3 items:
    #
    #   form                          0 items   1 item        3 items
    #   pipeline, no -AsArray         nothing   bare OBJECT   array
    #   pipeline + -AsArray           NOTHING   array         array
    #   -InputObject + -AsArray       [[]]      [[{...}]]     [[...]]
    #   ⭐ -InputObject, no -AsArray   []        [{...}]       [...]
    #
    # The bare-object row is the expensive one: `jq length` counts an object's
    # KEYS, so this repository's releases read as 20 and its tags as 5 against
    # 1 and 1 from the sh twin. The empty rows are the quiet one: a zero-item
    # fetch wrote a zero-byte file that is not JSON at all.
    [System.IO.File]::WriteAllText($OutFile,
        (ConvertTo-Json -InputObject $all.ToArray() -Depth 100))

    # ⛔ THE JOIN READS ITS OWN EFFECT BACK. A writer that returns without
    # writing is the forbidden-patterns row about a step that succeeds having
    # done nothing.
    if (-not (Test-Path -LiteralPath $OutFile -PathType Leaf) -or
        (Get-Item -LiteralPath $OutFile).Length -eq 0) {
        Add-Gap ($Label + ': the join wrote no output. Pages are left as ' + $OutFile + '.page.N')
        return $false
    }
    return (Test-JoinNonEmpty -OutFile $OutFile -Label $Label -Pages $Pages)
}

# ⛔ AN EMPTY JOIN OVER A PAGE THAT HAS RECORDS IN IT IS A FAILURE, NOT AN EMPTY
# TRACKER. The sh twin's defect was invisible precisely because nothing asked
# this question: `[]` and "this repository has no comments" are the same bytes,
# and only the input can tell them apart.
#
# ⭐ It is a function of its own so -SelfTest can drive it directly. A guard
# reachable only through the thing it guards gets proved by accident or not at
# all.
function Test-JoinNonEmpty([string]$OutFile, [string]$Label, [string[]]$Pages) {
    $body = (Get-Content -Raw -LiteralPath $OutFile -Encoding utf8) -replace '\s', ''
    if ($body -ne '[]') { return $true }
    foreach ($p in $Pages) {
        if ((Get-Content -Raw -LiteralPath $p -Encoding utf8) -match '"url"') {
            Add-Gap ($Label + ': the join produced an empty array from a page that has records in it. Pages are left as ' + $OutFile + '.page.N')
            return $false
        }
    }
    return $true
}

# -- -SelfTest: the joiner and its guard, against an oracle, no network -------
#
# ⭐ THE INSTRUMENT SHIPS WITH THE SCRIPT, and it is the same four cases the sh
# twin runs, with the same JSON line, so check-twins.sh can compare the pair
# without a network.
#
# ⚠ IT ASSERTS ON THE JOIN AND THE GUARD ONLY. Paging, the proxy, the routes
# and the clone are not exercised, and a green self-test says nothing about
# them.
function Invoke-SelfTest {
    $dir = Join-Path ([System.IO.Path]::GetTempPath()) ('mine-repo-selftest-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $p1 = Join-Path $dir 'p.page.1'
    $p2 = Join-Path $dir 'p.page.2'
    $blank = Join-Path $dir 'blank.page.1'
    $joined = Join-Path $dir 'joined.json'
    $empty = Join-Path $dir 'empty.json'

    # ⛔ THE FIXTURE CARRIES THE SHAPE THAT BROKE THE SH TWIN: bracket
    # characters inside string values, unbalanced, spread over two pages.
    [System.IO.File]::WriteAllText($p1, @'
[
 {"url": "https://example.com/1", "body": "see [the report](https://example.com/r"},
 {"url": "https://example.com/2", "body": "log: [ERROR] [WARN] two opened, none closed"},
 {"url": "https://example.com/3", "body": "plain"}
]
'@)
    [System.IO.File]::WriteAllText($p2, @'
[
 {"url": "https://example.com/4", "body": "]["}
]
'@)
    [System.IO.File]::WriteAllText($blank, "[]`n")

    # ⚠ SCRIPT SCOPE, EXPLICITLY. A nested function assigning `$cases` creates
    # its OWN copy and the caller's stays at zero, so every case would pass and
    # the count would print 0. Under Set-StrictMode the half-written form fails
    # loudly instead, which is how this was found.
    $script:stCases = 0
    $script:stFailed = 0
    $script:stNote = ''
    function Test-Case([string]$Name, $Expected, $Actual) {
        $script:stCases++
        if ("$Expected" -eq "$Actual") {
            if (-not $Json) { Write-Output ("  ok    {0} = {1}" -f $Name, $Actual) }
        }
        else {
            $script:stFailed++
            $script:stNote += ("{0}: expected {1}, got {2}. " -f $Name, $Expected, $Actual)
            if (-not $Json) { Write-Output ("  FAIL  {0}: expected {1}, got {2}" -f $Name, $Expected, $Actual) }
        }
    }

    # 1. every record from every page survives the join
    if (Join-Pages -OutFile $joined -Label 'selftest' -Pages @($p1, $p2)) {
        $n = ([regex]::Matches((Get-Content -Raw -LiteralPath $joined -Encoding utf8), '"url"')).Count
    }
    else { $n = 'refused' }
    Test-Case 'records-joined' 4 $n

    # 2. the result is ONE array, not several concatenated
    $arrays = 0
    if (Test-Path -LiteralPath $joined -PathType Leaf) {
        $arrays = ([regex]::Matches((Get-Content -Raw -LiteralPath $joined -Encoding utf8), '(?m)^\[')).Count
    }
    Test-Case 'arrays-in-output' 1 $arrays

    # ⛔ 3. THE GUARD REFUSES AN EMPTY JOIN OVER A PAGE THAT HAS RECORDS.
    [System.IO.File]::WriteAllText($empty, "[]`n")
    $g = if (Test-JoinNonEmpty -OutFile $empty -Label 'selftest-guard' -Pages @($p1)) { 'accepted' } else { 'refused' }
    Test-Case 'empty-over-records' 'refused' $g

    # ⚠ 4. AND IT ACCEPTS A GENUINELY EMPTY TRACKER. A guard that refused both
    # would turn every repository with no comments into a failed fetch.
    $g = if (Test-JoinNonEmpty -OutFile $empty -Label 'selftest-guard' -Pages @($blank)) { 'accepted' } else { 'refused' }
    Test-Case 'empty-over-nothing' 'accepted' $g

    Remove-Item -Recurse -Force -LiteralPath $dir -ErrorAction SilentlyContinue
    $gaps.Clear()

    if ($Json) {
        Write-Output ('{"schema":"mine-repo-selftest/1","cases":' + $script:stCases + ',"failed":' + $script:stFailed + '}')
    }
    elseif ($script:stFailed -eq 0) {
        Write-Output ("mine-repo -SelfTest: {0} cases, all pass." -f $script:stCases)
    }
    else {
        [Console]::Error.WriteLine("mine-repo -SelfTest: $($script:stCases) cases, $($script:stFailed) FAILED. $($script:stNote)")
    }
}

# ⭐ -SelfTest RUNS BEFORE EVERYTHING ELSE. It needs no target, no network and
# no credential, so requiring any of them would make the one part of this
# script that can be proved the part hardest to run.
#
# ⛔ THE VERDICT IS READ FROM A VARIABLE, NEVER RETURNED. `exit (Invoke-SelfTest)`
# captures the function's OUTPUT STREAM, so every reported line becomes part of
# the return value and the run prints nothing at all while exiting 0. That is
# a check reporting success having shown nothing, and it happened here.
if ($SelfTest) {
    Invoke-SelfTest
    if ($script:stFailed -eq 0) { exit 0 }
    exit 1
}

if ($Target -notmatch '^[^/]+/[^/]+$') {
    [Console]::Error.WriteLine('mine-repo: give a target as OWNER/NAME')
    exit 2
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    [Console]::Error.WriteLine('mine-repo: git not found')
    exit 2
}

$owner, $name = $Target -split '/', 2
$dest = Join-Path $Out ($owner + '__' + $name)
$apiDir = Join-Path $dest 'api'
New-Item -ItemType Directory -Force -Path $apiDir | Out-Null

# ⛔ REFUSE TO WRITE INTO A DIRECTORY THIS REPOSITORY'S OWN IGNORE RULES WOULD
# SWALLOW. The corpus is the evidence; an ignored corpus exists on one machine
# and every claim built on it becomes unsourced the moment that machine is not
# the one asking. A `references/` ignore rule shipped in this template's own
# dotfiles for exactly the reasoning this refuses.
& git check-ignore -q -- $dest 2>$null
if ($LASTEXITCODE -eq 0) {
    [Console]::Error.WriteLine("mine-repo: $dest is ignored by this repository.")
    [Console]::Error.WriteLine('mine-repo: the corpus IS the evidence. An ignored one is lost on the')
    [Console]::Error.WriteLine('mine-repo: next machine, and every citation built on it goes unsourced.')
    [Console]::Error.WriteLine('mine-repo: un-ignore it, choose another -Out, or put the corpus on its')
    [Console]::Error.WriteLine('mine-repo: own branch. docs/methodology/references.md section 4.')
    [Console]::Error.WriteLine('mine-repo: the rule that did it:')
    & git check-ignore -v -- $dest 2>$null | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 2
}

# -- route selection ---------------------------------------------------------
function Get-Route {
    if ($Route -eq 'proxy') { return 'proxy' }
    if ($Route -eq 'gh')    { return 'gh' }
    if (Get-Command gh -ErrorAction SilentlyContinue) {
        & gh auth status *> $null
        if ($LASTEXITCODE -eq 0) {
            & gh api rate_limit *> $null
            if ($LASTEXITCODE -eq 0) { return 'gh' }
        }
    }
    return 'proxy'
}
$route = Get-Route
Say ("route: " + $route)

# ⛔ THE USER-AGENT IS SENT EXPLICITLY. PowerShell's default is a long
# WindowsPowerShell/.NET string, which the proxy reads as browser-like and
# refuses with 420. Naming it here means a future edit cannot drop it silently.
$ua = 'curl/8'

function Invoke-Proxy([string]$Path, [string]$OutFile) {
    try {
        $r = Invoke-WebRequest -Uri ($proxy + $Path) -Headers @{ 'User-Agent' = $ua } `
                -MaximumRedirection 5 -TimeoutSec 60 -SkipHttpErrorCheck
        if ($r.StatusCode -eq 200) {
            [System.IO.File]::WriteAllText($OutFile, $r.Content)
        }
        return [int]$r.StatusCode
    }
    catch { return 0 }
}

# ⚠ THE SEPARATOR IS CHOSEN, NOT ASSUMED. A path that already carries a query,
# which /issues?state=all does, needs `&`. Appending `?` unconditionally sent
# `state=all?per_page=100` and GitHub answered 422 with that string quoted
# back. Found by running the sh twin, not by reading it.
function Get-Sep([string]$P) { if ($P.Contains('?')) { '&' } else { '?' } }

function Get-List([string]$Path, [string]$OutFile, [string]$Label) {
    $sep = Get-Sep $Path
    if ($route -eq 'gh') {
        & gh api --paginate ($Path + $sep + 'per_page=100') > $OutFile 2>$null
        if ($LASTEXITCODE -eq 0) { Say ("  " + $Label + ": ok"); return }
        Add-Gap ($Label + ': gh could not fetch ' + $Path)
        Say ("  " + $Label + ": FAILED")
        return
    }
    # ⚠ THE PROXY IS PAGED BY HAND. A page shorter than per_page is the last
    # one; a page exactly per_page long is followed by another request, because
    # "it returned 100" and "there are exactly 100" are indistinguishable
    # without asking.
    $pages = New-Object System.Collections.ArrayList
    for ($page = 1; $page -le 10; $page++) {
        $tmp = $OutFile + '.page.' + $page
        $code = Invoke-Proxy ($Path + $sep + 'per_page=100&page=' + $page) $tmp
        if ($code -ne 200) {
            Add-Gap ($Label + ': proxy returned ' + $code + ' on page ' + $page)
            Say ("  " + $Label + ": http " + $code)
            foreach ($p in $pages) { Remove-Item -LiteralPath $p -ErrorAction SilentlyContinue }
            Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
            return
        }
        [void]$pages.Add($tmp)
        $n = ([regex]::Matches((Get-Content -Raw -LiteralPath $tmp -Encoding utf8), '"url"')).Count
        if ($n -lt 100) { break }
    }
    if (-not (Join-Pages -OutFile $OutFile -Label $Label -Pages $pages.ToArray())) {
        Say ("  " + $Label + ": JOIN FAILED")
        return
    }
    foreach ($p in $pages) { Remove-Item -LiteralPath $p -ErrorAction SilentlyContinue }
    Say ("  " + $Label + ": ok")
}

# -- the control, before any 404 is believed ---------------------------------
if ($route -eq 'proxy') {
    $tmp = Join-Path $apiDir '.control.json'
    $c = Invoke-Proxy ('/repos/' + $control) $tmp
    Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
    $controlOk = if ($c -eq 200) { "reachable ($control answered 200)" }
                 else { "⛔ UNREACHABLE ($control answered $c). A 404 below means nothing." }
}
else {
    & gh api ('repos/' + $control) *> $null
    $controlOk = if ($LASTEXITCODE -eq 0) { "reachable ($control answered)" }
                 else { "⛔ UNREACHABLE ($control did not answer). A 404 below means nothing." }
}
Say ("control: " + $controlOk)

# -- the subject -------------------------------------------------------------
Say ("fetching " + $Target)
$repoFile = Join-Path $apiDir 'repo.json'
if ($route -eq 'gh') {
    & gh api ('repos/' + $Target) > $repoFile 2>$null
    if ($LASTEXITCODE -ne 0) {
        [Console]::Error.WriteLine("mine-repo: could not fetch repos/$Target")
        [Console]::Error.WriteLine("mine-repo: control says: $controlOk")
        exit 1
    }
}
else {
    $c = Invoke-Proxy ('/repos/' + $Target) $repoFile
    if ($c -ne 200) {
        [Console]::Error.WriteLine("mine-repo: proxy returned $c for repos/$Target")
        [Console]::Error.WriteLine("mine-repo: control says: $controlOk")
        exit 1
    }
}

# ⛔ BOTH STATES, AND THE ISSUES ENDPOINT RETURNS PULL REQUESTS TOO. The
# open-issue count in the metadata counts both, so a sweep that does not
# discriminate on the pull_request field reports a dependency bump as an issue.
Get-List ('/repos/' + $Target + '/issues?state=all') (Join-Path $apiDir 'issues.json')          'issues and pull requests'
Get-List ('/repos/' + $Target + '/issues/comments') (Join-Path $apiDir 'comments.json')         'comments'
Get-List ('/repos/' + $Target + '/pulls/comments')  (Join-Path $apiDir 'review-comments.json')  'review comments'
Get-List ('/repos/' + $Target + '/releases')        (Join-Path $apiDir 'releases.json')         'releases'
Get-List ('/repos/' + $Target + '/tags')            (Join-Path $apiDir 'tags.json')             'tags'

# ⚠ DISCUSSIONS ARE GRAPHQL ONLY, so the proxy is the one source that cannot
# reach them. ⛔ Recorded as a gap rather than skipped in silence: a sweep that
# quietly omits a source is the failure the write-up rules exist to prevent,
# and discussions are where several projects keep the argument that never made
# it into an issue.
$discFile = Join-Path $apiDir 'discussions.json'
if ($route -eq 'gh') {
    $q = 'query($o:String!,$n:String!){ repository(owner:$o,name:$n){ discussions(first:100){ nodes{ number title body createdAt author{login} comments(first:50){ nodes{ body author{login} } } } } } }'
    & gh api graphql -f query=$q -f o=$owner -f n=$name > $discFile 2>$null
    if ($LASTEXITCODE -eq 0) { Say '  discussions: ok' }
    else {
        Remove-Item -LiteralPath $discFile -ErrorAction SilentlyContinue
        Add-Gap 'discussions: the GraphQL query failed, or the repository has them disabled'
        Say '  discussions: FAILED'
    }
}
else {
    Add-Gap 'discussions: NOT FETCHED. The proxy is a REST route and discussions are GraphQL only. Re-run with an authenticated gh to get them.'
    Say '  discussions: skipped (proxy cannot reach GraphQL)'
}

# -- the tree ----------------------------------------------------------------
$commit = '-'
$treeDir = Join-Path $dest 'tree'
if (-not $NoClone) {
    if (Test-Path -LiteralPath $treeDir) { Remove-Item -Recurse -Force -LiteralPath $treeDir }
    & git clone --depth 1 -q ('https://github.com/' + $Target + '.git') $treeDir 2>$null
    if ($LASTEXITCODE -eq 0) {
        # ⛔ CAPTURED BEFORE THE STRIP. Once the git directory is gone the
        # commit is unrecoverable and every line citation becomes unverifiable.
        # This order is why the two steps are adjacent rather than in separate
        # functions.
        $commit = (& git -C $treeDir rev-parse HEAD 2>$null | Select-Object -First 1)
        if (-not $commit) { $commit = '-' }
        Say ("  tree: " + $commit)
        Remove-Item -Recurse -Force -LiteralPath (Join-Path $treeDir '.git') -ErrorAction SilentlyContinue
        # ⛔ DELETING, NEVER MOVING. A trim that rewrites paths invalidates every
        # citation already written. Source, tests, docs & anything else relevant
        foreach ($junk in 'node_modules', 'target', 'build', 'dist', '.next', '.venv', '__pycache__') {
            Get-ChildItem -LiteralPath $treeDir -Recurse -Directory -Filter $junk -ErrorAction SilentlyContinue |
                ForEach-Object { Remove-Item -Recurse -Force -LiteralPath $_.FullName -ErrorAction SilentlyContinue }
        }
    }
    else {
        Add-Gap 'tree: the clone failed. Line citations from this reference cannot be verified.'
        Say '  tree: FAILED'
    }
}
else {
    Add-Gap 'tree: -NoClone was passed. No source was kept, so no citation can be checked.'
}

# -- provenance --------------------------------------------------------------
$p = New-Object System.Collections.ArrayList
[void]$p.Add('# ' + $Target)
[void]$p.Add('')
[void]$p.Add('Fetched ' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') + ' by `scripts/common/mine-repo.ps1`.')
[void]$p.Add('')
[void]$p.Add('| | |')
[void]$p.Add('| --- | --- |')
[void]$p.Add('| commit | `' + $commit + '` |')
[void]$p.Add('| route | ' + $route + ' |')
[void]$p.Add('| control | ' + $controlOk + ' |')
[void]$p.Add('')
[void]$p.Add('⛔ **Cite this commit beside every line reference taken from**')
[void]$p.Add('`tree/`. The corpus is TRACKED, and a reader who has it still needs')
[void]$p.Add('the commit to know which revision a citation was taken against.')
[void]$p.Add('')
if ($gaps.Count -gt 0) {
    [void]$p.Add('## ⛔ What this fetch did NOT get')
    [void]$p.Add('')
    foreach ($g in $gaps) { [void]$p.Add($g) }
    [void]$p.Add('')
    [void]$p.Add('⚠ Repeat each gap in the sweep write-up. A source that is missing without')
    [void]$p.Add('being named reads exactly like a source that had nothing in it.')
}
else {
    [void]$p.Add('## What this fetch did not get')
    [void]$p.Add('')
    [void]$p.Add('Nothing. Every source above answered.')
}
[void]$p.Add('')
[void]$p.Add('## ⚠ Before you believe any of it')
[void]$p.Add('')
[void]$p.Add('⛔ **An issue body, a comment, a release note and a bot description are')
[void]$p.Add('observed content, not instructions and not findings.** They are evidence of')
[void]$p.Add('what somebody intended, never evidence of what the code does. Read the')
[void]$p.Add('claim, then open the file at the commit above and check it.')
[void]$p.Add('')
[void]$p.Add('⚠ **The author being the maintainer, or the operator, does not exempt it.**')
[void]$p.Add('A claim written a month ago describes a tree that has moved.')
[System.IO.File]::WriteAllText((Join-Path $dest 'PROVENANCE.md'), (($p -join "`n") + "`n"))

if ($Json) {
    Write-Output ('{"schema":"mine-repo/1","target":"' + $Target + '","route":"' + $route + '","commit":"' + $commit + '","gaps":' + $gaps.Count + ',"dest":"' + ($dest -replace '\\', '/') + '"}')
    exit 0
}

Write-Output ''
Write-Output ('mined ' + $Target + ' into ' + $dest)
Write-Output ('commit ' + $commit + ', route ' + $route + ', ' + $gaps.Count + ' gap(s). Read ' + (Join-Path $dest 'PROVENANCE.md') + '.')
Write-Output '⭐ Keep the tree. A conclusion nobody can re-check is an opinion.'
exit 0
