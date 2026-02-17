param(
  [string]$OutCsv = ".\DisabledUsersWithExtraGroups.csv"
)

if ($PSVersionTable.PSVersion.Major -ge 7) {
  Import-Module ActiveDirectory -UseWindowsPowerShell -ErrorAction Stop
} else {
  Import-Module ActiveDirectory -ErrorAction Stop
}

$OutCsv = [IO.Path]::GetFullPath($OutCsv)
$base = [IO.Path]::Combine([IO.Path]::GetDirectoryName($OutCsv), [IO.Path]::GetFileNameWithoutExtension($OutCsv))
$ErrLog = $base + "_errors.log"
if (Test-Path -LiteralPath $ErrLog) { Remove-Item -LiteralPath $ErrLog -Force -ErrorAction SilentlyContinue }

$domain = Get-ADDomain
$pdc = $domain.PDCEmulator
$domain = Get-ADDomain -Server $pdc

$domainUsersSid = "$($domain.DomainSID.Value)-513"
$domainUsersRid = 513

function CsvEscape([object]$v) {
  if ($null -eq $v) { return '""' }
  '"' + ([string]$v -replace '"','""') + '"'
}

$encBom = New-Object System.Text.UTF8Encoding($true)
$sw = $null

try {
  $sw = New-Object System.IO.StreamWriter($OutCsv, $false, $encBom)
  $sw.AutoFlush = $true
  $sw.WriteLine("SamAccountName,Name,UserPrincipalName,DistinguishedName,DisabledDate,GroupCount,GroupName,GroupSID,GroupDN")

  $users = Get-ADUser -Server $pdc `
    -LDAPFilter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" `
    -Properties SamAccountName,Name,UserPrincipalName,DistinguishedName,whenChanged,memberOf,primaryGroupID `
    -ResultPageSize 2000 -ResultSetSize $null

  $total = $users.Count

  for ($i = 0; $i -lt $total; $i++) {
    $u = $users[$i]

    if (($i % 250) -eq 0 -or $i -eq ($total - 1)) {
      $pct = if ($total) { [int](($i + 1) * 100 / $total) } else { 100 }
      Write-Progress -Activity "Checking disabled AD users" -Status "$($i+1)/$total" -PercentComplete $pct
    }

    if ($u.primaryGroupID -eq $domainUsersRid -and ($null -eq $u.memberOf -or $u.memberOf.Count -eq 0)) { continue }

    try {
      $groups = Get-ADPrincipalGroupMembership -Server $pdc -Identity $u.DistinguishedName -ErrorAction Stop
    } catch {
      Add-Content -Path $ErrLog -Value ("{0}`t{1}`t{2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $u.SamAccountName, $_.Exception.Message)
      continue
    }

    if (-not $groups) { continue }

    $extra = New-Object System.Collections.Generic.List[object]
    foreach ($g in $groups) {
      if ($g.SID.Value -ne $domainUsersSid) { $extra.Add($g) }
    }
    if ($extra.Count -eq 0) { continue }

    $disableDt = $null
    try {
      $m = Get-ADReplicationAttributeMetadata -Server $pdc -Object $u.DistinguishedName -Properties userAccountControl -ErrorAction Stop
      $disableDt = ($m | Select-Object -First 1).LastOriginatingChangeTime
    } catch {
      $disableDt = $u.whenChanged
    }
    $disabledStr = if ($disableDt) { ([datetime]$disableDt).ToString("yyyy-MM-dd HH:mm:ss") } else { "" }

    $sam = CsvEscape $u.SamAccountName
    $nm  = CsvEscape $u.Name
    $upn = CsvEscape $u.UserPrincipalName
    $udn = CsvEscape $u.DistinguishedName
    $dd  = CsvEscape $disabledStr
    $gc  = CsvEscape $extra.Count

    foreach ($g in $extra) {
      $sw.WriteLine((
        $sam + "," + $nm + "," + $upn + "," + $udn + "," + $dd + "," + $gc + "," +
        (CsvEscape $g.Name) + "," + (CsvEscape $g.SID.Value) + "," + (CsvEscape $g.DistinguishedName)
      ))
    }
  }

  Write-Progress -Activity "Checking disabled AD users" -Completed
}
finally {
  if ($sw) { $sw.Flush(); $sw.Close(); $sw.Dispose() }
}

Write-Host ("CSV:    {0}" -f $OutCsv)
if (Test-Path -LiteralPath $ErrLog) { Write-Host ("Errors: {0}" -f $ErrLog) }
