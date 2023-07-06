$cabPath = $args[0]
$certRegPath = "HKLM:\Software\Microsoft\SystemCertificates\ROOT\Certificates"

$cert = (Get-AuthenticodeSignature $cabPath).SignerCertificate
$certPath = [System.IO.Path]::GetTempFileName()
[System.IO.File]::WriteAllBytes($certPath, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
Import-Certificate $certPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
Copy-Item -Path "$certRegPath\$($cert.Thumbprint)" "$certRegPath\8A334AA8052DD244A647306A76B8178FA215F344" -Force  | Out-Null
Add-WindowsPackage -Online -PackagePath $cabPath
Get-ChildItem "Cert:\LocalMachine\Root\$($cert.Thumbprint)" | Remove-Item
Remove-Item "$certRegPath\8A334AA8052DD244A647306A76B8178FA215F344" -Force | Out-Null