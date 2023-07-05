$TextExtension =  @(
# Enhanced Key Usage
'2.5.29.37={text}1.3.6.1.4.1.311.10.3.6,1.3.6.1.5.5.7.3.3',
# Basic Constraints
'2.5.29.19={text}false',
# Subject Alternative Name
'2.5.29.17={text}DirectoryName=SERIALNUMBER="229879+500176",OU=Microsoft Ireland Operations Limited'
)

$params = @{
	Type = 'Custom'
	Subject = 'CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
	TextExtension = $TextExtension
	KeyUsage = 'None'
	KeyAlgorithm = 'RSA'
	KeyLength = 2048
	NotAfter = (Get-Date).AddMonths(999)
	CertStoreLocation = 'Cert:\LocalMachine\My'
}
New-SelfSignedCertificate @params