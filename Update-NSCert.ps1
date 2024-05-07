[CmdLetBinding()]
Param(
	[Parameter(Position=0)][string]$PFXFile,
	[Parameter(Position=1)][string]$PFXPassword,
	[Parameter(Position=2)][string]$NSIP,
	[Parameter(Position=3)][string]$NSUsername,
	[Parameter(Position=4)][string]$NSPassword,
	[Parameter(Position=5)][string]$vServers,
	[Parameter(Position=6)][switch]$SNI,
	[Parameter(Position=7)][switch]$SaveConfig
)
Function Error($Content){Write-Host -f Red $Content;pause;exit}

If (!$PFXFile){
	Add-Type -AN System.Windows.Forms
	Write-Host -f Yellow "PFXFile path not provided. Ask user for PFXFile"
	$OFD = New-Object System.Windows.Forms.OpenFileDialog
	$OFD.filter = "PFX Files (*.pfx)| *.pfx"
	$OFD.ShowDialog() | Out-Null
	$PFXFile = $OFD.FileName
}
If (!$PFXFile){Error "This script can't run without a PFX file and will now quit."}

Add-Type -AN Microsoft.VisualBasic
If (!$PFXPassword){$PFXPassword = [Microsoft.VisualBasic.Interaction]::InputBox('Enter the Password for the PFX File.','PFX password','nsroot')}
If (!$PFXPassword){Error "This script can't run without the PFX Password and will now quit"}
foreach ($char in $PFXPassword.ToCharArray()) {if ($char -notmatch '[0-9a-zA-Z]' -and $char -notin ' ', '"', "'", '`', '*') {Error "Password can't contain special characters like: $char"}}

try {	$PFX = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
	$PFX.Import($PFXFile, $PFXPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
}
catch {Error "Incorrect password for PFX File. Script will now quit."}
$FCN = [regex]::Escape(($PFX.SubjectName.Name).Split(",")[0])
$CN = ($PFX.SubjectName.Name).Split("=")[1].Split(",")[0]
$CertName = $CN.replace('*','wildcard')
$Cert = $CN.replace('*.','')

$LogFile = "$PSScriptRoot\$CertName.log"
sc $LogFile "$(Get-Date -U '%a %d-%m-%G %X') - Started Certificate replacement for $CN"
Function Log($Content){Write-Host -f Green $content;"$(Get-Date -U '%a %d-%m-%G %X') - $content" | Out-File $LogFile -Append -Enc ASCII}

If (!$NSIP -and !$NSUsername -and !$NSPassword -and !$SaveConfig){$NoNSParameters=$true}Else{$NoNSParameters=$false}

If (!$NSIP){$NSIP = [Microsoft.VisualBasic.Interaction]::InputBox('Enter the NetScaler IP address or DNS name','NSIP','dc1-vpx00.kiwa.intranet')}
Log "NSIP = $NSIP"

If (!$NSUsername){$NSUsername = [Microsoft.VisualBasic.Interaction]::InputBox('Enter the NetScaler username','username','nsroot')}
Log "NSUsername = $NSUsername"

If (!$NSPassword){$NSPassword = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the password for $nsroot",'password','nsr00t')}
Log "NSPassword = $NSPassword"

If ($vServers){Log "vServers = $vServers"}

If (!$SaveConfig -and $NoNSParameters) {If ([Microsoft.VisualBasic.Interaction]::MsgBox('Save Configuration?',68,'Save Configuration?') -eq '6'){$SaveConfig=$true}Else{$SaveConfig=$false}}

If (!(gv SNI -EA 0) -and $NoNSParameters) {If ([Microsoft.VisualBasic.Interaction]::MsgBox('Turn on SNI?',68,'SNI?') -eq '6'){$SNI=$true}Else{$SNI=$false}}

If (!$PFXFile -or !$PFXPassword -or !$NSIP -or !$NSUsername -or !$NSPassword){Error "One or more parameters is empty. Script will now quit"}

Log "Ignore Cert Errors and set TLS1.2 for NetScaler Access"
[System.Net.ServicePointManager]::CheckCertificateRevocationList={$false}
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
If ((get-host).version.Major -gt 5) {Log "Set Extra Parameters in Powershell 6 and above";$params=@{SkipCertificateCheck=$true;ContentType="application/json"}} else {$params=@{ContentType="application/json"}}

Log "Login to NetScaler"
#$params=@{ContentType="application/json"}
$Login = irm "https://$NSIP/nitro/v1/config/login" -Method POST -Body (ConvertTo-JSON @{"login"=@{"username"="$NSusername";"password"="$NSpassword";"timeout"="900"}}) -SessionVariable NSSession @params
$params.Add("WebSession",$NSSession)

Log "Get All Certificates from NetScaler"
$AllCerts = irm "https://$NSIP/nitro/v1/config/sslcertkey" @params

Log "Select Certificate"
$NSCert = $AllCerts.sslcertkey | ? subject -match $FCN

If (!$NSCert){Log "Certificate not found"}Else{
	If ($NSCert.count -gt 1){$NSCert = $NSCert | ogv -Title "Select the certificate you want to replace" -Outputmode Single}
	Log "Get Certificate vServer bindings"
	$BoundvServers = (irm "https://$NSIP/nitro/v1/config/sslcertkey_binding/$($NSCert.certkey)" @params -EA 0).sslcertkey_binding.sslcertkey_sslvserver_binding.servername

	If (!$BoundvServers){Log "No Certificate vServer bindings found. Will ask user to select vServers"} Else {
		Log "Found Certificate vServer bindings: "
		$VSBindings = @()
		$BoundvServers | % {
			If ($_ -ne '-DtlsTurn'){
				$Q = irm "https://$NSIP/nitro/v1/config/sslvserver_sslcertkey_binding/$_" @params
				$VSBindings += ($Q.sslvserver_sslcertkey_binding)
			}
		}

		If ($VSBindings){
			$VSBindings | % {
				Log ("vServerName: " + $_.vservername + "; CertkeyName: " + $_.certkeyname + "; SNI: " + $_.snicert + "; CA: " + $_.ca)
				If ($_.certkeyname -match $Cert){
					Log ("Unbinding: " + $_.certkeyname + " from vServer: " + $_.vservername)
					$ca = $($_.ca).ToString().ToLower()
					$snicert = $($_.snicert).ToString().ToLower()
					$UnbindCert = irm "https://$NSIP/nitro/v1/config/sslvserver_sslcertkey_binding/$($_.vservername)?args=certkeyname:$($_.certkeyname),ca:$ca,snicert:$snicert" -Method DELETE @params
				}
			}
		}
	}

	Log "Get Certificate Service Bindings"
	$BoundServices = (irm "https://$NSIP/nitro/v1/config/sslcertkey_service_binding/$($NSCert.certkey)" @params).sslcertkey_service_binding.servicename

	If ($BoundServices.count -eq 0){
		Log "No Certificate Service bindings found"
	} Else {
		Log "Found Certificate Service bindings: "
		$ServiceBindings = @()
		$BoundServices | % {
			$R = irm "https://$NSIP/nitro/v1/config/sslservice_sslcertkey_binding/$_" @params
			$ServiceBindings += ($R.sslservice_sslcertkey_binding)
		}
	
		If ($ServiceBindings){
			$ServiceBindings | % {
				Log ("Service: " + $_.servicename + "; certkeyname: " + $_.certkeyname + "; SNI: " + $_.snicert)
				If ($_.certkeyname -match $Cert){
					Log ("Unbinding: " + $_.certkeyname + " from Service: " + $_.servicename)
					$ca = $($_.ca).ToString().ToLower()
					$snicert = $($_.snicert).ToString().ToLower()
					$UnbindCert = irm "https://$NSIP/nitro/v1/config/sslservice_sslcertkey_binding/$($_.servicename)?args=certkeyname:$($_.certkeyname),ca:$ca,snicert:$snicert" -Method DELETE @params
				}
			}
		}
	}

	Log "Remove old Certificate $($NSCert.certkey) from configuration"
	$CertDel = irm "https://$NSIP/nitro/v1/config/sslcertkey/$($NSCert.certkey)" -Method DELETE @params

	Log "Remove old Certificate $($NSCert.cert) from filesystem"
	$DelPFX = irm ("https://$NSIP/nitro/v1/config/systemfile/$($NSCert.cert)?args=filelocation:"+[System.Web.HttpUtility]::UrlEncode("/nsconfig/ssl")) -Method DELETE @params
	If ($NSCert.cert -ne $NSCert.key){
		Log "Remove old key $($NSCert.key) from filesystem"
		$DelKey = irm ("https://$NSIP/nitro/v1/config/systemfile/$($NSCert.key)?args=filelocation:"+[System.Web.HttpUtility]::UrlEncode("/nsconfig/ssl")) -Method DELETE @params
	}
	If ($NSCert.cert -eq $NSCert.key){
		$OldPFX = $NSCert.cert.replace('.key','.pfx')
		Log "Remove old pfx $OldPFX from filesystem (this might give an error that the file does not exist)"
		$DelPFX = irm ("https://$NSIP/nitro/v1/config/systemfile/$($OldPFX)?args=filelocation:"+[System.Web.HttpUtility]::UrlEncode("/nsconfig/ssl")) -Method DELETE @params
	}
}

Log "Convert PFX to base64 and upload"
$CertBase64 = [System.Convert]::ToBase64String($(Get-Content $PFXFile -Encoding Byte))
$CertUpload = irm "https://$NSIP/nitro/v1/config/systemfile?action=add" -Method POST -Body (ConvertTo-Json @{"systemfile"=@{filename="$CertName.pfx";filecontent=$CertBase64;filelocation="/nsconfig/ssl/";fileencoding="BASE64"}}) @params

Log "Install Certificate"
$CertInstall = irm "https://$NSIP/nitro/v1/config/sslcertkey" -Method POST -Body (ConvertTo-Json @{"sslcertkey"=@{"certkey"="CERT_$Cert";"cert"="$CertName.pfx";"passplain"="$PFXPassword"}}) @params

Log "Get All New Certificates from NetScaler"
$AllCerts = irm "https://$NSIP/nitro/v1/config/sslcertkey" @params

Log "Select Certificate"
$NSCert = $AllCerts.sslcertkey | ? subject -match $FCN

Log "Link Certificate to Root"
$RootCert = ($AllCerts.sslcertkey | ? subject -match $NSCert.issuer).certkey
$CertLink = irm "https://$NSIP/nitro/v1/config/sslcertkey?action=link" -Method POST -Body (ConvertTo-Json @{"sslcertkey"=@{"certkey"="CERT_$Cert";"linkcertkeyname"="$RootCert"}}) @params

If ($vServers){
	Log "vServers provided, binding them to given vServers"
	$SNI
	$vServers | % {$BindCert = irm "https://$NSIP/nitro/v1/config/sslvserver_sslcertkey_binding" -Method PUT -Body (ConvertTo-Json @{"sslvserver_sslcertkey_binding"=@{"vservername"=$_;"certkeyname"=$NSCert.certkey;"ca"="false";"snicert"=$SNI}}) @params}
} Else {
	If ($BoundvServers){
		Log "Bind Certificate to vServers"
		$VSBindings | % {
			If ($_.certkeyname -match $Cert){
				Log ("Binding: " + $_.certkeyname + " to vserver: " + $_.vservername)
				$ca = $($_.ca).ToString().ToLower()
				$snicert = $($_.snicert).ToString().ToLower()
				$BindCert = irm "https://$NSIP/nitro/v1/config/sslvserver_sslcertkey_binding" -Method PUT -Body (ConvertTo-Json @{"sslvserver_sslcertkey_binding"=@{"vservername"=$_.vservername;"certkeyname"=$_.certkeyname;"ca"=$ca;"snicert"=$snicert}}) @params
			}
		}
	} Else {
		Log "No Certificate vServer bindings found. Will ask user to select vServers"
		$vServers = irm "https://$NSIP/nitro/v1/config/sslvserver" @params
		$vServers.sslvserver
		$SelectedvServers = $vServers.sslvserver.vservername | ogv -Title "Select the vServers that you want to bind the certificate to WITHOUT SNI" -OutputMode Multiple
		$SelectedvServers | % {$BindCert = irm "https://$NSIP/nitro/v1/config/sslvserver_sslcertkey_binding" -Method PUT -Body (ConvertTo-Json @{"sslvserver_sslcertkey_binding"=@{"vservername"=$_;"certkeyname"=$NSCert.certkey;"ca"="false";"snicert"="false"}}) @params}
		$SelectedvServersSNI = $vServers.sslvserver.vservername | ogv -Title "Select the vServers that you want to bind the certificate to WITH SNI" -OutputMode Multiple
		$SelectedvServersSNI | % {$BindCertSNI = irm "https://$NSIP/nitro/v1/config/sslvserver_sslcertkey_binding" -Method PUT -Body (ConvertTo-Json @{"sslvserver_sslcertkey_binding"=@{"vservername"=$_;"certkeyname"=$NSCert.certkey;"ca"="false";"snicert"="true"}}) @params}
	}
}

If ($ServiceBindings){
	Log "Bind Certificate to Services"
	$ServiceBindings | % {
		If ($_.certkeyname -match $CertName){
			Log ("Binding: " + $_.certkeyname + " to service: " + $_.servicename)
			$ca = $($_.ca).ToString().ToLower()
			$snicert = $($_.snicert).ToString().ToLower()
			$BindCert = irm "https://$NSIP/nitro/v1/config/sslservice_sslcertkey_binding" -Method PUT -Body (ConvertTo-Json @{"sslservice_sslcertkey_binding"=@{"servicename"=$_.servicename;"certkeyname"=$_.certkeyname;"ca"=$ca;"snicert"=$snicert}}) @params
		}
	}
}

If ($SaveConfig){Log "Save Configuration";$Save = irm "https://$NSIP/nitro/v1/config/nsconfig?action=save" -Method POST -Body (ConvertTo-Json @{"nsconfig"=@{}}) @params}

Log "Logout"
$Logout = irm "https://$NSIP/nitro/v1/config/logout" -Method POST -Body (ConvertTo-JSON @{"logout"=@{}}) @params

##### Finished #####
Log "Certificate is replaced, please confirm everything is working correctly"

pause