#Isn't the best script on the planet, but it gets the job done for what I need it to do.
#Most of this is REST, but there is a part using POSH-SSH because I need to figure out how to do a factory reset with the REST API.

$fortigate_ip = "192.168.1.99"

$fortigate_user = "admin"

$fortigate_password = ""

$uri = "https://$fortigate_ip"

$script:Session = ""

#CMDB API is used to retrieve and modify CLI configurations.  
#Example: create/edit/delete firewall policy.
$cmdbpath = "/api/v2/cmdb"
#Monitor API is used to perform specific actions on endpoint resources.  
#Examples:retrieve/close firewall sessions, restart/shutdown Fortigate, backup/restore config file.
$monitorpath = "/api/v2/monitor"
#$path = "C:/Users/SomeUsers/Desktop"

#File holding base64 encoded firmware for firemware upload.
$firmwarebase64 = Get-Content "\\SomeFileShare\Fortinet\FGT60E\5.4.7\5.4.7firmware.txt" -Raw

#Notes that may be helpful learning the REST API
#Cross-Site Request Forgery (CSRF) tokens are required for write requests.  
#This token is available in the session cookie named ccsrftoken - which is included in the request header under X-CSRFTOKEN.

#shows requests to the FortiOS web interface in addition to the REST API requests.
#diagnose debug enable
#diagnose debug application https -1

#Changed it to Invoke-RestMethod because this tends to handle json better than Invoke-WebRequest 
#Invoke-RestMethod turns the responses into objects instead of strings.  Easier to manipulate in Powershell

#If it can't verify the SSL certificate, it throws an error message.  Disabling this validation check seems to fix it.

function Disable-SSLVerification(){

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

}

function Enable-SSLVerification(){

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$null}

}

#This fixes an error with an SSL protocol mismatch.

[System.Net.ServicePointManager]::Expect100Continue = {$true}
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

#Get a session on the Fortigate.

function Get-SessionFortiGate ($fortigate_user, $fortigate_password, $uri){

	    $url = "/logincheck"

		$body = @{

				username=$fortigate_user

				secretkey=$fortigate_password

				ajax=1

		}
		
		$response = Invoke-WebRequest -Method Post -ContentType "application/json" -Uri $uri$url -Body $body -SessionVariable fgtSession
		$content = $response.Content

		#The documentation states that only reading the first character of the response data is necessary for determining login failure or success. FortiOS-5.6.5-Rest_API_Reference.pdf page 8.
		if($content -match "1"){
			Write-Host "You have successfully logged in."
		}
		elseif($content -match "2"){
			Write-Host "$fortigate_user has been locked out."
		}
		elseif($content -match "3"){
			Write-Host "Two-Factor Authentication is needed."
		}
		elseif($content -match "0"){
			Write-Host "Login failure.  Most likely an incorrect username/password combo."
		}
		else{
			Write-Host "I have no idea what the issue is."
		}
        $script:Session = $fgtSession
        if($script:Session -ne ""){
            $cookies = $script:Session.Cookies.GetCookies($uri)
	        #Checking cookies to see what the values are.
            #ForEach($cookie in $cookies){
                #Write-Host "$($cookie.name) = $($cookie.value)"
            #}
	        #apstoken is the name in the first element of the $cookies array.
            $script:apstoken = $cookies[0].Name
	        #apstokenvalue is the value in the first element of the $cookies array.
            $script:apstokenvalue = $cookies[0].Value
	        #ccsrftoken is the value in the third element of the $cookies array. (Computers count from 0 up)
            $script:ccsrftoken = [String]$cookies[2].Value
	        #Get rid of the damn quotes in the ccsrf token - otherwise it doesn't accept the token.
            $script:ccsrftoken = $script:ccsrftoken.Replace('"','')
	        #Populate the session Headers with the X-CSRFTOKEN header and the csrftoken.
            $script:Session.Headers.Add('X-CSRFTOKEN',$script:ccsrftoken)
            $script:Session.Headers.Add('Accept','application/json')
        }
        else{
            Write-Host "Could not establish a session with the Fortigate Rest API." -ForegroundColor Red
            Read-Host -Promt "Please Stop and Restart the script.  The firmware downgrade must be done before proceeding."
        }
}

#Send get requests
function Get-Request ($url){
    try{
    #ErrorAction SilentlyContinue is not a great name for this. If there are certain types of errors - it throws an ugly red error message.
    #So, to get it not to have a block of ugly red for some errors - have to have a try/catch statement and change the ErrorAction.
    $request = Invoke-RestMethod -URI "$uri$url" -ContentType "application/json" -WebSession $script:Session -Method GET -ErrorAction SilentlyContinue
    }
    catch{

    }
    return $request
}

#Send post, put, or delete requests
function Send-Request ($method, $url, $body){
    try{
        $request = Invoke-RestMethod -URI "$uri$url" -ContentType "application/json" -WebSession $script:Session -Method $method -Body $body -ErrorAction SilentlyContinue
    }
    catch{

    }

    return $request
}

#Removes the session when we're finished configuring the Fortigate the way we need to.
function Remove-SessionFortiGate {

    $url = "/logout"

    $request = Invoke-RestMethod -Method Post -ContentType "application/json" -Uri $uri$url -WebSession $script:Session
}

#Retrieve a list of firmware images available to use to upgrade the Fortigate.
function Select-Firmware {

	$url = "$monitorpath/system/firmware/"

    Get-Request $url

}

#Upgrade the Fortigate by using a base64 encoded file.
function Upgrade-Firmwarebase64 {

    $url = "$monitorpath/system/firmware/upgrade/"

    $body = @{
            source = "upload"
            file_content = $firmwarebase64.trim().Replace('[",\s]','')
            format_partition = "true"
    } | ConvertTo-Json

    $method = "post"
    Disable-SSLVerification
    $request = Send-Request $method $url $body
    $firmwarestatus = ""
    $firmwarestatus = $request.results.status
    #The firewall sends back a status that it got the firmware change request - doesn't mean it will actually do it.  This is the best we can do for now.
    #Hence the reason for the version check.
    $request
    if($firmwarestatus -eq "success"){
        Write-Host "The firmware change request has been received by the firewall." -ForegroundColor Green
    }
    #$request = Invoke-WebRequest -URI "$uri$monitorpath$url" -ContentType "application/json" -WebSession $script:Session -Method POST -Body $body
    #$request
}

#This reboots the Fortigate.
function Reboot-Firewall {

    $url = "$monitorpath/system/os/reboot"

    #running this will cause an error - because the firewall shuts down before the script expects it to.  The firewall does reboot though.

    $request = Invoke-RestMethod -URI "$uri$url" -ContentType "application/json" -WebSession $script:Session -Method POST
    $request
}

#This shuts down the Fortigate
function Shutdown-Firewall {

    #running this will cause an error - because the firewall shuts down before the script expects it to.  The firewall does shutdown though.

    $url = "$monitorpath/system/os/shutdown"

    $request = Invoke-RestMethod -URI "$uri$url" -ContentType "application/json" -WebSession $script:Session -Method POST
    $request

}

#Get the version of FortiOS running on the firewall
function Check-Version {
   
   $current_firmware_version = ""
   Write-Host "Checking the firmware version..." -ForegroundColor Cyan
   $current_firmware_version = (Select-Firmware).results.current.version.trim().replace('v','')
   Write-Host "The version is $current_firmware_version."
   return $current_firmware_version

}

#This function checks to see if port 443 is running and available.
function checkPort($port) {
    try {
        new-object System.Net.Sockets.TcpClient($script:fortigate_ip, $port)
        $status = $true
    }
    catch {
        $status = $false
    }
    return $status
}

# This functions checks for the firewall to be online on 443.
function Wait-Reboot ($port) {
    Write-Host "Waiting on system to come back online..." -ForegroundColor Cyan
    Do {
        Sleep -Seconds 2
    } Until ( (checkPort $port) -eq $true)

    Write-Host "Fortinet port $port back online... waiting 2 seconds" -ForegroundColor Cyan

    Sleep -Seconds 5

}

function Factory-Reset{
# Factory reset to fix issues with jumping firmware version
    if(($script:computer -eq "192.168.1.99") -and ($script:password -eq "")){
        $credential = New-Object System.Management.Automation.PSCredential ($script:username, (new-object System.Security.SecureString))
    } else {
        $script:password = $script:password | ConvertTo-SecureString -asPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential ($script:username, $script:password)
    }
    Remove-SSHTrustedHost -SSHHost $script:computer -WarningAction SilentlyContinue
    if($session = New-SSHSession -AcceptKey:$true -ComputerName $script:computer -Credential $credential){
		Write-Host "Performing factory reset..." -ForegroundColor Cyan
		$SSHStream = New-SSHShellStream -SSHSession $session
		Invoke-SSHStreamExpectAction -ShellStream $SSHStream -Command "execute factoryreset" -ExpectString "Do you want to continue" -Action "y" -Verbose
			# Wait for SSH session to close
			while(Get-SSHSession | Where-Object {$_.Connected -eq $true}){
					Sleep -Seconds 1
			}
		# Cleanup session
		$SSHStream.Close()
		removeSSHSessions
		Write-Host "Reboot initiated" -ForegroundColor Cyan
		Wait-Reboot "22"
        Remove-SSHTrustedHost -SSHHost $script:computer -WarningAction SilentlyContinue
	}
	#Remove SSH Key between upgrades because it will be changed.
	Remove-SSHTrustedHost -SSHHost $script:computer -WarningAction SilentlyContinue
}

function Sanity-Check{

    #Give the firewall time to power down and back on before testing to see if it's back online and trying to log into it again.
	#If this is not done, it may try to get a session with it before it even has a chance to power down to update the firmware.
        Sleep -Seconds 10
	
        #Wait until the firewall reboots before getting a session.
        Wait-Reboot "443"
    $script:Session = ""
	#Get a session on the firewall.
        Disable-SSLVerification
        Get-SessionFortiGate $fortigate_user $fortigate_password $uri
    if($script:Session){
	    #Make sure that there isn't anything in the $current_firmware_version variable from before.
	    $current_firmware_version = ""
	
	    #Check the firmware version to make sure it upgraded.
            [String]$current_firmware_version = Check-Version
	
	    #Show the current firmware.
            Write-Host "The firmware is now $current_firmware_version."
	
	    #Check to see if the firmware upgrade was successful.
            if([version]$upgrade_firmware_version -ne [version]$current_firmware_version){

                Write-Host "For some reason, this device wasn't upgraded.  I'm in a loop right now.  I will keep running until I can upgrade the firewall." -ForegroundColor Magenta
                Write-Host "Now would probably be a good time to make sure that the device is powered on and the network is properly configured." -ForegroundColor Magenta 
            }

            #Remove-SessionFortiGate
            else{
	
                Write-Host "Looks like the version is the correct version." -ForegroundColor Green
                Remove-SessionFortiGate
	    
            }
            return $current_firmware_version
    }
    else{
        Write-Host "For some reason, I couldn't connect to the Fortigate." -ForegroundColor Red
    }       
}

#Disable SSLVerification for the reason mentioned above.
Disable-SSLVerification

#Get a session on the Fortigate.

Get-SessionFortiGate $fortigate_user $fortigate_password $uri

#If is a session, execute the following commands.
if($script:Session){

    #Would really prefer converting these to integers and comparing ints because comparing strings can have weird results.
    $upgrade_firmware_version = "5.4.7"
    
    #Making sure that I'm getting a string so I can compare like types String to String.
    [String]$current_firmware_version = Check-Version
    
    #if the upgrade_firmware_version does not match the firmware version on the firewall, do the following...
    if([version]$upgrade_firmware_version -ne [version]$current_firmware_version){
    Do{
            Write-Host "Changing the firmware version to $upgrade_firmware_version..." -ForegroundColor Cyan
	
	        #Upgrade the firmware using a base64 encoded file.
            Upgrade-Firmwarebase64

            $current_firmware_version = Sanity-Check
    }Until ($current_firmware_version -eq $upgrade_firmware_version)
        Write-Host "Performing factory reset to handle errors..." -ForegroundColor Cyan
        Factory-Reset
        Write-Host "Might see an error pop up after the factory reset because the IP changes, and the other connection isn't gracefully torn down.  This is normal." -ForegroundColor Cyan
        #Give the firewall time to power down and back on before testing to see if it's back online and trying to log into it again.
	    #If this is not done, it may try to get a session with it before it even has a chance to power down to factory reset the firmware.
        #Sleep -Seconds 8
	
        #Wait until the firewall reboots before continuing with the script.
        #Wait-Reboot "443"
    }
    else{
    
            Write-Host "Looks like the version is the correct version." -ForegroundColor Green
            Remove-SessionFortiGate
	    
    }

   Remove-SessionFortiGate 
}
#If there is not a session, say that a session couldn't be established with the Fortigate.
else{

    Write-Host "Could not establish a session with $fortigate_ip"
    
}
