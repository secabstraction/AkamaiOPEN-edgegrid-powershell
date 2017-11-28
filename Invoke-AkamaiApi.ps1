function Invoke-AkamaiApi {
    param (
        [Microsoft.PowerShell.Commands.WebRequestMethod]
        ${Method} = [Microsoft.PowerShell.Commands.WebRequestMethod]::Get,

        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        ${Credential},

        [Parameter(Mandatory=$true)]
        [string]
        ${AccessToken},

        [Parameter(Mandatory=$true)]
        [uri]
        ${Uri},

        [string]
        ${Body},

        [switch]
        ${Recurse}
    )

    function New-HMAC {
        param (
            [string]
            $secret, 
            
            [string]
            $message
        ) 
        $KeyBytes = [System.Text.Encoding]::ASCII.GetBytes($secret)
        $MessageBytes = [System.Text.Encoding]::ASCII.GetBytes($message)
        $HMAC = New-Object 'System.Security.Cryptography.HMACSHA256' -ArgumentList @(,$KeyBytes)
        $MessageHash = $HMAC.ComputeHash($messageBytes)
        [Convert]::ToBase64String($MessageHash)
    }

    #Uri Verification
    if ($Uri -notmatch 'akamaiapis\.net') { throw 'Ivalid Request URI' }

    $Parameters = @{ Method = $Method; Uri = $Uri; ContentType = 'application/json' }

    #Split $Uri for inclusion in SignatureData
    $ReqArray = $Uri -split "(.*\/{2})(.*?)(\/)(.*)"

    #Timestamp for request signing
    $TimeStamp = [DateTime]::UtcNow.ToString('yyyyMMddTHH:mm:sszz00')

    #GUID for request signing
    $Guid = [guid]::NewGuid()

    #Build data string for signature generation
    $SignatureData = "{0}`thttps`t{1}`t{2}{3}" -f $Method.ToString().ToUpper(), $ReqArray[2], $ReqArray[3], $ReqArray[4]

    if ($Body) {
        $SHA256 = [System.Security.Cryptography.SHA256]::Create()
        $BodyHash = [System.Convert]::ToBase64String($SHA256.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($Body.ToString())))

        $SignatureData = "{0}`t`t{1}`t" -f $SignatureData, $BodyHash
    } else { $SignatureData = "{0}`t`t`t" -f $SignatureData }

    $NetCredential = $Credential.GetNetworkCredential()
    
    $AuthHeader = 'EG1-HMAC-SHA256 client_token={0};access_token={1};timestamp={2};nonce={3};' -f $NetCredential.UserName, $AccessToken, $TimeStamp, $Guid

    $SignatureData = '{0}{1}' -f $SignatureData, $AuthHeader

    #Generate SigningKey
    $SigningKey = New-HMAC -secret $NetCredential.Password -message $TimeStamp

    #Generate Auth Signature
    $Signature = New-HMAC -secret $SigningKey -message $SignatureData

    #Create AuthHeader
    $Headers = @{ Authorization = '{0}signature={1}' -f $AuthHeader, $Signature }

    if ($Body) {
        $BodySize = [System.Text.Encoding]::UTF8.GetByteCount($Body)
        $Headers['max-body'] = $BodySize.ToString()

        # turn off the "Expect: 100 Continue" header, as it's not supported on the Akamai side.
        [System.Net.ServicePointManager]::Expect100Continue = $false
        $Parameters['Body'] = $Body
    }

    $Parameters['Headers'] = $Headers
    try { 
        foreach ($Response in (Invoke-RestMethod @Parameters)) {
            Write-Output $Response
            if ($Recurse.IsPresent) {
                foreach ($Link in $Response.links) {
                    if ($Link.rel -eq 'next') {
                        $PSBoundParameters['Uri'] = '{0}://{1}{2}' -f $Uri.Scheme, $Uri.Host, $Link.href
                        Invoke-AkamaiApi @PSBoundParameters
                    }
                }
            }
        }
    } catch { throw }
}