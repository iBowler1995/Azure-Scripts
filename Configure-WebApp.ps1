[CmdletBinding()]
param (
    [Parameter(Mandatory = $True)]
    [String]$AppName,
    [Parameter(Mandatory = $True)]
    [String]$Environment,
    [Parameter(Mandatory = $True)]
    [ValidateSet('Yes','No')]
    [Parameter(Mandatory = $True)]
    [ValidateSet('App1','App2','App3')]
    [String]$AppType,
    [Parameter()]
    [ValidateSet('v6.0','v7.0','v8.0')]
    [String]$NetVersion,
    [Parameter()]
    [Switch]$Slot
)

#REQUIRED MOUDLES: Az.Accounts, Az.Resources, Az.Websites

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

Function Configure-ApplicationInsights {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$InstrumentationKey,
        [Parameter(Mandatory = $True)]
        [String]$App
    )
        
    Try {

        Write-Host "Configuring Application Insights..." -ForegroundColor Cyan
        $Application = Get-AzWebapp -Name $App
        $newAppSettings = @{}
        foreach ($setting in $Application.SiteConfig.AppSettings) {
            $newAppSettings[$setting.Name] = $setting.Value
        }
            
        #Add the new settings to the hashtable
        $newAppSettings["APPINSIGHTS_INSTRUMENTATIONKEY"] = $InstrumentationKey
        $newAppSettings["APPLICATIONINSIGHTS_CONNECTION_STRING"] = "InstrumentationKey=$InstrumentationKey"
        $newAppSettings["ApplicationInsightsAgent_EXTENSION_VERSION"] = "~2"
            
        #Update the web app with the new settings
        Set-AzWebApp -AppSettings $newAppSettings -ResourceGroupName $Application.ResourceGroup -Name $Application.Name -ErrorAction Stop | Out-Null
        Write-Host "Application Insights Configured!" -ForegroundColor Green
        Write-Host "================"
            

    }
    catch {

        Write-Error "Error configuring Application Insights at line $($_.InvocationInfo.ScriptLineNumber): $_"

    }

}

Function Check-Container{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$StorageAccount,
        [Parameter(Mandatory = $True)]
        [String]$ResourceGroup,
        [Parameter(Mandatory = $true)]
        [String]$App
    )

    Write-Host "Checking for storage container..." -ForegroundColor Cyan
    Try {

        Set-AzCurrentStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageAccount | Out-Null
        $ContainerExists = Get-AzStorageContainer -Name $App -ErrorAction SilentlyContinue
        If ($null -eq $ContainerExists) {
                            
            #Creating Storage container
            $SA = Get-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageAccount   
            $ctx = $SA.Context
            New-AzStorageContainer -Name $App -Context $ctx -Permission Off | Out-Null
            return $ctx

        }
        else {

            Write-Host "Container already exists. Continuing to next step." -ForegroundColor Yellow
            $SA = Get-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageAccount   
            $ctx = $SA.Context
            return $ctx

        }
                        
    }
    catch {

        Write-Error "Error checking or creating storage container at line $($_.InvocationInfo.ScriptLineNumber): $_"

    }

}
Function Configure-Backups{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$App,
        [Parameter(Mandatory = $True)]
        [Microsoft.WindowsAzure.Commands.Common.Storage.LazyAzureStorageContext]$Context
    )

    Try {

        Write-Host "Configuring backup schedule..." -ForegroundColor Cyan
        $AzApp = Get-Azwebapp -Name $App
        $sasURL = New-AzStorageContainerSASToken -Name $Azapp.Name -Permission rwdl -Context $Context -ExpiryTime (Get-Date).AddYears(1) -FullUri
        Edit-AzWebAppBackupConfiguration -ResourceGroupName $AzApp.ResourceGroup -Name $Azapp.Name -StorageAccountUrl $sasURL.ToString() -FrequencyInterval 1 -FrequencyUnit Day -KeepAtLeastOneBackup -StartTime (Get-Date).AddHours(1) -RetentionPeriodInDays 60 -Enabled | Out-Null
        Write-Host "Backup schedule configured!" -ForegroundColor Green
        Write-Host "================"
        return $sasURL

    }
    catch {

        Write-Error "Error configuring backup schedule at line $($_.InvocationInfo.ScriptLineNumber): $_"

    }

}

function Enable-E2EEncryption{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$App,
        [Parameter(Mandatory = $true)]
        [String]$ResourceGroup,
        [Parameter(Mandatory = $true)]
        [String]$AppId,
        [Parameter(Mandatory = $true)]
        [ValidateSet("NC","SC")]
        [String]$Location
    )

    Write-Host "Enabling End-to-End TLS Encryption..." -ForegroundColor Cyan
    $subid = ($AppId -split '/')[2]
    If ($Location -eq "SC"){

    $region = "southcentralus"

    }
    elseif ($Location -eq "NC"){

        $region = "northcentralus"

    }

    $resourceUrl = "/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.Web/sites/$App`?api-version=2022-03-01"
    $body = @{

        location = $region
        properties = @{

            endToEndEncryptionEnabled = $true

        }
        tags = @{

            ApplicationName = $AppType
            Environment = $Environment

        }
    } | ConvertTo-Json
    Invoke-AzRestMethod -Method Put -Path $resourceUrl -Payload $body | Out-Null
    Write-Host "End-to-End TLS Encryption enabled!" -ForegroundColor Green
    Write-Host "================"

}

#Giant Switch to determine environment/app combo.
switch ($Environment){

    Prod{

        Switch ($AppType){

            App1{

                Set-AzContext "prod-upper-001" | Out-Null
                #Obtaining app info
                Try {

                    Write-Host "Obtaining app info for $AppName..." -ForegroundColor Cyan
                    $Webapp = Get-AzWebapp -Name $appName -ErrorAction Stop -WarningAction 'silentlyContinue'
                    Write-Host "App info obtained!" -ForegroundColor Green
                    Write-Host "================"

                }
                catch {

                    Write-Error "Error obtaining app info at line $($_.InvocationInfo.ScriptLineNumber): $_"
                            
                }
                    
                #Configuring Application Insights
                Try{

                    Configure-ApplicationInsights -App $AppName -InstrumentationKey "x"

                }
                catch {

                    Write-Error "Error configuring Application Insights at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

                #Check for existing container
                $SAName = "SAprod"
                $SARG = "rg-prod-storage-001"
                $ctx = Check-Container -StorageAccount $SAName -ResourceGroup $SARG -App $AppName

                #Setting Backup schedule
                Try {

                    $sasURL = Configure-Backups -App $AppName -Context $ctx

                }
                catch {

                    Write-Error "Error configuring backup schedule at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

            }
            App2{

                Set-AzContext "prod-upper-001" | Out-Null
                #Obtaining app info
                Try {

                    Write-Host "Obtaining app info for $AppName..." -ForegroundColor Cyan
                    $Webapp = Get-AzWEbapp -Name $appName -ErrorAction Stop -WarningAction 'silentlyContinue'
                    Write-Host "App info obtained!" -ForegroundColor Green
                    Write-Host "================"

                }
                catch {

                    Write-Error "Error obtaining app info at line $($_.InvocationInfo.ScriptLineNumber): $_"
                            
                }
 
                #Configuring Application Insights
                Try{

                    $SAName = "SAprod"
                    $SARG = "rg-prod-storage-001"
                    Configure-ApplicationInsights -App $AppName -InstrumentationKey "x"

                }
                catch {

                    Write-Error "Error configuring Application Insights at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

                #Check for existing container
                $SAName = "SAprod"
                $SARG = "rg-prod-storage-001"
                $ctx = Check-Container -StorageAccount $SAName -ResourceGroup $SARG -App $AppName
                
                #Setting Backup schedule
                Try {

                    $sasURL = Configure-Backups -App $AppName -Context $ctx

                }
                catch {

                    Write-Error "Error configuring backup schedule at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

            }
            App3{

                Set-AzContext "app3-upper-001" | Out-Null
                #Obtaining app info
                Try {

                    Write-Host "Obtaining app info for $AppName..." -ForegroundColor Cyan
                    $Webapp = Get-AzWebapp -Name $appName -ErrorAction Stop -WarningAction 'silentlyContinue'
                    Write-Host "App info obtained!" -ForegroundColor Green
                    Write-Host "================"

                }
                catch {

                    Write-Error "Error obtaining app info at line $($_.InvocationInfo.ScriptLineNumber): $_"
                            
                }
                    
                #Configuring Application Insights
                Try{

                    Configure-ApplicationInsights -App $AppName -InstrumentationKey "x"

                }
                catch {

                    Write-Error "Error configuring Application Insights at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

                #Check for existing container
                $SAName = "SAprod-App3"
                $SARG = "rg-prod-storage-001"
                $ctx = Check-Container -StorageAccount $SAName -ResourceGroup $SARG -App $AppName
                
                #Setting Backup schedule
                Try {

                    $sasURL = Configure-Backups -App $AppName -Context $ctx

                }
                catch {

                    Write-Error "Error configuring backup schedule at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

            }

        }

    }
    Prod2{

        Switch ($AppType){

            App1{

                Set-AzContext "prod2-upper-001" | Out-Null
                #Obtaining app info
                Try {

                    Write-Host "Obtaining app info for $AppName..." -ForegroundColor Cyan
                    $Webapp = Get-AzWEbapp -Name $appName -ErrorAction Stop -WarningAction 'silentlyContinue'
                    Write-Host "App info obtained!" -ForegroundColor Green
                    Write-Host "================"

                }
                catch {

                    Write-Error "Error obtaining app info at line $($_.InvocationInfo.ScriptLineNumber): $_"
                            
                }
                    
                #Configuring Application Insights
                Try{

                    Configure-ApplicationInsights -App $AppName -InstrumentationKey "x"

                }
                catch {

                    Write-Error "Error configuring Application Insights at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

                #Check for existing container
                $SAName = "SAProd2"
                $SARG = "rg-prod2-storage-001"
                $ctx = Check-Container -StorageAccount $SAName -ResourceGroup $SARG -App $AppName
                
                #Setting Backup schedule
                Try {

                    $sasURL = Configure-Backups -App $AppName -Context $ctx

                }
                catch {

                    Write-Error "Error configuring backup schedule at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

            }
            App2{

                Set-AzContext "prod2-upper-001" | Out-Null
                #Obtaining app info
                Try {

                    Write-Host "Obtaining app info for $AppName..." -ForegroundColor Cyan
                    $Webapp = Get-AzWEbapp -Name $appName -ErrorAction Stop -WarningAction 'silentlyContinue'
                    Write-Host "App info obtained!" -ForegroundColor Green
                    Write-Host "================"

                }
                catch {

                    Write-Error "Error obtaining app info at line $($_.InvocationInfo.ScriptLineNumber): $_"
                            
                }
                    
                #Configuring Application Insights
                Try{

                    Configure-ApplicationInsights -App $AppName -InstrumentationKey "x"

                }
                catch {

                    Write-Error "Error configuring Application Insights at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

                #Check for existing container
                $SAName = "SAProd2"
                $SARG = "rg-prod2-storage-001"
                $ctx = Check-Container -StorageAccount $SAName -ResourceGroup $SARG -App $AppName
                
                #Setting Backup schedule
                Try {

                    $sasURL = Configure-Backups -App $AppName -Context $ctx

                }
                catch {

                    Write-Error "Error configuring backup schedule at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

            }
            App3{

                Set-AzContext "app3-upper-001" | Out-Null
                #Obtaining app info
                Try {

                    Write-Host "Obtaining app info for $AppName..." -ForegroundColor Cyan
                    $Webapp = Get-AzWebapp -Name $appName -ErrorAction Stop -WarningAction 'silentlyContinue'
                    Write-Host "App info obtained!" -ForegroundColor Green
                    Write-Host "================"

                }
                catch {

                    Write-Error "Error obtaining app info at line $($_.InvocationInfo.ScriptLineNumber): $_"
                            
                }
                    
                #Configuring Application Insights
                Try{

                    Configure-ApplicationInsights -App $AppName -InstrumentationKey "x"

                }
                catch {

                    Write-Error "Error configuring Application Insights at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

                #Check for existing container
                $SAName = "SAApp3Prod2"
                $SARG = "rg-app3-data-prod2-001"
                $ctx = Check-Container -StorageAccount $SAName -ResourceGroup $SARG -App $AppName
                
                #Setting Backup schedule
                Try {

                    $sasURL = Configure-Backups -App $AppName -Context $ctx

                }
                catch {

                    Write-Error "Error configuring backup schedule at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

            }

        }

    }
    Beta{

        
        Switch ($AppType){

            App1{

                Set-AzContext "beta-upper-001" | Out-Null
                #Obtaining app info
                Try {

                    Write-Host "Obtaining app info for $AppName..." -ForegroundColor Cyan
                    $Webapp = Get-AzWEbapp -Name $appName -ErrorAction Stop -WarningAction 'silentlyContinue'
                    Write-Host "App info obtained!" -ForegroundColor Green
                    Write-Host "================"

                }
                catch {

                    Write-Error "Error obtaining app info at line $($_.InvocationInfo.ScriptLineNumber): $_"
                            
                }
                    
                #Configuring Application Insights
                Try{

                    Configure-ApplicationInsights -App $AppName -InstrumentationKey "x"

                }
                catch {

                    Write-Error "Error configuring Application Insights at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

                #Check for existing container
                $SAName = "SAbeta"
                $SARG = "rg-beta-storage-001"
                $ctx = Check-Container -StorageAccount $SAName -ResourceGroup $SARG -App $AppName

                #Setting Backup schedule
                Try {

                    $sasURL = Configure-Backups -App $AppName -Context $ctx

                }
                catch {

                    Write-Error "Error configuring backup schedule at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

            }
            App2{

                Set-AzContext "beta-upper-001" | Out-Null
                #Obtaining app info
                Try {

                    Write-Host "Obtaining app info for $AppName..." -ForegroundColor Cyan
                    $Webapp = Get-AzWebapp -Name $appName -ErrorAction Stop -WarningAction 'silentlyContinue'
                    Write-Host "App info obtained!" -ForegroundColor Green
                    Write-Host "================"

                }
                catch {

                    Write-Error "Error obtaining app info at line $($_.InvocationInfo.ScriptLineNumber): $_"
                            
                }
                    
                #Configuring Application Insights
                Try{

                    Configure-ApplicationInsights -App $AppName -InstrumentationKey "x"

                }
                catch {

                    Write-Error "Error configuring Application Insights at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

                #Check for existing container
                $SAName = "SAbeta"
                $SARG = "rg-beta-storage-001"
                $ctx = Check-Container -StorageAccount $SAName -ResourceGroup $SARG -App $AppName
                
                #Setting Backup schedule
                Try {

                    $sasURL = Configure-Backups -App $AppName -Context $ctx

                }
                catch {

                    Write-Error "Error configuring backup schedule at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

            }
            App3{

                Set-AzContext "app3-upper-001" | Out-Null
                #Obtaining app info
                Try {

                    Write-Host "Obtaining app info for $AppName..." -ForegroundColor Cyan
                    $Webapp = Get-AzWEbapp -Name $appName -ErrorAction Stop -WarningAction 'silentlyContinue'
                    Write-Host "App info obtained!" -ForegroundColor Green
                    Write-Host "================"

                }
                catch {

                    Write-Error "Error obtaining app info at line $($_.InvocationInfo.ScriptLineNumber): $_"
                            
                }
                    
                #Configuring Application Insights
                Try{
                    
                    Configure-ApplicationInsights -App $AppName -InstrumentationKey "x"

                }
                catch {

                    Write-Error "Error configuring Application Insights at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

                #Check for existing container
                $SAName = "SAApp3beta"
                $SARG = "rg-App3-beta-storage-001"
                $ctx = Check-Container -StorageAccount $SAName -ResourceGroup $SARG -App $AppName
                
                #Setting Backup schedule
                Try {

                    $sasURL = Configure-Backups -App $AppName -Context $ctx

                }
                catch {

                    Write-Error "Error configuring backup schedule at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

            }

        }

    }
    Dev{

        Switch ($AppType){

            App1{

                Set-AzContext "dev-lower-001" | Out-Null
                #Obtaining app info
                Try {

                    Write-Host "Obtaining app info for $AppName..." -ForegroundColor Cyan
                    $Webapp = Get-AzWEbapp -Name $appName -ErrorAction Stop -WarningAction 'silentlyContinue'
                    Write-Host "App info obtained!" -ForegroundColor Green
                    Write-Host "================"

                }
                catch {

                    Write-Error "Error obtaining app info at line $($_.InvocationInfo.ScriptLineNumber): $_"
                            
                }
                    
                #Configuring Application Insights
                Try{
                    
                    Configure-ApplicationInsights -App $AppName -InstrumentationKey "x"

                }
                catch {

                    Write-Error "Error configuring Application Insights at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

                #Check for existing container
                $SAName = "SADev"
                $SARG = "rg-dev-storage-001"
                $ctx = Check-Container -StorageAccount $SAName -ResourceGroup $SARG -App $AppName
                
                #Setting Backup schedule
                Try {

                    $sasURL = Configure-Backups -App $AppName -Context $ctx

                }
                catch {

                    Write-Error "Error configuring backup schedule at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

            }
            app2{

                Set-AzContext "dev-lower-001" | Out-Null
                #Obtaining app info
                Try {

                    Write-Host "Obtaining app info for $AppName..." -ForegroundColor Cyan
                    $Webapp = Get-AzWEbapp -Name $appName -ErrorAction Stop -WarningAction 'silentlyContinue'
                    Write-Host "App info obtained!" -ForegroundColor Green
                    Write-Host "================"

                }
                catch {

                    Write-Error "Error obtaining app info at line $($_.InvocationInfo.ScriptLineNumber): $_"
                            
                }
                    
                #Configuring Application Insights
                Try{

                    $SAName = "SADev"
                    $SARG = "rg-dev-storage-001"
                    Configure-ApplicationInsights -App $AppName -InstrumentationKey "x"

                }
                catch {

                    Write-Error "Error configuring Application Insights at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

                #Check for existing container
                $SAName = "SADev"
                $SARG = "rg-dev-storage-001"
                $ctx = Check-Container -StorageAccount $SAName -ResourceGroup $SARG -App $AppName
                
                #Setting Backup schedule
                Try {

                    $sasURL = Configure-Backups -App $AppName -Context $ctx

                }
                catch {

                    Write-Error "Error configuring backup schedule at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

            }
            App3{

                Set-AzContext "app3-lower-001" | Out-Null
                #Obtaining app info
                Try {

                    Write-Host "Obtaining app info for $AppName..." -ForegroundColor Cyan
                    $Webapp = Get-AzWEbapp -Name $appName -ErrorAction Stop -WarningAction 'silentlyContinue'
                    Write-Host "App info obtained!" -ForegroundColor Green
                    Write-Host "================"

                }
                catch {

                    Write-Error "Error obtaining app info at line $($_.InvocationInfo.ScriptLineNumber): $_"
                            
                }
                    
                #Configuring Application Insights
                Try{
                    
                    $SAName = "SADevApp3"
                    $SARG = "rg-app3-dev-storage-001"
                    Configure-ApplicationInsights -App $AppName -InstrumentationKey "x"

                }
                catch {

                    Write-Error "Error configuring Application Insights at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

                #Check for existing container
                $SAName = "SADevApp3"
                $SARG = "rg-App3-dev-storage-001"
                $ctx = Check-Container -StorageAccount $SAName -ResourceGroup $SARG -App $AppName
                
                #Setting Backup schedule
                Try {

                    $sasURL = Configure-Backups -App $AppName -Context $ctx

                }
                catch {

                    Write-Error "Error configuring backup schedule at line $($_.InvocationInfo.ScriptLineNumber): $_"

                }

            }

        }

    }

}

#Assigning System Identity
Try {

    Write-Host "Assigning system identity..." -ForegroundColor Cyan
    Set-AzWebApp -ResourceGroupName $Webapp.ResourceGroup -Name $AppName -AssignIdentity $True | Out-Null
    Write-Host "System identity assigned!" -ForegroundColor Green
    Write-Host "================"

}
catch {

    Write-Error "Error assigning system identity at line $($_.InvocationInfo.ScriptLineNumber): $_"

}

#Adding Health Check and enabling HTTP 2.0, plus setting NetFrameworkVersion if specified
Try {

    Write-Host "Adding Health Check, enabling HTTP 2.0..." -ForegroundColor Cyan
    $Webapp.SiteConfig.HealthCheckPath = "/api/v1/health/status"
    $Webapp.SiteConfig.Http20Enabled = $True
    If ($NetVersion) {
            
        Set-AzWebapp -Webapp $Webapp | Out-Null
        $PropertiesObject = @{ 
                
            "CURRENT_STACK" = "dotnetcore" 
                
            }
        New-AzResource -PropertyObject $PropertiesObject -ResourceGroupName $Webapp.ResourceGroup -ResourceType Microsoft.Web/sites/config -ResourceName "$($Webapp.Name)/metadata" -ApiVersion 2018-02-01 -Force | Out-Null
        Set-AzWebapp -Name $Webapp.Name -ResourceGroupName $Webapp.ResourceGroup -NetFrameworkVersion $NetVersion | Out-Null
        Write-Host "Health check added, HTTP 2.0 enabled, and NetFrameworkVersion set!" -ForegroundColor Green

    }
    else {

        Set-AzWebapp -Webapp $Webapp | Out-Null
        Write-Host "Health check added, HTTP 2.0 enabled!" -ForegroundColor Green

    }
    Write-Host "================"
}
catch {

    Write-Error "Error adding health check or setting NetFrameworkVersion at line $($_.InvocationInfo.ScriptLineNumber): $_"

}

#Configure App Service Logs
Try {

    Write-Host "Configuring App Service Logs..." -ForegroundColor Cyan
    $Logging = Get-AzResource -ResourceGroupName $Webapp.ResourceGroup -ResourceType Microsoft.Web/sites/config -ResourceName "$($Webapp.name)/logs" -ApiVersion 2016-08-01
    $Logging.Properties.applicationLogs.azureBlobStorage.level = "Error"
    $Logging.Properties.applicationLogs.azureBlobStorage.sasUrl = $sasURL.ToString()
    $Logging.Properties.applicationLogs.azureBlobStorage.retentionInDays = 30
    $Logging.Properties.applicationLogs.fileSystem.Level = "Off"
    $Logging.Properties.httpLogs.azureBlobStorage.sasUrl = $sasURL.ToString()
    $Logging.Properties.httpLogs.azureBlobStorage.retentionInDays = 30
    $Logging.Properties.httpLogs.azureBlobStorage.enabled = $True
    $Logging.Properties.httpLogs.fileSystem.enabled = $false
    $Logging.Properties.failedRequestsTracing.enabled = $true
    $Logging.Properties.detailedErrorMessages.enabled = $true
    Set-AzResource -Properties $Logging.Properties -ResourceGroupName $Webapp.ResourceGroup -ResourceType Microsoft.Web/sites/config -ResourceName "$($Webapp.name)/logs" -ApiVersion 2016-08-01 -Force | Out-Null
    Write-Host "App Service Logs configured!" -ForegroundColor Green
    Write-Host "================"

}
catch {

    Write-Error "Error configuring App Service Logs at line $($_.InvocationInfo.ScriptLineNumber): $_"

}

#Create the blue deployment slot, if specified
If ($Slot){

    Try{

        #Retrieve the app settings from the existing web app
        $appSettings = $webApp.SiteConfig.AppSettings
    
        #Create a hashtable for the app settings
        $appSettingsHashtable = @{}
        foreach ($setting in $appSettings) {
            $appSettingsHashtable[$setting.Name] = $setting.Value
        }
    
        #Create the new deployment slot with the copied settings
        $FullSlotName = "$AppName/blue"
        $charCount = ($FullSlotName | Measure-Object -Character).Characters
        Write-Host "Creating blue deployment slot..." -ForegroundColor Cyan
        If ($charCount -gt 60){
    
            Write-Error "The full app name '$FullAppName' is longer than 60 characters. The deployment slot must be created manually with a shorter name."
            Write-Host "================"
            
    
        }
        else{
    
            New-AzWebAppSlot -ResourceGroupName $Webapp.ResourceGroup -Name $AppName -Slot "blue" -AppSettingsOverrides $appSettingsHashtable | Out-Null
            Write-Host "Blue deployment slot created!" -ForegroundColor Green
            Write-Host "================"
    
        }
        
    
    }
    catch{
    
        Write-Error "Error creating blue deployment slot at line $($_.InvocationInfo.ScriptLineNumber): $_"
    
    }

}

#Lastly, the two region-dependent actions: Enabling E2E Encryption and configuring diagnostics
If ($Environment -eq "Prod2"){

    #Enabling E2E Encryption
    Try {

        Enable-E2EEncryption -App $AppName -ResourceGroup $Webapp.ResourceGroup -AppId $Webapp.id -Location SC

    }
    catch {

        Write-Error "Error enabling End-to-End TLS Encryption at line $($_.InvocationInfo.ScriptLineNumber): $_"

    }
    #Configure Diagnostics Settings
    Try{

        Write-Host "Configuring diagnostics settings..." -ForegroundColor Cyan
        Set-AzContext "Diagnostics" | out-null
        $Metric = @()
        $Log = @()
        $categories = Get-AzDiagnosticSettingCategory -ResourceId $Webapp.Id
        $categories | ForEach-Object {if($_.CategoryType -eq "Metrics"){$metric+=New-AzDiagnosticSettingMetricSettingsObject -Enabled $true -Category $_.Name -RetentionPolicyDay 0 -RetentionPolicyEnabled $false} else{$log+=New-AzDiagnosticSettingLogSettingsObject -Enabled $true -Category $_.Name -RetentionPolicyDay 0 -RetentionPolicyEnabled $false}}
        New-AzDiagnosticSetting -Name "Diagnostic Settings" -ResourceId $Webapp.Id -WorkspaceId "/subscriptions/{YOURSUBIDHERE}/resourceGroups/{YOURRGHERE}/providers/Microsoft.OperationalInsights/workspaces/{YOURWORKSPACE}" -Log $log -Metric $metric -EventHubName "{YOUREHNAME}" -eventHubAuthorizationRuleId "/subscriptions/{YOURSUBIDHERE}/resourceGroups/{YOURRGHERE}/providers/Microsoft.EventHub/namespaces/{YOUREHNAME}/authorizationrules/{YOURRULEHERE}" | Out-Null
        Write-Host "Diagnostics settings configured!" -ForegroundColor Green
        Write-Host "================"
        Write-Host "$AppName fully configured!" -ForegroundColor Green

    }
    catch {

        Write-Error "Error configuring diagnostics settings at line $($_.InvocationInfo.ScriptLineNumber): $_"

    }

}
else{

    #Enabling E2E Encryption
    Try {

        Enable-E2EEncryption -App $AppName -ResourceGroup $Webapp.ResourceGroup -AppId $Webapp.id -Location NC

    }
    catch {

        Write-Error "Error enabling End-to-End TLS Encryption at line $($_.InvocationInfo.ScriptLineNumber): $_"

    }
    #Configure Diagnostics Settings
    Try {

        Write-Host "Configuring diagnostics settings..." -ForegroundColor Cyan
        Set-AzContext "Diagnostics" | Out-Null
        $Metric = @()
        $Log = @()
        $categories = Get-AzDiagnosticSettingCategory -ResourceId $Webapp.Id
        $categories | ForEach-Object {

            if ($_.CategoryType -eq "Metrics") {

                $metric += New-AzDiagnosticSettingMetricSettingsObject -Enabled $true -Category $_.Name -RetentionPolicyDay 0 -RetentionPolicyEnabled $false

            }
            else {

                $log += New-AzDiagnosticSettingLogSettingsObject -Enabled $true -Category $_.Name -RetentionPolicyDay 0 -RetentionPolicyEnabled $false
                    
            }

        }
        New-AzDiagnosticSetting -Name "Diagnostic Settings" -ResourceId $Webapp.Id -WorkspaceId "/subscriptions/{YOURSUBIDHERE}/resourceGroups/{YOURRGHERE}/providers/Microsoft.OperationalInsights/workspaces/{YOURWORKSPACE}" -Log $log -Metric $metric -EventHubName "{YOUREHNAME}" -EventHubAuthorizationRuleId "/subscriptions/{YOURSUBIDHERE}/resourceGroups/{YOURRGHERE}/providers/Microsoft.EventHub/namespaces/{YOUREHNAME}/authorizationrules/{YOURRULEHERE}" | Out-Null
        Write-Host "Diagnostics settings configured!" -ForegroundColor Green
        Write-Host "================"
        Write-Host "$AppName fully configured!" -ForegroundColor Green
    }
    catch {

        Write-Error "Error configuring diagnostics settings at line $($_.InvocationInfo.ScriptLineNumber): $_"

    }

}

#Cleanup all user-defined variables
Get-Variable | Where-Object { $_.Name -notmatch '^(__|PS|Host|Error|MyInvocation|\?)$' } | Remove-Variable | out-null
