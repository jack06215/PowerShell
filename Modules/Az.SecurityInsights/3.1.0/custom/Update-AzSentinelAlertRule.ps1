
# ----------------------------------------------------------------------------------
#
# Copyright Microsoft Corporation
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------------

<#
.Synopsis
Updates the alert rule.
.Description
Updates the alert rule.

.Link
https://learn.microsoft.com/powershell/module/az.securityinsights/Update-azsentinelalertrule
#>
function Update-AzSentinelAlertRule {
    [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.CmdletBreakingChange("11.0.0", "4.0.0", "2023/11/15", ChangeDescription="Parameters of NRT set will be deprecated.")]
    [OutputType([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.AlertRule])]
    [CmdletBinding(DefaultParameterSetName = 'UpdateScheduled', PositionalBinding = $false, SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(ParameterSetName = 'UpdateFusionMLTI')]
        [Parameter(ParameterSetName = 'UpdateMicrosoftSecurityIncidentCreation')]
        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Path')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.DefaultInfo(Script = '(Get-AzContext).Subscription.Id')]
        [System.String]
        # Gets subscription credentials which uniquely identify Microsoft Azure subscription.
        # The subscription ID forms part of the URI for every service call.
        ${SubscriptionId},
        
        [Parameter(ParameterSetName = 'UpdateFusionMLTI', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateMicrosoftSecurityIncidentCreation', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateNRT', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateScheduled', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Path')]
        [System.String]
        # The Resource Group Name.
        ${ResourceGroupName},

        [Parameter(ParameterSetName = 'UpdateFusionMLTI', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateMicrosoftSecurityIncidentCreation', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateNRT', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateScheduled', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Path')]
        [System.String]
        # The name of the workspace.
        ${WorkspaceName},

        [Parameter(ParameterSetName = 'UpdateFusionMLTI', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateMicrosoftSecurityIncidentCreation', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateNRT', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateScheduled', Mandatory)]
        #[Alias('RuleId')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Path')]
        [System.String]
        # The name of Operational Insights Resource Provider.
        ${RuleId},

        [Parameter(ParameterSetName = 'UpdateViaIdentityFusionMLTI', Mandatory, ValueFromPipeline)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftSecurityIncidentCreation', Mandatory, ValueFromPipeline)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT', Mandatory, ValueFromPipeline)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled', Mandatory, ValueFromPipeline)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Path')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.ISecurityInsightsIdentity]
        # Identity Parameter
        # To construct, see NOTES section for INPUTOBJECT properties and create a hash table.
        ${InputObject},

        [Parameter(ParameterSetName = 'UpdateFusionMLTI', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityFusionMLTI', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        ${FusionMLorTI},

        [Parameter(ParameterSetName = 'UpdateMicrosoftSecurityIncidentCreation', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftSecurityIncidentCreation', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        ${MicrosoftSecurityIncidentCreation},

        [Parameter(ParameterSetName = 'UpdateNRT', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        ${NRT},

        [Parameter(ParameterSetName = 'UpdateScheduled', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        ${Scheduled},

        [Parameter(ParameterSetName = 'UpdateFusionMLTI')]
        [Parameter(ParameterSetName = 'UpdateMicrosoftSecurityIncidentCreation')]
        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityFusionMLTI')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftSecurityIncidentCreation')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${AlertRuleTemplateName},
        
        [Parameter(ParameterSetName = 'UpdateFusionMLTI')]
        [Parameter(ParameterSetName = 'UpdateMicrosoftSecurityIncidentCreation')]
        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityFusionMLTI')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftSecurityIncidentCreation')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Switch]
        ${Enabled},

        [Parameter(ParameterSetName = 'UpdateFusionMLTI')]
        [Parameter(ParameterSetName = 'UpdateMicrosoftSecurityIncidentCreation')]
        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityFusionMLTI')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftSecurityIncidentCreation')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Switch]
        ${Disabled},

        [Parameter(ParameterSetName = 'UpdateMicrosoftSecurityIncidentCreation')]
        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftSecurityIncidentCreation')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${Description},

        [Parameter(ParameterSetName = 'UpdateMicrosoftSecurityIncidentCreation')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftSecurityIncidentCreation')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String[]]
        ${DisplayNamesFilter},

        [Parameter(ParameterSetName = 'UpdateMicrosoftSecurityIncidentCreation')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftSecurityIncidentCreation')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String[]]
        ${DisplayNamesExcludeFilter},


        [Parameter(ParameterSetName = 'UpdateMicrosoftSecurityIncidentCreation')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftSecurityIncidentCreation')]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.MicrosoftSecurityProductName])]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.MicrosoftSecurityProductName]
        ${ProductFilter},
            
        [Parameter(ParameterSetName = 'UpdateMicrosoftSecurityIncidentCreation')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftSecurityIncidentCreation')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.AlertSeverity[]]
        #High, Medium, Low, Informational
        ${SeveritiesFilter},

        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${Query},
        
        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${DisplayName},

        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.DefaultInfo(Script = 'New-TimeSpan -Hours 5')]
        [System.TimeSpan]
        ${SuppressionDuration},

        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Switch]
        ${SuppressionEnabled},

        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.AlertSeverity])]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.AlertSeverity]
        ${Severity},

        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.AttackTactic])]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.AttackTactic]
        [System.String[]]
        ${Tactic},
            
        
        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Switch]
        ${CreateIncident},

        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Switch]
        ${GroupingConfigurationEnabled},

        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Switch]
        ${ReOpenClosedIncident},

        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.DefaultInfo(Script = 'New-TimeSpan -Hours 5')]
        [System.TimeSpan]
        ${LookbackDuration},

        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.DefaultInfo(Script = '"AllEntities"')]
        [ValidateSet('AllEntities', 'AnyAlert', 'Selected')]
        [System.String]
        ${MatchingMethod},
            
        
        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.AlertDetail])]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.AlertDetail[]]
        ${GroupByAlertDetail}, 
        
        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [string[]] 
        ${GroupByCustomDetail},
        
        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.EntityMappingType])]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.EntityMappingType[]]
        ${GroupByEntity},
    
        
        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        #'Account', 'Host', 'IP', 'Malware', 'File', 'Process', 'CloudApplication', 'DNS', 'AzureResource', 'FileHash', 'RegistryKey', 'RegistryValue', 'SecurityGroup', 'URL', 'Mailbox', 'MailCluster', 'MailMessage', 'SubmissionMail'
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.EntityMapping[]]
        ${EntityMapping},

        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${AlertDescriptionFormat},

        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${AlertDisplayNameFormat},

        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${AlertSeverityColumnName},

        [Parameter(ParameterSetName = 'UpdateNRT')]
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityNRT')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${AlertTacticsColumnName},


        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.TimeSpan]
        ${QueryFrequency},

        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.TimeSpan]
        ${QueryPeriod},

        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.TriggerOperator])]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.TriggerOperator]
        ${TriggerOperator},
        
        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [int]
        ${TriggerThreshold},

        [Parameter(ParameterSetName = 'UpdateScheduled')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityUpdateScheduled')]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.EventGroupingAggregationKind])]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.EventGroupingAggregationKind]
        ${EventGroupingSettingAggregationKind},
            
        [Parameter()]
        [Alias('AzureRMContext', 'AzureCredential')]
        [ValidateNotNull()]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Azure')]
        [System.Management.Automation.PSObject]
        # The credentials, account, tenant, and subscription used for communication with Azure.
        ${DefaultProfile},

        [Parameter()]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        # Run the command as a job
        ${AsJob},

        [Parameter(DontShow)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        # Wait for .NET debugger to attach
        ${Break},

        [Parameter(DontShow)]
        [ValidateNotNull()]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.SendAsyncStep[]]
        # SendAsync Pipeline Steps to be appended to the front of the pipeline
        ${HttpPipelineAppend},

        [Parameter(DontShow)]
        [ValidateNotNull()]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.SendAsyncStep[]]
        # SendAsync Pipeline Steps to be prepended to the front of the pipeline
        ${HttpPipelinePrepend},

        [Parameter()]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        # Run the command asynchronously
        ${NoWait},

        [Parameter(DontShow)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Uri]
        # The URI for the proxy server to use
        ${Proxy},

        [Parameter(DontShow)]
        [ValidateNotNull()]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.PSCredential]
        # Credentials for a proxy server to use for the remote call
        ${ProxyCredential},

        [Parameter(DontShow)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        # Use the default credentials for the proxy
        ${ProxyUseDefaultCredentials}
    )

    process {
        try {
            $null = $PSBoundParameters.Remove('FusionMLorTI')
            $null = $PSBoundParameters.Remove('MicrosoftSecurityIncidentCreation')
            $null = $PSBoundParameters.Remove('NRT')
            $null = $PSBoundParameters.Remove('Scheduled')
            #Handle Get
            $GetPSBoundParameters = @{}
            if($PSBoundParameters['InputObject']){
                $GetPSBoundParameters.Add('InputObject', $PSBoundParameters['InputObject'])
            }
            else {
                $GetPSBoundParameters.Add('ResourceGroupName', $PSBoundParameters['ResourceGroupName'])
                $GetPSBoundParameters.Add('WorkspaceName', $PSBoundParameters['WorkspaceName'])
                $GetPSBoundParameters.Add('RuleId', $PSBoundParameters['RuleId'])
            }
            $AlertRule = Az.SecurityInsights\Get-AzSentinelAlertRule @GetPSBoundParameters

            #Fusion
            if ($AlertRule.Kind -eq 'Fusion'){
                If($PSBoundParameters['AlertTemplateName']){
                    $AlertRule.AlertRuleTemplateName = $PSBoundParameters['AlertRuleTemplateName']
                    $null = $PSBoundParameters.Remove('AlertRuleTemplateName')
                }
                
                If($PSBoundParameters['Enabled']){
                    $AlertRule.Enabled = $true
                    $null = $PSBoundParameters.Remove('Enabled')
                }
                if($PSBoundParameters['Disabled']) {
                    $AlertRule.Enabled = $false
                    $null = $PSBoundParameters.Remove('Disabled')
                }
            }
            #MSIC
            if($AlertRule.Kind -eq 'MicrosoftSecurityIncidentCreation'){
                If($PSBoundParameters['AlertRuleTemplateName']){
                    $AlertRule.AlertRuleTemplateName = $PSBoundParameters['AlertRuleTemplateName']
                    $null = $PSBoundParameters.Remove('AlertRuleTemplateName')
                }
                
                If($PSBoundParameters['Enabled']){
                    $AlertRule.Enabled = $true
                    $null = $PSBoundParameters.Remove('Enabled')
                }
                if($PSBoundParameters['Disabled']) {
                    $AlertRule.Enabled = $false
                    $null = $PSBoundParameters.Remove('Disabled')
                }
                
                If($PSBoundParameters['Description']){
                    $AlertRule.Description = $PSBoundParameters['Description']
                    $null = $PSBoundParameters.Remove('Description')
                }
                
                If($PSBoundParameters['DisplayNamesFilter']){
                    $AlertRule.DisplayNamesFilter = $PSBoundParameters['DisplayNamesFilter']
                    $null = $PSBoundParameters.Remove('DisplayNamesFilter')
                }
                
                If($PSBoundParameters['DisplayNamesExcludeFilter']){
                    $AlertRule.DisplayNamesExcludeFilter = $PSBoundParameters['DisplayNamesExcludeFilter']
                    $null = $PSBoundParameters.Remove('DisplayNamesExcludeFilter')
                }
                
                If($PSBoundParameters['ProductFilter']){
                    $AlertRule.ProductFilter = $PSBoundParameters['ProductFilter']
                    $null = $PSBoundParameters.Remove('ProductFilter')
                }

                If($PSBoundParameters['SeveritiesFilter']){
                    $Parameter.SeveritiesFilter = $PSBoundParameters['SeveritiesFilter']
                    $null = $PSBoundParameters.Remove('SeveritiesFilter')
                }
            }
            #ML
            if ($AlertRule.Kind -eq 'MLBehaviorAnalytics'){
                If($PSBoundParameters['AlertRuleTemplateName']){
                    $AlertRule.AlertRuleTemplateName = $PSBoundParameters['AlertRuleTemplateName']
                    $null = $PSBoundParameters.Remove('AlertRuleTemplateName')
                }
                
                If($PSBoundParameters['Enabled']){
                    $AlertRule.Enabled = $true
                    $null = $PSBoundParameters.Remove('Enabled')
                }
                if($PSBoundParameters['Disabled']) {
                    $AlertRule.Enabled = $false
                    $null = $PSBoundParameters.Remove('Disabled')
                }
            }

            #NRT
            if($AlertRule.Kind -eq 'NRT'){
                If($PSBoundParameters['AlertRuleTemplateName']){
                    $AlertRule.Enabled = $PSBoundParameters['AlertRuleTemplateName']
                    $null = $PSBoundParameters.Remove('AlertRuleTemplateName')
                }
                
                If($PSBoundParameters['Enabled']){
                    $AlertRule.Enabled = $true
                    $null = $PSBoundParameters.Remove('Enabled')
                }
                if($PSBoundParameters['Disabled']) {
                    $AlertRule.Enabled = $false
                    $null = $PSBoundParameters.Remove('Disabled')
                }
                
                If($PSBoundParameters['Description']){
                    $AlertRule.Description = $PSBoundParameters['Description']
                    $null = $PSBoundParameters.Remove('Description')
                }
                
                If($PSBoundParameters['Query']){
                    $AlertRule.Query = $PSBoundParameters['Query']
                    $null = $PSBoundParameters.Remove('Query')
                }

                If($PSBoundParameters['DisplayName']){
                    $AlertRule.DisplayName = $PSBoundParameters['DisplayName']
                    $null = $PSBoundParameters.Remove('DisplayName')
                }

                If($PSBoundParameters['SuppressionDuration']){
                    $AlertRule.SuppressionDuration = $PSBoundParameters['SuppressionDuration']
                    $null = $PSBoundParameters.Remove('SuppressionDuration')
                }

                If($PSBoundParameters['SuppressionEnabled']){
                    $AlertRule.SuppressionEnabled = $true
                    $null = $PSBoundParameters.Remove('SuppressionEnabled')
                }
                else{
                    $AlertRule.SuppressionEnabled = $false
                }
                
                If($PSBoundParameters['Severity']){
                    $AlertRule.Severity = $PSBoundParameters['Severity']
                    $null = $PSBoundParameters.Remove('Severity')
                }
                
                If($PSBoundParameters['Tactic']){
                    $AlertRule.Tactic = $PSBoundParameters['Tactic']
                    $null = $PSBoundParameters.Remove('Tactic')
                }
                
                If($PSBoundParameters['IncidentConfigurationCreateIncident']){
                    $AlertRule.IncidentConfigurationCreateIncident = $true
                    $null = $PSBoundParameters.Remove('IncidentConfigurationCreateIncident')
                }
                else{
                    $AlertRule.IncidentConfigurationCreateIncident = $false
                }
                
                If($PSBoundParameters['Enabled']){
                    $AlertRule.GroupingConfigurationEnabled = $true
                    $null = $PSBoundParameters.Remove('Enabled')
                }
                else{
                    $AlertRule.GroupingConfigurationEnabled = $false
                }
                
                If($PSBoundParameters['ReOpenClosedIncident']){
                    $AlertRule.GroupingConfigurationReOpenClosedIncident = $true
                    $null = $PSBoundParameters.Remove('ReOpenClosedIncident')
                }
                else{
                    $AlertRule.GroupingConfigurationReOpenClosedIncident = $false
                }
                
                If($PSBoundParameters['LookbackDuration']){
                    $AlertRule.GroupingConfigurationLookbackDuration = $PSBoundParameters['LookbackDuration']
                    $null = $PSBoundParameters.Remove('LookbackDuration')
                }

                If($PSBoundParameters['MatchingMethod']){
                    $AlertRule.GroupingConfigurationMatchingMethod = $PSBoundParameters['MatchingMethod']
                    $null = $PSBoundParameters.Remove('MatchingMethod')
                }

                If($PSBoundParameters['GroupByAlertDetail']){
                    $AlertRule.GroupingConfigurationGroupByAlertDetail = $PSBoundParameters['GroupByAlertDetail']
                    $null = $PSBoundParameters.Remove('GroupByAlertDetail')
                }

                If($PSBoundParameters['GroupByCustomDetail']){
                    $AlertRule.GroupingConfigurationGroupByCustomDetail = $PSBoundParameters['GroupByCustomDetail']
                    $null = $PSBoundParameters.Remove('GroupByCustomDetail')
                }
                
                If($PSBoundParameters['GroupByEntity']){
                    $AlertRule.GroupingConfigurationGroupByEntity = $PSBoundParameters['GroupByEntity']
                    $null = $PSBoundParameters.Remove('GroupByEntity')
                }

                If($PSBoundParameters['EntityMapping']){
                    $AlertRule.EntityMapping = $PSBoundParameters['EntityMapping']
                    $null = $PSBoundParameters.Remove('EntityMapping')
                }

                If($PSBoundParameters['AlertDescriptionFormat']){
                    $AlertRule.AlertDetailOverrideAlertDescriptionFormat = $PSBoundParameters['AlertDescriptionFormat']
                    $null = $PSBoundParameters.Remove('AlertDescriptionFormat')
                }

                If($PSBoundParameters['AlertDisplayNameFormat']){
                    $AlertRule.AlertDetailOverrideAlertDisplayNameFormat = $PSBoundParameters['AlertDisplayNameFormat']
                    $null = $PSBoundParameters.Remove('AlertDisplayNameFormat')
                }

                If($PSBoundParameters['AlertSeverityColumnName']){
                    $AlertRule.AlertDetailOverrideAlertSeverityColumnName = $PSBoundParameters['AlertSeverityColumnName']
                    $null = $PSBoundParameters.Remove('AlertSeverityColumnName')
                }

                If($PSBoundParameters['AlertTacticsColumnName']){
                    $AlertRule.AlertDetailOverrideAlertTacticsColumnName = $PSBoundParameters['AlertTacticsColumnName']
                    $null = $PSBoundParameters.Remove('AlertTacticsColumnName')
                }
                
            }
            #Scheduled
            if ($AlertRule.Kind -eq 'Scheduled'){
                If($PSBoundParameters['AlertRuleTemplateName']){
                    $AlertRule.Enabled = $PSBoundParameters['AlertRuleTemplateName']
                    $null = $PSBoundParameters.Remove('AlertRuleTemplateName')
                }
                
                If($PSBoundParameters['Enabled']){
                    $AlertRule.Enabled = $true
                    $null = $PSBoundParameters.Remove('Enabled')
                }
                if($PSBoundParameters['Disabled']) {
                    $AlertRule.Enabled = $false
                    $null = $PSBoundParameters.Remove('Disabled')
                }
                
                If($PSBoundParameters['Description']){
                    $AlertRule.Description = $PSBoundParameters['Description']
                    $null = $PSBoundParameters.Remove('Description')
                }
                
                If($PSBoundParameters['Query']){
                    $AlertRule.Query = $PSBoundParameters['Query']
                    $null = $PSBoundParameters.Remove('Query')
                }

                If($PSBoundParameters['DisplayName']){
                    $AlertRule.DisplayName = $PSBoundParameters['DisplayName']
                    $null = $PSBoundParameters.Remove('DisplayName')
                }

                If($PSBoundParameters['SuppressionDuration']){
                    $AlertRule.SuppressionDuration = $PSBoundParameters['SuppressionDuration']
                    $null = $PSBoundParameters.Remove('SuppressionDuration')
                }

                If($PSBoundParameters['SuppressionEnabled']){
                    $AlertRule.SuppressionEnabled = $true
                    $null = $PSBoundParameters.Remove('SuppressionEnabled')
                }
                else{
                    $AlertRule.SuppressionEnabled = $false
                }
                
                If($PSBoundParameters['Severity']){
                    $AlertRule.Severity = $PSBoundParameters['Severity']
                    $null = $PSBoundParameters.Remove('Severity')
                }

                If($PSBoundParameters['Tactic']){
                    $AlertRule.Tactic = $PSBoundParameters['Tactic']
                    $null = $PSBoundParameters.Remove('Tactic')
                }
                
                If($PSBoundParameters['CreateIncident']){
                    $AlertRule.IncidentConfigurationCreateIncident = $true
                    $null = $PSBoundParameters.Remove('CreateIncident')
                }
                else{
                    $AlertRule.IncidentConfigurationCreateIncident = $false
                }
                
                If($PSBoundParameters['GroupingConfigurationEnabled']){
                    $AlertRule.GroupingConfigurationEnabled = $true
                    $null = $PSBoundParameters.Remove('GroupingConfigurationEnabled')
                }
                else{
                    $AlertRule.GroupingConfigurationEnabled = $false
                }
                
                If($PSBoundParameters['ReOpenClosedIncident']){
                    $AlertRule.GroupingConfigurationReOpenClosedIncident = $PSBoundParameters['ReOpenClosedIncident']
                    $null = $PSBoundParameters.Remove('ReOpenClosedIncident')
                }
                else{
                    $AlertRule.GroupingConfigurationReOpenClosedIncident = $false
                }
                
                If($PSBoundParameters['LookbackDuration']){
                    $AlertRule.GroupingConfigurationLookbackDuration = $PSBoundParameters['LookbackDuration']
                    $null = $PSBoundParameters.Remove('LookbackDuration')
                }

                If($PSBoundParameters['MatchingMethod']){
                    $AlertRule.GroupingConfigurationMatchingMethod = $PSBoundParameters['MatchingMethod']
                    $null = $PSBoundParameters.Remove('MatchingMethod')
                }

                If($PSBoundParameters['GroupByAlertDetail']){
                    $AlertRule.GroupingConfigurationGroupByAlertDetail = $PSBoundParameters['GroupByAlertDetail']
                    $null = $PSBoundParameters.Remove('GroupByAlertDetail')
                }

                If($PSBoundParameters['GroupByCustomDetail']){
                    $AlertRule.GroupingConfigurationGroupByCustomDetail = $PSBoundParameters['GroupByCustomDetail']
                    $null = $PSBoundParameters.Remove('GroupByCustomDetail')
                }
                
                If($PSBoundParameters['GroupByEntity']){
                    $AlertRule.GroupingConfigurationGroupByEntity = $PSBoundParameters['GroupByEntity']
                    $null = $PSBoundParameters.Remove('GroupByEntity')
                }

                If($PSBoundParameters['EntityMapping']){
                    $AlertRule.EntityMapping = $PSBoundParameters['EntityMapping']
                    $null = $PSBoundParameters.Remove('EntityMapping')
                }

                If($PSBoundParameters['AlertDescriptionFormat']){
                    $AlertRule.AlertDetailOverrideAlertDescriptionFormat = $PSBoundParameters['AlertDescriptionFormat']
                    $null = $PSBoundParameters.Remove('AlertDescriptionFormat')
                }

                If($PSBoundParameters['AlertDisplayNameFormat']){
                    $AlertRule.AlertDetailOverrideAlertDisplayNameFormat = $PSBoundParameters['AlertDisplayNameFormat']
                    $null = $PSBoundParameters.Remove('AlertDisplayNameFormat')
                }

                If($PSBoundParameters['AlertSeverityColumnName']){
                    $AlertRule.AlertDetailOverrideAlertSeverityColumnName = $PSBoundParameters['AlertSeverityColumnName']
                    $null = $PSBoundParameters.Remove('AlertSeverityColumnName')
                }

                If($PSBoundParameters['AlertTacticsColumnName']){
                    $AlertRule.AlertDetailOverrideAlertTacticsColumnName = $PSBoundParameters['AlertTacticsColumnName']
                    $null = $PSBoundParameters.Remove('AlertTacticsColumnName')
                }

                If($PSBoundParameters['QueryFrequency']){
                    $AlertRule.QueryFrequency = $PSBoundParameters['QueryFrequency']
                    $null = $PSBoundParameters.Remove('QueryFrequency')
                }

                If($PSBoundParameters['QueryPeriod']){
                    $AlertRule.QueryPeriod = $PSBoundParameters['QueryPeriod']
                    $null = $PSBoundParameters.Remove('QueryPeriod')
                }

                If($PSBoundParameters['TriggerOperator']){
                    $AlertRule.TriggerOperator = $PSBoundParameters['TriggerOperator']
                    $null = $PSBoundParameters.Remove('TriggerOperator')
                }

                If($null -ne $PSBoundParameters['TriggerThreshold']){
                    $AlertRule.TriggerThreshold = $PSBoundParameters['TriggerThreshold']
                    $null = $PSBoundParameters.Remove('TriggerThreshold')
                }

                If($PSBoundParameters['EventGroupingSettingAggregationKind']){
                    $AlertRule.EventGroupingSettingAggregationKind = $PSBoundParameters['EventGroupingSettingAggregationKind']
                    $null = $PSBoundParameters.Remove('EventGroupingSettingAggregationKind')
                }
            }
            #TI
            if ($AlertRule.Kind -eq 'ThreatIntelligence'){
                If($PSBoundParameters['AlertRuleTemplateName']){
                    $AlertRule.AlertRuleTemplateName = $PSBoundParameters['AlertRuleTemplateName']
                    $null = $PSBoundParameters.Remove('AlertRuleTemplateName')
                }

                If($PSBoundParameters['Enabled']){
                    $AlertRule.Enabled = $true
                    $null = $PSBoundParameters.Remove('Enabled')
                }
                if($PSBoundParameters['Disabled']) {
                    $AlertRule.Enabled = $false
                    $null = $PSBoundParameters.Remove('Disabled')
                }
            }
            
            $null = $PSBoundParameters.Add('AlertRule', $AlertRule) 

            Az.SecurityInsights.internal\Update-AzSentinelAlertRule @PSBoundParameters
        }
        catch {
            throw
        }
    }
}

# SIG # Begin signature block
# MIInzwYJKoZIhvcNAQcCoIInwDCCJ7wCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA2NMuJqShvocXN
# yp8pdgl5s4U5qSvrKqaHJOG5O5iNBqCCDYUwggYDMIID66ADAgECAhMzAAADTU6R
# phoosHiPAAAAAANNMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI4WhcNMjQwMzE0MTg0MzI4WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDUKPcKGVa6cboGQU03ONbUKyl4WpH6Q2Xo9cP3RhXTOa6C6THltd2RfnjlUQG+
# Mwoy93iGmGKEMF/jyO2XdiwMP427j90C/PMY/d5vY31sx+udtbif7GCJ7jJ1vLzd
# j28zV4r0FGG6yEv+tUNelTIsFmmSb0FUiJtU4r5sfCThvg8dI/F9Hh6xMZoVti+k
# bVla+hlG8bf4s00VTw4uAZhjGTFCYFRytKJ3/mteg2qnwvHDOgV7QSdV5dWdd0+x
# zcuG0qgd3oCCAjH8ZmjmowkHUe4dUmbcZfXsgWlOfc6DG7JS+DeJak1DvabamYqH
# g1AUeZ0+skpkwrKwXTFwBRltAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUId2Img2Sp05U6XI04jli2KohL+8w
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzUwMDUxNzAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# ACMET8WuzLrDwexuTUZe9v2xrW8WGUPRQVmyJ1b/BzKYBZ5aU4Qvh5LzZe9jOExD
# YUlKb/Y73lqIIfUcEO/6W3b+7t1P9m9M1xPrZv5cfnSCguooPDq4rQe/iCdNDwHT
# 6XYW6yetxTJMOo4tUDbSS0YiZr7Mab2wkjgNFa0jRFheS9daTS1oJ/z5bNlGinxq
# 2v8azSP/GcH/t8eTrHQfcax3WbPELoGHIbryrSUaOCphsnCNUqUN5FbEMlat5MuY
# 94rGMJnq1IEd6S8ngK6C8E9SWpGEO3NDa0NlAViorpGfI0NYIbdynyOB846aWAjN
# fgThIcdzdWFvAl/6ktWXLETn8u/lYQyWGmul3yz+w06puIPD9p4KPiWBkCesKDHv
# XLrT3BbLZ8dKqSOV8DtzLFAfc9qAsNiG8EoathluJBsbyFbpebadKlErFidAX8KE
# usk8htHqiSkNxydamL/tKfx3V/vDAoQE59ysv4r3pE+zdyfMairvkFNNw7cPn1kH
# Gcww9dFSY2QwAxhMzmoM0G+M+YvBnBu5wjfxNrMRilRbxM6Cj9hKFh0YTwba6M7z
# ntHHpX3d+nabjFm/TnMRROOgIXJzYbzKKaO2g1kWeyG2QtvIR147zlrbQD4X10Ab
# rRg9CpwW7xYxywezj+iNAc+QmFzR94dzJkEPUSCJPsTFMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGaAwghmcAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAANNTpGmGiiweI8AAAAA
# A00wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHHk
# YqtvIOKoPkq+K49zAMaknWMIzGtztnIkCRLaKrPVMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEANK9Y5B8kub99ESea/h158pZdcOwvo3FNjJiC
# QNnvUPABIiOHmd3efzMWdWeyKEfWcjc11z4kvhaEAPOCzKQD5ZwOE+Tl6Ngl+eSt
# 6Frl2nvWWMjdS6eTH0TIQVJQ9vMoSqbHmqL/QjgLU0HG+qBdfndVsRkOsiJRHp2g
# lSEV+NZxHEEIi5nEtFsNymKefzbP055017YHsR2hSZs18l7aT4Jqz+GPixe9oG5+
# SBMJb4B87h+IFyYNKDmd4g0RsNwWNmREr/EEQlrscRjnH31sa4GToMuv3o4kI6OS
# dtoBpNVi5vrObRlL7Mau4Ku+RULu2Sb13oblWa5LgDXJbLtoBKGCFyowghcmBgor
# BgEEAYI3AwMBMYIXFjCCFxIGCSqGSIb3DQEHAqCCFwMwghb/AgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFXBgsqhkiG9w0BCRABBKCCAUYEggFCMIIBPgIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCArjeVfY5FVRkaR+rjlJwmYKKAdvslCBHHL
# GRPCDIvZDQIGZN+FrxyhGBEyMDIzMDkyMDA1NTAzOC4zWjAEgAIB9KCB2KSB1TCB
# 0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMk
# TWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjo4NkRGLTRCQkMtOTMzNTElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaCCEXswggcnMIIFD6ADAgECAhMzAAABtyEnGgei
# KoZGAAEAAAG3MA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwMB4XDTIyMDkyMDIwMjIxNFoXDTIzMTIxNDIwMjIxNFowgdIxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29m
# dCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRT
# UyBFU046ODZERi00QkJDLTkzMzUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDH/c9X
# UDQTZEwatxyXJcqY0HCSJQwIKb7MOLxyXtOp+d9kShpHJ9Fe6euTngNcDqDvvDbK
# KZ4z6VWfPuLP0YXTAjDT0CV6FnZFjqf96biBLNX8zwYEya3Zs3clGM6wJaCAmMe9
# toJnaWzX9z9MuWdoETuPLFiGMmHjSWHIfmXyc16qr7r6uxvDZvCDEIvGWsr8fuXU
# hgTOVWBwcQhI1xfRDekMOwOtEml4yo6I0qVJqWjOBZlXnPfOTzXUofITnj9rS+/N
# UgWp/dg09fbXzR7/R9BQJhNhxkcIsx5Cf/5gGXUtLOm4v1MDzJLAImuW6ZyAwTqG
# mHVpFdJVRuazdPpbUc/c45Wh/boXRkyflojSjq+5kZ5c2EAOd37UkiQarBKU8wr+
# 3Ou933b5bcd8uPD3q+r3OlEeXuJEmbB9eNSIcYZkUdkphGm7mCjk3Tu0P75bwH0M
# bhJyfdzS+C2FdSFsPDvsTTuoJY6waQjnzjk0IFiRfjOvyD8rmK3L+/S7u5XOu0vl
# PTBLtnaINDLiSKGAjIrlWl0ufhZjiYsn4gmZtFSbCee9MvZP7REHumkEfTMQ1tad
# hdx1nm6JV4/bLu866xJTZRwBL6RYXIKDJ4spTU4k2cy8FI+0x/N4J7oMNRQhFVYe
# VPZcDTDy9SBrs/91PkU/cGQgSWCKxST3epPFLQIDAQABo4IBSTCCAUUwHQYDVR0O
# BBYEFLPyOT4MNCQFYQ3WAdsjyCPJeLTsMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl
# 0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1T
# dGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4IC
# AQANnWTMm4VcUl02ycxYLzYjAlefwMp+VLsyVOPeWA7XHn6JXdHoUfUARgYR5gDL
# ddFmAh89lkFMjN5kA+CLB3xC9SRMIBvbRqu9bnJ/XZJywRw99Cb20EYSCnLxUp70
# QgqVaYpTPBf2GllwvVYm0nn/z1NhlgPtc7OuFRcSah3rsvCqq0MnxdtEgp3fM0WZ
# eGGAXI4fRtBo4SR1DwGBMdK/I0lo8otqNlgBw+gqaQbZMJ2Un+wOvAy+DsMAaZhQ
# d/r7m44DcGiAkvn5Blb0Zz9mYJpX52gGrPDMe4oCanIqqtEOgJ/tKx49ZMYrDXSI
# k8xZbuRsNnoV6S65efZL7JjjVQCR4Z3acd5/9K++kx/t1jUvVE/Y28UJBPrdrYYn
# +jCuZKxTJ5ASAgkfw1XFdasPbIOrDBKNMFkl5UGF73EFgOuXlc0pKLMpYSJSGWSy
# 9xh2Q9S0LQI6dgORewtyMODbewu2gwn6RcaJt2bpUZxSaJZTx297p4/YQPcb0Yip
# 1jADKUuDGQKIleDtvc1imXVM8oKe4A+FoyitdeSgidKLxHH/dgJ8DAFzJzbNaNCw
# rM4Prg5okGbOXke483Ss1Xxdc+23w2DTwCb5uaUkHW8t8CDrDf7LWIzPhJGj7VM6
# /DsjMKxvo6RTG7AeHHzerbyHhra7ZJTCRbZxevAnGWeSADCCB3EwggVZoAMCAQIC
# EzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoX
# DTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC
# 0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VG
# Iwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP
# 2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/P
# XfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361
# VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwB
# Sru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9
# X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269e
# wvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDw
# wvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr
# 9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+e
# FnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAj
# BgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+n
# FV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBH
# hkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
# BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4Swf
# ZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTC
# j/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu
# 2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/
# GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3D
# YXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbO
# xnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqO
# Cb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I
# 6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0
# zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaM
# mdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNT
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLXMIICQAIBATCCAQChgdikgdUwgdIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046ODZERi00QkJDLTkzMzUxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAMhnQRjDmzg5bBgWZklF
# 9qFoH6nGoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJ
# KoZIhvcNAQEFBQACBQDotNsgMCIYDzIwMjMwOTIwMTA0NDQ4WhgPMjAyMzA5MjEx
# MDQ0NDhaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOi02yACAQAwCgIBAAICCIcC
# Af8wBwIBAAICEdwwCgIFAOi2LKACAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYB
# BAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOB
# gQAlx4vbherzshJJAJgkO2OIxO+tXiibfMm6UyeVB11Zal/OY4nhzz76xVNlr11N
# /TG8uvjjqjynAsOqWFF0NESykhj388XYfp6LbgOmyz99BGBa9OumoM+TZn3m9ann
# UpbWGu3sDEbKxSrpny/SqDSlcNMlcWH6WANuzqkZJepK+TGCBA0wggQJAgEBMIGT
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABtyEnGgeiKoZGAAEA
# AAG3MA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwLwYJKoZIhvcNAQkEMSIEIKRjjkm2YXlmcZ/JSVTd6rTmmhUkKN8q90ynVDPJ
# 1b2uMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgbCd407Ie2i/ITXomBi+f
# /CAZ/M1H6+/0O65DPInNcEEwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAbchJxoHoiqGRgABAAABtzAiBCDQ7Ch4AEDQEU9Q3/G0MHVd
# HiVVYMkASPZ/G8ZpLCVVpDANBgkqhkiG9w0BAQsFAASCAgAtPMEiHAmsCk9MqmTm
# 5XY1S2lolAqbP3jtgpvaRrmR6LjKv8P1UVosK+ShUzrsztCc6j/uICa+DJvzRsgi
# n45Hs5IDELK8cUMjrv0lGg+Wtiz3rRXTVJkqHfw8gvduP0J9yhrQuK/42ZtMcUFZ
# Yro+Iv2oKz5n/tagBFrV9lGkwd+Ff+1SThS3e7HElInCrDa92nig6yFkxvUgNLXm
# 5uBooDpo2G/Zx07tgf9NgAkqAQqoocZmD/DQdfgjF2KeEZEVaQcxL5MExBZgTh78
# LXAx4o4paUSgJU2F/0hCcr2shqjFy+S0LbFBZaYypaaq0cYBUKCoLO5vG+SqUe6G
# 5bZofXJqsazFt+wnYpO0ksYaKI5pxx+kam9V3O55kDBEfOEvfHPikdW3ZH6kbwjb
# g4YYa+dFMTw0qWKZKgbAQPliI9c1mPAxJ836weQ42EuuaJmTWz/YbBex9vnaSAtu
# YKn48jp4RvXZWXQ6PpVFfg+gXv3vkYQn8d0JxmCZFX1EbPPPVwO1MGuArH6xyMJq
# ZoPxqbw+Bitm0xjoHDE2SajJzVd2XWOQoLn76LUdeSXSjy3XIEEyTvoCC978DNIA
# 09NOazevNoAlelrIgbGUoGOp/0Tn8cbzO0PVoSM3IpiMmDMyY8kn6JgOxLZJCl0l
# 6q3+xNdAL9TA0N2lMhqaSnzfnw==
# SIG # End signature block
