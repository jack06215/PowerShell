
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
Updates the data connector.
.Description
Updates the data connector.

.Link
https://learn.microsoft.com/powershell/module/az.securityinsights/update-azsentineldataconnector
#>
function Update-AzSentinelDataConnector {
    [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.CmdletBreakingChange("11.0.0", "4.0.0", "2023/11/15", ChangeDescription="ParameterSets AmazonWebServicesS3, Dynamics365, MicrosoftThreatIntelligence, MicrosoftThreatProtection, OfficeATP, OfficeIRM, ThreatIntelligenceTaxii will be deprecated.")]
    [OutputType([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.DataConnector])]
    [CmdletBinding(DefaultParameterSetName = 'UpdateAADAATP', PositionalBinding = $false, SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(ParameterSetName = 'UpdateAmazonWebServicesCloudTrail')]
        [Parameter(ParameterSetName = 'UpdateAmazonWebServicesS3')]
        [Parameter(ParameterSetName = 'UpdateAADAATP')]    
        [Parameter(ParameterSetName = 'UpdateAzureSecurityCenter')]
        [Parameter(ParameterSetName = 'UpdateDynamics365')]
        #[Parameter(ParameterSetName = 'UpdateGenericUI')]
        [Parameter(ParameterSetName = 'UpdateMicrosoftCloudAppSecurity')]
        [Parameter(ParameterSetName = 'UpdateMicrosoftDefenderAdvancedThreatProtection')]
        [Parameter(ParameterSetName = 'UpdateMicrosoftThreatIntelligence')]
        [Parameter(ParameterSetName = 'UpdateMicrosoftThreatProtection')]
        [Parameter(ParameterSetName = 'UpdateOffice365')]
        [Parameter(ParameterSetName = 'UpdateOfficeATP')]
        [Parameter(ParameterSetName = 'UpdateOfficeIRM')]
        [Parameter(ParameterSetName = 'UpdateThreatIntelligence')]
        [Parameter(ParameterSetName = 'UpdateThreatIntelligenceTaxii')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Path')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.DefaultInfo(Script = '(Get-AzContext).Subscription.Id')]
        [System.String]
        # Gets subscription credentials which uniquely identify Microsoft Azure subscription.
        # The subscription ID forms part of the URI for every service call.
        ${SubscriptionId},

        [Parameter(ParameterSetName = 'UpdateAmazonWebServicesCloudTrail', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateAmazonWebServicesS3', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateAADAATP', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateAzureSecurityCenter', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateDynamics365', Mandatory)]
        #[Parameter(ParameterSetName = 'UpdateGenericUI', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateMicrosoftCloudAppSecurity', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateMicrosoftDefenderAdvancedThreatProtection', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateMicrosoftThreatIntelligence', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateMicrosoftThreatProtection', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateOffice365', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateOfficeATP', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateOfficeIRM', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateThreatIntelligence', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateThreatIntelligenceTaxii', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Path')]
        [System.String]
        # The Resource Group Name.
        ${ResourceGroupName},

        [Parameter(ParameterSetName = 'UpdateAmazonWebServicesCloudTrail', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateAmazonWebServicesS3', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateAADAATP', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateAzureSecurityCenter', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateDynamics365', Mandatory)]
        #[Parameter(ParameterSetName = 'UpdateGenericUI', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateMicrosoftCloudAppSecurity', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateMicrosoftDefenderAdvancedThreatProtection', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateMicrosoftThreatIntelligence', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateMicrosoftThreatProtection', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateOffice365', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateOfficeATP', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateOfficeIRM', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateThreatIntelligence', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateThreatIntelligenceTaxii', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Path')]
        [System.String]
        # The name of the workspace.
        ${WorkspaceName},

        [Parameter(ParameterSetName = 'UpdateAmazonWebServicesCloudTrail', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateAmazonWebServicesS3', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateAADAATP', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateAzureSecurityCenter', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateDynamics365', Mandatory)]
        #[Parameter(ParameterSetName = 'UpdateGenericUI', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateMicrosoftCloudAppSecurity', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateMicrosoftDefenderAdvancedThreatProtection', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateMicrosoftThreatIntelligence', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateMicrosoftThreatProtection', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateOffice365', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateOfficeATP', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateOfficeIRM', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateThreatIntelligence', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateThreatIntelligenceTaxii', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Path')]
        [System.String]
        # The Id of the Data Connector.
        ${Id},

        [Parameter(ParameterSetName = 'UpdateViaIdentityAmazonWebServicesCloudTrail', Mandatory, ValueFromPipeline)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAmazonWebServicesS3', Mandatory, ValueFromPipeline)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAADAATP', Mandatory, ValueFromPipeline)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAzureSecurityCenter', Mandatory, ValueFromPipeline)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityDynamics365', Mandatory, ValueFromPipeline)]
        #[Parameter(ParameterSetName = 'UpdateViaIdentityGenericUI', Mandatory, ValueFromPipeline)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftCloudAppSecurity', Mandatory, ValueFromPipeline)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftDefenderAdvancedThreatProtection', Mandatory, ValueFromPipeline)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftThreatIntelligence', Mandatory, ValueFromPipeline)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftThreatProtection', Mandatory, ValueFromPipeline)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityOffice365', Mandatory, ValueFromPipeline)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityOfficeATP', Mandatory, ValueFromPipeline)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityOfficeIRM', Mandatory, ValueFromPipeline)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityThreatIntelligence', Mandatory, ValueFromPipeline)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityThreatIntelligenceTaxii', Mandatory, ValueFromPipeline)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Path')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.ISecurityInsightsIdentity]
        # Identity Parameter
        # To construct, see NOTES section for INPUTOBJECT properties and create a hash table.
        ${InputObject},

        [Parameter(ParameterSetName = 'UpdateAmazonWebServicesCloudTrail', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAmazonWebServicesCloudTrail', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        ${AWSCloudTrail},
        
        [Parameter(ParameterSetName = 'UpdateAmazonWebServicesS3', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAmazonWebServicesS3', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        ${AWSS3},
        
        [Parameter(ParameterSetName = 'UpdateAADAATP', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAADAATP', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        ${AzureADorAATP},
        
        [Parameter(ParameterSetName = 'UpdateAzureSecurityCenter', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAzureSecurityCenter', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        ${AzureSecurityCenter},
        
        [Parameter(ParameterSetName = 'UpdateDynamics365', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityDynamics365', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        ${Dynamics365},
        
        #[Parameter(ParameterSetName = 'UpdateGenericUI', Mandatory)]
        #[Parameter(ParameterSetName = 'UpdateViaIdentityGenericUI', Mandatory)]
        #[Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        #[System.Management.Automation.SwitchParameter]
        #${GenericUI},
        
        [Parameter(ParameterSetName = 'UpdateMicrosoftCloudAppSecurity', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftCloudAppSecurity', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        ${CloudAppSecurity},
        
        [Parameter(ParameterSetName = 'UpdateMicrosoftDefenderAdvancedThreatProtection', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftDefenderAdvancedThreatProtection', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        ${DefenderATP},

        [Parameter(ParameterSetName = 'UpdateMicrosoftThreatIntelligence', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftThreatIntelligence', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        ${MicrosoftTI},
        
        [Parameter(ParameterSetName = 'UpdateMicrosoftThreatProtection', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftThreatProtection', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        ${MicrosoftThreatProtection},
        
        [Parameter(ParameterSetName = 'UpdateOffice365', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityOffice365', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        ${Office365},
        
        [Parameter(ParameterSetName = 'UpdateOfficeATP', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityOfficeATP', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        ${OfficeATP},
        
        [Parameter(ParameterSetName = 'UpdateOfficeIRM', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityOfficeIRM', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        ${OfficeIRM},
        
        [Parameter(ParameterSetName = 'UpdateThreatIntelligence', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityThreatIntelligence', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        ${ThreatIntelligence},
        
        [Parameter(ParameterSetName = 'UpdateThreatIntelligenceTaxii', Mandatory)]
        [Parameter(ParameterSetName = 'UpdateViaIdentityThreatIntelligenceTaxii', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        ${ThreatIntelligenceTaxii},

        [Parameter(ParameterSetName = 'UpdateAADAATP')]
        [Parameter(ParameterSetName = 'UpdateDynamics365')]
        [Parameter(ParameterSetName = 'UpdateMicrosoftCloudAppSecurity')]
        [Parameter(ParameterSetName = 'UpdateMicrosoftDefenderAdvancedThreatProtection')]
        [Parameter(ParameterSetName = 'UpdateMicrosoftThreatIntelligence')]
        [Parameter(ParameterSetName = 'UpdateMicrosoftThreatProtection')]
        [Parameter(ParameterSetName = 'UpdateOffice365')]
        [Parameter(ParameterSetName = 'UpdateOfficeATP')]
        [Parameter(ParameterSetName = 'UpdateOfficeIRM')]
        [Parameter(ParameterSetName = 'UpdateThreatIntelligence')]
        [Parameter(ParameterSetName = 'UpdateThreatIntelligenceTaxii')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAmazonWebServicesCloudTrail')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAmazonWebServicesS3')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAADAATP')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAzureSecurityCenter')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityDynamics365')]
        #[Parameter(ParameterSetName = 'UpdateViaIdentityGenericUI')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftCloudAppSecurity')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftDefenderAdvancedThreatProtection')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftThreatIntelligence')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftThreatProtection')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityOffice365')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityOfficeATP')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityOfficeIRM')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityThreatIntelligence')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityThreatIntelligenceTaxii')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.DefaultInfo(Script = '(Get-AzContext).Tenant.Id')]
        [System.String]
        # The TenantId.
        ${TenantId},

        [Parameter(ParameterSetName = 'UpdateAzureSecurityCenter')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAzureSecurityCenter')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        # ASC Subscription Id.
        ${ASCSubscriptionId},

        [Parameter(ParameterSetName = 'UpdateAADAATP')]
        [Parameter(ParameterSetName = 'UpdateAzureSecurityCenter')]
        [Parameter(ParameterSetName = 'UpdateMicrosoftCloudAppSecurity')]
        [Parameter(ParameterSetName = 'UpdateMicrosoftDefenderAdvancedThreatProtection')]
        [Parameter(ParameterSetName = 'UpdateOfficeATP')]
        [Parameter(ParameterSetName = 'UpdateOfficeIRM')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAADAATP')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAzureSecurityCenter')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftCloudAppSecurity')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftDefenderAdvancedThreatProtection')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityOfficeATP')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityOfficeIRM')]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.DataTypeState])]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${Alerts},

        [Parameter(ParameterSetName = 'UpdateDynamics365')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityDynamics365')]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.DataTypeState])]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${CommonDataServiceActivity},

        [Parameter(ParameterSetName = 'UpdateMicrosoftCloudAppSecurity')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftCloudAppSecurity')]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.DataTypeState])]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${DiscoveryLog},

        [Parameter(ParameterSetName = 'UpdateMicrosoftThreatIntelligence')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftThreatIntelligence')]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.DataTypeState])]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${BingSafetyPhishinURL},

        [Parameter(ParameterSetName = 'UpdateMicrosoftThreatIntelligence')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftThreatIntelligence')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [ValidateSet('OneDay', 'OneWeek', 'OneMonth', 'All')]
        [System.String]
        ${BingSafetyPhishingUrlLookbackPeriod},

        [Parameter(ParameterSetName = 'UpdateMicrosoftThreatIntelligence')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftThreatIntelligence')]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.DataTypeState])]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${MicrosoftEmergingThreatFeed},

        [Parameter(ParameterSetName = 'UpdateMicrosoftThreatIntelligence')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftThreatIntelligence')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [ValidateSet('OneDay', 'OneWeek', 'OneMonth', 'All')]
        [System.String]
        ${MicrosoftEmergingThreatFeedLookbackPeriod},

        [Parameter(ParameterSetName = 'UpdateMicrosoftThreatProtection')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityMicrosoftThreatProtection')]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.DataTypeState])]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${Incident},

        [Parameter(ParameterSetName = 'UpdateOffice365')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityOffice365')]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.DataTypeState])]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${Exchange},

        [Parameter(ParameterSetName = 'UpdateOffice365')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityOffice365')]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.DataTypeState])]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${SharePoint},

        [Parameter(ParameterSetName = 'UpdateOffice365')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityOffice365')]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.DataTypeState])]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${Teams},

        [Parameter(ParameterSetName = 'UpdateThreatIntelligence')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityThreatIntelligence')]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.DataTypeState])]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${Indicator},

        [Parameter(ParameterSetName = 'UpdateThreatIntelligenceTaxii')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityThreatIntelligenceTaxii')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${WorkspaceId},

        [Parameter(ParameterSetName = 'UpdateThreatIntelligenceTaxii')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityThreatIntelligenceTaxii')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${FriendlyName},

        [Parameter(ParameterSetName = 'UpdateThreatIntelligenceTaxii', Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${APIRootURL},

        [Parameter(ParameterSetName = 'UpdateThreatIntelligenceTaxii')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityThreatIntelligenceTaxii')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${CollectionId},

        [Parameter(ParameterSetName = 'UpdateThreatIntelligenceTaxii')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityThreatIntelligenceTaxii')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${UserName},

        [Parameter(ParameterSetName = 'UpdateThreatIntelligenceTaxii')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityThreatIntelligenceTaxii')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${Password},

        [Parameter(ParameterSetName = 'UpdateThreatIntelligenceTaxii')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityThreatIntelligenceTaxii')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [ValidateSet('OneDay', 'OneWeek', 'OneMonth', 'All')]
        [System.String]
        ${TaxiiLookbackPeriod},

        [Parameter(ParameterSetName = 'UpdateThreatIntelligenceTaxii')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityThreatIntelligenceTaxii')]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.PollingFrequency])]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.PollingFrequency]
        ${PollingFrequency},

        [Parameter(ParameterSetName = 'UpdateAmazonWebServicesCloudTrail')]
        [Parameter(ParameterSetName = 'UpdateAmazonWebServicesS3')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAmazonWebServicesCloudTrail')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAmazonWebServicesS3')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${AWSRoleArn},

        [Parameter(ParameterSetName = 'UpdateAmazonWebServicesCloudTrail')]
        [Parameter(ParameterSetName = 'UpdateAmazonWebServicesS3')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAmazonWebServicesCloudTrail')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAmazonWebServicesS3')]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.DataTypeState])]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${Log},

        [Parameter(ParameterSetName = 'UpdateAmazonWebServicesS3')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAmazonWebServicesS3')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [String[]]
        ${SQSURL},

        [Parameter(ParameterSetName = 'UpdateAmazonWebServicesS3')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityAmazonWebServicesS3')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${DetinationTable},

        [Parameter(ParameterSetName = 'UpdateGenericUI')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityGenericUI')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${UiConfigTitle},

        [Parameter(ParameterSetName = 'UpdateGenericUI')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityGenericUI')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${UiConfigPublisher},

        [Parameter(ParameterSetName = 'UpdateGenericUI')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityGenericUI')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${UiConfigDescriptionMarkdown},

        [Parameter(ParameterSetName = 'UpdateGenericUI')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityGenericUI')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${UiConfigCustomImage},

        [Parameter(ParameterSetName = 'UpdateGenericUI')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityGenericUI')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [System.String]
        ${UiConfigGraphQueriesTableName},

        [Parameter(ParameterSetName = 'UpdateGenericUI')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityGenericUI')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.GraphQueries[]]
        ${UiConfigGraphQuery},

        [Parameter(ParameterSetName = 'UpdateGenericUI')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityGenericUI')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.SampleQueries[]]
        ${UiConfigSampleQuery},

        [Parameter(ParameterSetName = 'UpdateGenericUI')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityGenericUI')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.LastDataReceivedDataType[]]
        ${UiConfigDataType},

        [Parameter(ParameterSetName = 'UpdateGenericUI')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityGenericUI')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.ConnectivityCriteria[]]
        ${UiConfigConnectivityCriterion},

        [Parameter(ParameterSetName = 'UpdateGenericUI')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityGenericUI')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Bool]
        ${AvailabilityIsPreview},

        [Parameter(ParameterSetName = 'UpdateGenericUI')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityGenericUI')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.DefaultInfo(Script = 1)]
        [Int]
        ${AvailabilityStatus},

        [Parameter(ParameterSetName = 'UpdateGenericUI')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityGenericUI')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.PermissionsResourceProviderItem[]] 
        ${PermissionResourceProvider},

        [Parameter(ParameterSetName = 'UpdateGenericUI')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityGenericUI')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.PermissionsCustomsItem[]]
        ${PermissionCustom},

        [Parameter(ParameterSetName = 'UpdateGenericUI')]
        [Parameter(ParameterSetName = 'UpdateViaIdentityGenericUI')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.InstructionSteps[]]
        ${UiConfigInstructionStep},

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
            #Handle Get
            $GetPSBoundParameters = @{}
            if ($PSBoundParameters['InputObject']) {
                $GetPSBoundParameters.Add('InputObject', $PSBoundParameters['InputObject'])
            }
            else {
                $GetPSBoundParameters.Add('ResourceGroupName', $PSBoundParameters['ResourceGroupName'])
                $GetPSBoundParameters.Add('WorkspaceName', $PSBoundParameters['WorkspaceName'])
                $GetPSBoundParameters.Add('Id', $PSBoundParameters['Id'])
            }
            $DataConnector = Az.SecurityInsights\Get-AzSentinelDataConnector @GetPSBoundParameters


            if ($DataConnector.Kind -eq 'AzureActiveDirectory') {
                If ($PSBoundParameters['TenantId']) {
                    $DataConnector.TenantId = $PSBoundParameters['TenantId']
                    $null = $PSBoundParameters.Remove('TenantId')
                }
                If ($PSBoundParameters['Alerts']) {
                    $DataConnector.AlertState = $PSBoundParameters['Alerts']
                    $null = $PSBoundParameters.Remove('Alerts')
                }

                $null = $PSBoundParameters.Remove('AzureADorAATP')
            }
            if ($DataConnector.Kind -eq 'AzureAdvancedThreatProtection') {
                If ($PSBoundParameters['TenantId']) {
                    $DataConnector.TenantId = $PSBoundParameters['TenantId']
                    $null = $PSBoundParameters.Remove('TenantId')
                }
                If ($PSBoundParameters['Alerts']) {
                    $DataConnector.AlertState = $PSBoundParameters['Alerts']
                    $null = $PSBoundParameters.Remove('Alerts')
                }
                $null = $PSBoundParameters.Remove('AzureADorAATP')
            }
            if ($DataConnector.Kind -eq 'Dynamics365') {
                If ($PSBoundParameters['TenantId']) {
                    $DataConnector.TenantId = $PSBoundParameters['TenantId']
                    $null = $PSBoundParameters.Remove('TenantId')
                }

                If ($PSBoundParameters['CommonDataServiceActivity']) {
                    $DataConnector.Dynamics365CdActivityState = $PSBoundParameters['CommonDataServiceActivity']
                    $null = $PSBoundParameters.Remove('CommonDataServiceActivity')
                }
                $null = $PSBoundParameters.Remove('Dynamics365')
            }
            if ($DataConnector.Kind -eq 'MicrosoftCloudAppSecurity') {
                If ($PSBoundParameters['TenantId']) {
                    $DataConnector.TenantId = $PSBoundParameters['TenantId']
                    $null = $PSBoundParameters.Remove('TenantId')
                }

                If ($PSBoundParameters['Alerts']) {
                    $DataConnector.DataTypeAlertState = $PSBoundParameters['Alerts']
                    $null = $PSBoundParameters.Remove('Alerts')
                }

                If ($PSBoundParameters['DiscoveryLog']) {
                    $DataConnector.DiscoveryLogState = $PSBoundParameters['DiscoveryLog']
                    $null = $PSBoundParameters.Remove('DiscoveryLog')
                }
                $null = $PSBoundParameters.Remove('CloudAppSecurity')
            }
            if ($DataConnector.Kind -eq 'MicrosoftDefenderAdvancedThreatProtection') {
                If ($PSBoundParameters['TenantId']) {
                    $DataConnector.TenantId = $PSBoundParameters['TenantId']
                    $null = $PSBoundParameters.Remove('TenantId')
                }

                If ($PSBoundParameters['Alerts']) {
                    $DataConnector.AlertState = $PSBoundParameters['Alerts']
                    $null = $PSBoundParameters.Remove('Alerts')
                }
                $null = $PSBoundParameters.Remove('DefenderATP')
            }
            if ($DataConnector.Kind -eq 'MicrosoftThreatIntelligence') {
                If ($PSBoundParameters['TenantId']) {
                    $DataConnector.TenantId = $PSBoundParameters['TenantId']
                    $null = $PSBoundParameters.Remove('TenantId')
                }
                
                If ($PSBoundParameters['BingSafetyPhishinURL']) {
                    $DataConnector.BingSafetyPhishingUrlState = $PSBoundParameters['BingSafetyPhishinURL']
                    $null = $PSBoundParameters.Remove('BingSafetyPhishinURL')
                }

                If ($PSBoundParameters['BingSafetyPhishingUrlLookbackPeriod']) {
                    if ($PSBoundParameters['BingSafetyPhishingUrlLookbackPeriod'] -eq 'OneDay') {
                        $DataConnector.BingSafetyPhishingUrlLookbackPeriod = ((Get-Date).AddDays(-1).ToUniversalTime() | Get-DAte -Format yyyy-MM-ddTHH:mm:ss.fffZ).ToString()
                    }
                    elseif ($PSBoundParameters['BingSafetyPhishingUrlLookbackPeriod'] -eq 'OneWeek') {
                        $DataConnector.BingSafetyPhishingUrlLookbackPeriod = ((Get-Date).AddDays(-7).ToUniversalTime() | Get-DAte -Format yyyy-MM-ddTHH:mm:ss.fffZ).ToString()
                    }
                    elseif ($PSBoundParameters['BingSafetyPhishingUrlLookbackPeriod'] -eq 'OneMonth') {
                        $DataConnector.BingSafetyPhishingUrlLookbackPeriod = ((Get-Date).AddMonths(-1).ToUniversalTime() | Get-DAte -Format yyyy-MM-ddTHH:mm:ss.fffZ).ToString()
                    }
                    elseif ($PSBoundParameters['BingSafetyPhishingUrlLookbackPeriod'] -eq 'All') {
                        $DataConnector.BingSafetyPhishingUrlLookbackPeriod = "1970-01-01T00:00:00.000Z"
                    }
                    $null = $PSBoundParameters.Remove('BingSafetyPhishingUrlLookbackPeriod')
                }
                
                If ($PSBoundParameters['MicrosoftEmergingThreatFeed']) {
                    $DataConnector.MicrosoftEmergingThreatFeedState = $PSBoundParameters['MicrosoftEmergingThreatFeed']
                    $null = $PSBoundParameters.Remove('MicrosoftEmergingThreatFeed')
                }
                
                If ($PSBoundParameters['MicrosoftEmergingThreatFeedLookbackPeriod']) {
                    if ($PSBoundParameters['MicrosoftEmergingThreatFeedLookbackPeriod'] -eq 'OneDay') {
                        $DataConnector.MicrosoftEmergingThreatFeedLookbackPeriod = ((Get-Date).AddDays(-1).ToUniversalTime() | Get-DAte -Format yyyy-MM-ddTHH:mm:ss.fffZ).ToString()
                    }
                    elseif ($PSBoundParameters['MicrosoftEmergingThreatFeedLookbackPeriod'] -eq 'OneWeek') {
                        $DataConnector.MicrosoftEmergingThreatFeedLookbackPeriod = ((Get-Date).AddDays(-7).ToUniversalTime() | Get-DAte -Format yyyy-MM-ddTHH:mm:ss.fffZ).ToString()
                    }
                    elseif ($PSBoundParameters['MicrosoftEmergingThreatFeedLookbackPeriod'] -eq 'OneMonth') {
                        $DataConnector.MicrosoftEmergingThreatFeedLookbackPeriod = ((Get-Date).AddMonths(-1).ToUniversalTime() | Get-DAte -Format yyyy-MM-ddTHH:mm:ss.fffZ).ToString()
                    }
                    elseif ($PSBoundParameters['MicrosoftEmergingThreatFeedLookbackPeriod'] -eq 'All') {
                        $DataConnector.MicrosoftEmergingThreatFeedLookbackPeriod = "1970-01-01T00:00:00.000Z"
                    }
                    $null = $PSBoundParameters.Remove('MicrosoftEmergingThreatFeedLookbackPeriod')
                }
                $null = $PSBoundParameters.Remove('MicrosoftTI')
            }
            if ($DataConnector.Kind -eq 'MicrosoftThreatProtection') {
                If ($PSBoundParameters['TenantId']) {
                    $DataConnector.TenantId = $PSBoundParameters['TenantId']
                    $null = $PSBoundParameters.Remove('TenantId')
                }

                If ($PSBoundParameters['Incident']) {
                    $DataConnector.IncidentState = $PSBoundParameters['Incident']
                    $null = $PSBoundParameters.Remove('Incident')
                }
                $null = $PSBoundParameters.Remove('MicrosoftThreatProtection')
            }
            if ($DataConnector.Kind -eq 'Office365') {
                If ($PSBoundParameters['TenantId']) {
                    $DataConnector.TenantId = $PSBoundParameters['TenantId']
                    $null = $PSBoundParameters.Remove('TenantId')
                }

                If ($PSBoundParameters['Exchange']) {
                    $DataConnector.ExchangeState = $PSBoundParameters['Exchange']
                    $null = $PSBoundParameters.Remove('Exchange')
                }

                If ($PSBoundParameters['SharePoint']) {
                    $DataConnector.SharePointState = $PSBoundParameters['SharePoint']
                    $null = $PSBoundParameters.Remove('SharePoint')
                }

                If ($PSBoundParameters['Teams']) {
                    $DataConnector.TeamState = $PSBoundParameters['Teams']
                    $null = $PSBoundParameters.Remove('Teams')
                }
                $null = $PSBoundParameters.Remove('Office365')
            }
            if ($DataConnector.Kind -eq 'OfficeATP') {
                If ($PSBoundParameters['TenantId']) {
                    $DataConnector.TenantId = $PSBoundParameters['TenantId']
                    $null = $PSBoundParameters.Remove('TenantId')
                }
                
                If ($PSBoundParameters['Alerts']) {
                    $DataConnector.AlertState = $PSBoundParameters['Alerts']
                    $null = $PSBoundParameters.Remove('Alerts')
                }
                $null = $PSBoundParameters.Remove('OfficeATP')
            }
            if ($DataConnector.Kind -eq 'OfficeIRM') {
                If ($PSBoundParameters['TenantId']) {
                    $DataConnector.TenantId = $PSBoundParameters['TenantId']
                    $null = $PSBoundParameters.Remove('TenantId')
                }
                
                If ($PSBoundParameters['Alerts']) {
                    $DataConnector.AlertState = $PSBoundParameters['Alerts']
                    $null = $PSBoundParameters.Remove('Alerts')
                }
                $null = $PSBoundParameters.Remove('OfficeIRM')
            }
            if ($DataConnector.Kind -eq 'ThreatIntelligence') {
                If ($PSBoundParameters['TenantId']) {
                    $DataConnector.TenantId = $PSBoundParameters['TenantId']
                    $null = $PSBoundParameters.Remove('TenantId')
                }
                
                If ($PSBoundParameters['Indicator']) {
                    $DataConnector.IndicatorState = $PSBoundParameters['Indicator']
                    $null = $PSBoundParameters.Remove('Indicator')
                }
                $null = $PSBoundParameters.Remove('ThreatIntelligence')
            }
            if ($DataConnector.Kind -eq 'ThreatIntelligenceTaxii') {
                If ($PSBoundParameters['TenantId']) {
                    $DataConnector.TenantId = $PSBoundParameters['TenantId']
                    $null = $PSBoundParameters.Remove('TenantId')
                }

                If ($PSBoundParameters['FriendlyName']) {
                    $DataConnector.FriendlyName = $PSBoundParameters['FriendlyName']
                    $null = $PSBoundParameters.Remove('FriendlyName')
                }

                If ($PSBoundParameters['APIRootURL']) {
                    $DataConnector.TaxiiServer = $PSBoundParameters['APIRootURL']
                    $null = $PSBoundParameters.Remove('APIRootURL')
                }

                If ($PSBoundParameters['CollectionId']) {
                    $DataConnector.CollectionId = $PSBoundParameters['CollectionId']
                    $null = $PSBoundParameters.Remove('CollectionId')
                }

                If ($PSBoundParameters['UserName']) {
                    $DataConnector.UserName = $PSBoundParameters['UserName']
                    $null = $PSBoundParameters.Remove('UserName')
                }

                If ($PSBoundParameters['Password']) {
                    $DataConnector.Password = $PSBoundParameters['Password']
                    $null = $PSBoundParameters.Remove('Password')
                }

                If ($PSBoundParameters['WorkspaceId']) {
                    $DataConnector.WorkspaceId = $PSBoundParameters['WorkspaceId']
                    $null = $PSBoundParameters.Remove('WorkspaceId')
                }
                
                if ($PSBoundParameters['PollingFrequency']) {
                    if ($PSBoundParameters['PollingFrequency'] -eq 'OnceADay') {
                        $DataConnector.PollingFrequency = "OnceADay"
                    }
                    elseif ($PSBoundParameters['PollingFrequency'] -eq 'OnceAMinute') {
                        $DataConnector.PollingFrequency = "OnceAMinute"
                    }
                    elseif ($PSBoundParameters['PollingFrequency'] -eq 'OnceAnHour') {
                        $DataConnector.PollingFrequency = "OnceAnHour"
                    }
                    $null = $PSBoundParameters.Remove('PollingFrequency')
                }
                $null = $PSBoundParameters.Remove('ThreatIntelligenceTaxii')
            }
            if ($DataConnector.Kind -eq 'AzureSecurityCenter') {
                If ($PSBoundParameters['ASCSubscriptionId']) {
                    $DataConnector.SubscriptionId = $PSBoundParameters['ASCSubscriptionId']
                    $null = $PSBoundParameters.Remove('ASCSubscriptionId')
                }

                If ($PSBoundParameters['Alerts']) {
                    $DataConnector.AlertState = $PSBoundParameters['Alerts']
                    $null = $PSBoundParameters.Remove('Alerts')
                }
                $null = $PSBoundParameters.Remove('AzureSecurityCenter')
            }
            if ($DataConnector.Kind -eq 'AmazonWebServicesCloudTrail') {
                If ($PSBoundParameters['AWSRoleArn']) {
                    $DataConnector.AWSRoleArn = $PSBoundParameters['AWSRoleArn']
                    $null = $PSBoundParameters.Remove('AWSRoleArn')
                }

                If ($PSBoundParameters['Log']) {
                    $DataConnector.LogState = $PSBoundParameters['Log']
                    $null = $PSBoundParameters.Remove('Log')
                }
                $null = $PSBoundParameters.Remove('AWSCloudTrail')            
            }
            if ($DataConnector.Kind -eq 'AmazonWebServicesS3') {
                If ($PSBoundParameters['AWSRoleArn']) {
                    $DataConnector.AWSRoleArn = $PSBoundParameters['AWSRoleArn']
                    $null = $PSBoundParameters.Remove('AWSRoleArn')
                }

                If ($PSBoundParameters['Log']) {
                    $DataConnector.LogState = $PSBoundParameters['Log']
                    $null = $PSBoundParameters.Remove('Log')
                }
                
                If ($PSBoundParameters['SQSURL']) {
                    $DataConnector.SqsUrl = $PSBoundParameters['SQSURL']
                    $null = $PSBoundParameters.Remove('SQSURL')
                }
                If ($PSBoundParameters['DetinationTable']) {
                    $DataConnector.DestinationTable = $PSBoundParameters['DetinationTable']
                    $null = $PSBoundParameters.Remove('DetinationTable')
                }
                $null = $PSBoundParameters.Remove('AWSS3')
            }
            if ($DataConnector.Kind -eq 'GenericUI') {
                If ($PSBoundParameters['UiConfigTitle']) {
                    $DataConnector.ConnectorUiConfigTitle = $PSBoundParameters['UiConfigTitle']
                    $null = $PSBoundParameters.Remove('UiConfigTitle')
                }
                If ($PSBoundParameters['UiConfigPublisher']) {
                    $DataConnector.ConnectorUiConfigPublisher = $PSBoundParameters['UiConfigPublisher']
                    $null = $PSBoundParameters.Remove('UiConfigPublisher')
                }        
                If ($PSBoundParameters['UiConfigDescriptionMarkdown']) {
                    $DataConnector.ConnectorUiConfigDescriptionMarkdown = $PSBoundParameters['UiConfigDescriptionMarkdown']
                    $null = $PSBoundParameters.Remove('UiConfigDescriptionMarkdown')
                }
                If ($PSBoundParameters['UiConfigCustomImage']) {
                    $DataConnector.ConnectorUiConfigCustomImage = $PSBoundParameters['UiConfigCustomImage']
                    $null = $PSBoundParameters.Remove('UiConfigCustomImage')
                }
                If ($PSBoundParameters['UiConfigGraphQueriesTableName']) {
                    $DataConnector.ConnectorUiConfigGraphQueriesTableName = $PSBoundParameters['UiConfigGraphQueriesTableName']
                    $null = $PSBoundParameters.Remove('UiConfigGraphQueriesTableName')
                }
                If ($PSBoundParameters['UiConfigGraphQuery']) {
                    $DataConnector.ConnectorUiConfigGraphQuery = $PSBoundParameters['UiConfigGraphQuery']
                    $null = $PSBoundParameters.Remove('UiConfigGraphQuery')
                }
                If ($PSBoundParameters['UiConfigSampleQuery']) {
                    $DataConnector.ConnectorUiConfigSampleQuery = $PSBoundParameters['UiConfigSampleQuery']
                    $null = $PSBoundParameters.Remove('UiConfigSampleQuery')
                }
                If ($PSBoundParameters['UiConfigDataType']) {
                    $DataConnector.ConnectorUiConfigDataType = $PSBoundParameters['UiConfigDataType']
                    $null = $PSBoundParameters.Remove('UiConfigDataType')
                }
                If ($PSBoundParameters['UiConfigConnectivityCriterion']) {
                    $DataConnector.ConnectorUiConfigConnectivityCriterion = $PSBoundParameters['UiConfigConnectivityCriterion']
                    $null = $PSBoundParameters.Remove('UiConfigConnectivityCriterion')
                }
                If ($PSBoundParameters['AvailabilityIsPreview']) {
                    $DataConnector.AvailabilityIsPreview = $PSBoundParameters['AvailabilityIsPreview']
                    $null = $PSBoundParameters.Remove('AvailabilityIsPreview')
                }
                If ($PSBoundParameters['AvailabilityStatus']) {
                    $DataConnector.AvailabilityStatus = $PSBoundParameters['AvailabilityStatus']
                    $null = $PSBoundParameters.Remove('AvailabilityStatus')
                }
                If ($PSBoundParameters['PermissionResourceProvider']) {
                    $DataConnector.PermissionResourceProvider = $PSBoundParameters['PermissionResourceProvider']
                    $null = $PSBoundParameters.Remove('PermissionResourceProvider')
                }
                If ($PSBoundParameters['PermissionCustom']) {
                    $DataConnector.DestinationTable = $PSBoundParameters['PermissionCustom']
                    $null = $PSBoundParameters.Remove('PermissionCustom')
                }
                If ($PSBoundParameters['UiConfigInstructionStep']) {
                    $DataConnector.ConnectorUiConfigInstructionStep = $PSBoundParameters['UiConfigInstructionStep']
                    $null = $PSBoundParameters.Remove('UiConfigInstructionStep')
                }
            }
    
            $null = $PSBoundParameters.Add('DataConnector', $DataConnector)
            Az.SecurityInsights.internal\Update-AzSentinelDataConnector @PSBoundParameters
        }
        catch {
            throw
        }
    }
}
# SIG # Begin signature block
# MIIn0QYJKoZIhvcNAQcCoIInwjCCJ74CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDpZh5y3l55zqL3
# QO9A6jfDx9qV1Nkq3q0AvX+aSqwZ7aCCDYUwggYDMIID66ADAgECAhMzAAADTU6R
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
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGaIwghmeAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAANNTpGmGiiweI8AAAAA
# A00wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGWE
# tzCABExjiQnULe/bXAoY64R7CQY3rIaG64en2tTnMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAekFTXErePIF6bNYnryv3WpbJ+DRYv9MnsiKa
# +ofhYNkYPyJzj6STdqxWNPO88wpGyzDkrD+l9HvJdiQkXkhuujGipcNsxvrd76ZZ
# cILoX9W+DqiU5A0xLLJIWWjM9trA1rNeZjahOgyay0lGiT6e0kYOOBEf2cHMmAeE
# +bJYO3QEHoulhxZ09pzo3JT5cvgFPdlr9RDu3HxrTgY8tM0YJKG3kktTiPYItE0w
# rxCW1TiveAdRTBjFwRbtB1Y6eu/eSXMHpBaU2TLM1zpfs/gSwpEoJ9wXu6slGaFW
# XU2tdxGgQ3OLcK28uZ96O5kyt6vijoMCgmag6o5XtOH1HEkYwaGCFywwghcoBgor
# BgEEAYI3AwMBMYIXGDCCFxQGCSqGSIb3DQEHAqCCFwUwghcBAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCDOxOuxRZdgrjXCs5pMCLrW+YkYRFDyKZiF
# Uvz0hDHugQIGZN5nEXvtGBMyMDIzMDkyMDA1NTA0MC4xNzNaMASAAgH0oIHYpIHV
# MIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOjNCRDQtNEI4MC02OUMzMSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIRezCCBycwggUPoAMCAQICEzMAAAG0+4AI
# RAXSLfoAAQAAAbQwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTAwHhcNMjIwOTIwMjAyMjA5WhcNMjMxMjE0MjAyMjA5WjCB0jELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9z
# b2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjozQkQ0LTRCODAtNjlDMzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALRH
# pp5lBzJCH7zortuyvOmW8FoZLBsFe9g5dbhnaq9qSpvpn86E/mJ4JKvWixH/lw7Q
# A8gPtiiGVNIjvFhu/XiY889vX5WaQSmyoPMZdj9zvXa5XrkMN05zXzTePkCIIzF6
# RN7cTxezOyESymTIjrdxX5BVlZolyQAOxNziMCYKYYNPbYd0786fDE/PhzrRt23a
# 0Xf8trvFa0LEEy2YlcE2eqg2CjU/D0GZe8Ra0kjt0M12vdS4qWZ2Dpd7IhiQwnnt
# QWu19Ytd3UBR8SpeRX+Ccw3bjgWfOXtla6chctWt2shlMwayMOfY4TG4yMPWFXEL
# fZFFp7cgpjZNeVsmwkvoV6RAwy1Y9V+VvbJ5qFtartN/rp6a0I1kGlbjuwX3L0HT
# VXcikqgHistXk9h3HOZ9WgFXlxZurG1SZmcz0BEEdya+1vGHE45KguYU9qq2LiHG
# Bjn9z4+DqnV5tUKobsLbJMb4r+8st2fj8SacSsftnusxkWqEJiJS34P2uNlzVR03
# +ls6+ZO0NcO79LgP7BbIMipiOx8yh19PMQw0piaKFwOW7Q+gdJcfy6rOkG+CrYZw
# OzdiBHSebIzCIch2cAa+38w7JFP/koKdlJ36qzdVXWv4G/qZpWycIvDKYbxJWM40
# +z2Stg5uHqK3I8e09kFXtxCHpS7hm8c8m25WaEU5AgMBAAGjggFJMIIBRTAdBgNV
# HQ4EFgQUy0SF5fGUuDqcuxIot07eOMwy2X4wHwYDVR0jBBgwFoAUn6cVXQBeYl2D
# 9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1l
# LVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUB
# Af8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQAD
# ggIBABLRDwWMKbeCYqEqtI6Bs8KmF+kqDR+2G6qYAK3ZZ63bert7pCkRJbihFakt
# l2o18cdFJFxnOF4vXadm0sabskJ05KviEMJIO6dXSq8AGtr3Zmjc895q0mnlBLuN
# Mgk4R8KrkJMHqBuHqkUWXtfTrVUpgwzQt2UOiINKs+/b4r14MuXRVpOJ6cQOS8Uh
# keMAWl2iLlYaBGtOr3f/f9mLEPfWwoke0sSUbdV60OZCRh1ItBYYM9efKr14H5qu
# 6jan6n00prEEa7W3uGb/1/qj6P5emnvkqy5HI0X69DjVdLxVbjSsegm/dA+S4DaX
# PcfFf6iBxK/iV21l1upgEVVajUApl5VR40wY4XF8EpmnUdTqLXDf7CqdhDjPST2K
# /OjvWPyQGQvc7oPapYyk66GU32AOyyHXJj6+vbtRUg/+ory+h0R2Xf5NhC+xbWcM
# zXEUXRRf1YKZDsRyH6r412pm8KDKE/r7Rk7aoKK7oYUpNGzNRf6QaYv5z2bVTSxk
# zWivFrepLHGwvRun9PYM/8AQSTgZr0yzzjk/97WghkqCaAwAVpyvg3uaYnuCl/Ac
# cSkGyb8c+70bFSeUephsfgb2r+QI7Mb2WcOnkJpCNLz0XJMS/UwlQn1ktLsiCpsq
# Ok3aLJ2wTv6LK3u69I0vQB/LKRKlZYRXKUDXzoPwr3UtsTVTMIIHcTCCBVmgAwIB
# AgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1
# WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O
# 1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZn
# hUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t
# 1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxq
# D89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmP
# frVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSW
# rAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv
# 231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zb
# r17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYcten
# IPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQc
# xWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17a
# j54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3h
# LB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x
# 5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74p
# y27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1A
# oL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbC
# HcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB
# 9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNt
# yo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3
# rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcV
# v7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A24
# 5oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lw
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAtcwggJAAgEBMIIBAKGB2KSB1TCB
# 0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMk
# TWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjozQkQ0LTRCODAtNjlDMzElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAZZzYkPObl/ZzeCkS
# bf4B5CceCQiggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAN
# BgkqhkiG9w0BAQUFAAIFAOi0ZjswIhgPMjAyMzA5MjAwMjI2MDNaGA8yMDIzMDky
# MTAyMjYwM1owdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA6LRmOwIBADAKAgEAAgIL
# eAIB/zAHAgEAAgIRgTAKAgUA6LW3uwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUA
# A4GBAKPU3OAqjDPlJkQJ5I+LMsKSS1tGXs44sRE+8J+szoz//Tk4WKtX6ldo58lr
# iQbG8LeyZcPBQ3t3EHgZAIi4L4cVcR6DZz2z6vsC+F7QUqo4/1eVGFgu80GqfV5V
# fQN5IYwrJOOrQTOcmvMxFayse7bF9nFK9+gXUi3xlHX00q2wMYIEDTCCBAkCAQEw
# gZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAG0+4AIRAXSLfoA
# AQAAAbQwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0B
# CRABBDAvBgkqhkiG9w0BCQQxIgQg6VMwhgzR8g488AC8zsr/JFyFlJzYvbxzpz4o
# 9dzLstIwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCDTyPd75qMwcAZRcb36
# /6xJa3hT0eLse71ysdp4twH3BjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABtPuACEQF0i36AAEAAAG0MCIEIGaiH7IAIAhdfdbwnTE6
# WDqLwhvDhkdUQq735Bd4jF/uMA0GCSqGSIb3DQEBCwUABIICABe+axzOEwxaCSjG
# 8Ae+ByYBVmToBmftvb5bTTVNkC+solSwZuzJRTU2/iycD8xxYuKhEOrexMkK3q2X
# zRHJ/RMk8JdhNgnZZWeWavNSOoenpShabvvMRIJDeTab6SSolGVAMUMuQwENtrd7
# HKDOKI/rFBCtz61+NE2g63t0wOfTn9n3xsC+0ZDPAqXuCJrSaG8jF2jnLFoVxfNW
# sDNnk5fnXanlldnynqxZCx5GC98PNBDwaxJjz9KmlUeJu8GaxaCsC2PGJXWtN0x3
# jGkWmbkjMtBWmx8pPvtIsj7MvVsD6g4hxcncG8HA9KrvkEqGycB9vt6cHceXSSk5
# 3ZSdS8AF84zr61EIZJAjL3GuRHDYu1G+aya3hexX16zCsdG3zsbjoqfLFhTRJRlj
# Vc0oJsUoj0u2hVsF5Wp+0Vi8ia+ff6Rw5l7By/ob7uzPmJ+xEUrFFpYB0eWYFzSG
# fjI1D9wLEjIK75QCvhI5nHeBXuFjR5IN8Sh2e1v1TjAZvcAXFIdCPDsZlKnRvurm
# fmuCAEqomrhy6w5Hy+PEP6rFe1cQH+NpQnTIgijt3TmFUWpMpXnVmp6qfHV7FnYp
# 8sBcnffv1xPRpRwqv4RB7rHTDqpDctuEMLkgigChABSvAo6ngqhr4CijODlLwxDx
# AGjRzczQx1AcJivJdzalLAKnmZJ5
# SIG # End signature block
