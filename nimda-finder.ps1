<#
    .SYNOPSIS
        Portion ADsearch comes from here :
        - http://blogs.technet.com/b/askpfeplat/archive/2013/04/08/audit-membership-in-privileged-active-directory-groups-a-second-look.aspx
        - http://gallery.technet.microsoft.com/scriptcenter/List-Membership-In-bff89703
      
        - Listing of all Enterprise and Domain Administrator account 
        - Write all account in a flat file
        - Each rescan it compares it to the new output
        - Sends an email for each new account
        - Delete the flat file to startover

        RSAT TOOL ADFS MUST BE INSTALLED TO GET THE USER INFORMATION
        Information here :
        https://www.techjunkie.com/install-active-directory-users-computers-windows-10/

    .INPUTS

    .OUTPUTS
        
    .NOTES
        Version:        1.0
        Author:         Ugo Deschamps
        Creation Date:  2019/12/16
        Purpose/Change: Creation

        Usage : CHANGE the configuration options


                Launch a first time to create the flat file
                After the file is created, it will start to compare it

                Create a scheduled task each, X hours to make ru nthe scan
                $FLAT_FILE, $sendTO, $sendFROM, $SendEmail, $msgSubject, $smtpserver
#>

#########################################################################
$FLAT_FILE = "<FILENAME>"
$sendTO = "<INSERT EMAIL>"
$sendFROM = "<INSERT EMAIL>"
$SendEmail = $true
$msgSubject = "<INSERT SUBJECT>"
$smtpserver= "<INSERT SMTP SERVER>"
#########################################################################


#Set this to remove un nescessary error outputs on some object being null
$ErrorActionPreference = 'Continue'
#-------------------------------------------------------------

##################   Function to Expand Group Membership ################
function getMemberExpanded
{
  param ($dn)

  $colOfMembersExpanded=@()
  $adobject = [adsi]"LDAP://$dn"
  try {
  $colMembers = $adobject.properties.item("member")
}
catch{
  #Silent error pour les domaines non joignable
}
  Foreach ($objMember in $colMembers)
  {
    $objMembermod = $objMember.replace("/","\/")
    $objAD = [adsi]"LDAP://$objmembermod"
    $attObjClass = $objAD.properties.item("objectClass")
    
    if ($attObjClass -eq "group") { getmemberexpanded $objMember }   
    else { $colOfMembersExpanded += $objMember }
  }    
  $colOfMembersExpanded 
}    

########################### Function to Calculate Password Age ##############
Function getUserAccountAttribs
{
  param($objADUser,$parentGroup)
	$objADUser = $objADUser.replace("/","\/")
  $adsientry=new-object directoryservices.directoryentry("LDAP://$objADUser")
  $adsisearcher=new-object directoryservices.directorysearcher($adsientry)
  $adsisearcher.pagesize=1000
  $adsisearcher.searchscope="base"
  $colUsers=$adsisearcher.findall()
  foreach($objuser in $colUsers)
  {
	  $sam = $objuser.properties.item("samaccountname")
    $attObjClass = $objuser.properties.item("objectClass")
    
    If ($attObjClass -eq "user")
		{
      If (($objuser.properties.item("lastlogontimestamp") | Measure-Object).Count -gt 0) 
      {
        $lastlogontimestamp = $objuser.properties.item("lastlogontimestamp")[0]
        $lastLogon = [System.DateTime]::FromFileTime($lastlogontimestamp)
        $lastLogonInDays = ((Get-Date) - $lastLogon).Days
        
        if ($lastLogon -match "1/01/1601") 
        {
          $lastLogon = "1901/01/01 00:00:00"
          $lastLogonInDays = "-1"
        }
      } 
      else 
      {
        $lastLogon = "1901/01/01 00:00:00"
        $lastLogonInDays = "-1"
      }

      $pwdLastSet=$objuser.properties.item("pwdLastSet")
      
      if ($pwdLastSet -gt 0)
      {
        $pwdLastSet = [datetime]::fromfiletime([int64]::parse($pwdLastSet))
        $PasswordAge = ((get-date) - $pwdLastSet).days
      }
      Else {$PasswordAge = "-1"}                                                                        

    }                                                        
    
    $record = "" | select-object SamAccountName,PasswordAge,MemberOf
    $record.SamAccountName = [string]$sam
    $record.PasswordAge = $PasswordAge
    $record.MemberOf = [string]$parentGroup
  } 
  $record
}
####### Function to find all Privileged Groups in the Forest ##########
Function getForestPrivGroups
{
  # Privileged Group Membership for the following groups:
  # - Domain Admins - SID: S-1-5-21domain-512
  # Reference: http://support.microsoft.com/kb/243330

  $colOfDNs = @()
  $Forest = [System.DirectoryServices.ActiveDirectory.forest]::getcurrentforest()
	$RootDomain = [string]($forest.rootdomain.name)
	$forestDomains = $forest.domains
	$colDomainNames = @()
  
  ForEach ($domain in $forestDomains)
	{
	  $domainname = [string]($domain.name)
		$colDomainNames += $domainname
	}
		
  $ForestRootDN = FQDN2DN $RootDomain
	$colDomainDNs = @()
  
  ForEach ($domainname in $colDomainNames)
	{
	  $domainDN = FQDN2DN $domainname
		$colDomainDNs += $domainDN	
	}

	$GC = $forest.FindGlobalCatalog()
  $adobject = [adsi]"GC://$ForestRootDN"
  $RootDomainSid = New-Object System.Security.Principal.SecurityIdentifier($AdObject.objectSid[0], 0)
	$RootDomainSid = $RootDomainSid.toString()
	$colDASids = @()
  
  ForEach ($domainDN in $colDomainDNs)
	{
	  $adobject = [adsi]"GC://$domainDN"
    $DomainSid = New-Object System.Security.Principal.SecurityIdentifier($AdObject.objectSid[0], 0)
		$DomainSid = $DomainSid.toString()
		$daSid = "$DomainSID-512"
		$colDASids += $daSid
	}

  $colPrivGroups = @("$rootDomainSid-519")
	$colPrivGroups += $colDASids
  $searcher = $gc.GetDirectorySearcher()
  
  ForEach($privGroup in $colPrivGroups)
  {
    $searcher.filter = "(objectSID=$privGroup)"
    $Results = $Searcher.FindAll()
    
    ForEach ($result in $Results)
    {
      $dn = $result.properties.distinguishedname
      $colOfDNs += $dn
    }
  }

  $colofDNs
}

########################## Function to Generate Domain DN from FQDN ########
Function FQDN2DN
{
	Param ($domainFQDN)
	$colSplit = $domainFQDN.Split(".")
	$FQDNdepth = $colSplit.length
	$DomainDN = ""
	For ($i=0;$i -lt ($FQDNdepth);$i++)
	{
		If ($i -eq ($FQDNdepth - 1)) {$Separator=""}
		else {$Separator=","}
		[string]$DomainDN += "DC=" + $colSplit[$i] + $Separator
	}
	$DomainDN
}
Function Get-AllPrivUsers{

  ########################## MAIN ###########################

  $forestPrivGroups = GetForestPrivGroups
  $colAllPrivUsers = @()

  Foreach ($privGroup in $forestPrivGroups)
  {
    Write-Host "Enumerating $privGroup.." -foregroundColor yellow
    $uniqueMembers = @()
    $colofUniqueMembers = @()
    $members = getmemberexpanded $privGroup
    If ($members){
      $uniqueMembers = $members | sort-object -unique
      Foreach ($uniqueMember in $uniqueMembers){
        $objAttribs = getUserAccountAttribs $uniqueMember $privGroup
        $colOfuniqueMembers += $objAttribs      
      }
      $colAllPrivUsers += $colOfUniqueMembers
    }
  }
  return $colAllPrivUsers
}
Function Get-Domain-from-MemberOf{
  Param ($MemberOf)

      #Cut au premier DC="
      $separator = ",DC="

      $str_unified = $MemberOf.Split($separator)
      
      $str_formated = ""
      for($i = $str_unified.Count -1 ; $i -gt 0; $i--){
          if( $str_unified[$i].indexof("=") -ne -1) { break }
          
          if ($i -eq $str_unified.Count -1) { $str_formated = $str_unified[$i] }
          else { $str_formated = $str_unified[$i] + "." + $str_formated }
  
          
      }

      return $str_formated
}

Function Send_EmailLog{
  Param(
    $user
  )

  $Domain = Get-Domain-from-MemberOf $user.MemberOf
  $SamAccountName = $user.SamAccountName
  $aduser = Get-ADUser -Filter {SamAccountName -like $SamAccountName} -Server $Domain -Properties *

  $MailMsg = @"
  ------------------------------------------
  New Domain Administrator rights detected 
  ------------------------------------------
  DisplayName     : {1}
  Domain          : {10}
  CanonicalName   : {0}  
  Enabled         : {2}
  LastLogonDate   : {3}
  Modified        : {4}
  ModifiedTS      : {5}
  PasswordLastSet : {6}
  SamAccountName  : {7}
  WhenChanged     : {8}
  WhenCreated     : {9}
"@

  $MailMsg = $MailMsg -f $aduser.CanonicalName, $aduser.DisplayName, $aduser.Enabled, $aduser.LastLogonDate,
                          $aduser.Modified, $aduser.ModifiedTS, $aduser.PasswordLastSet, $aduser.SamAccountName,
                          $aduser.WhenChanged, $aduser.WhenCreated, $Domain
  write-host -ForegroundColor Green $MailMsg
  Send-MailMessage -From $sendFROM -To $sendTO -Body $MailMsg -SmtpServer $smtpserver

}

#Start du log
$logfile = $MyInvocation.MyCommand.path -replace '\.ps1$', '.log'
Start-Transcript -path $logfile

$banner = @"
---- CONFIGURATION ----
Flat file   : $FLAT_FILE
Send to     : $sendTO 
Send From   : $sendFROM 
Send email? : $SendEmail
Email Subj  : $msgSubject
SMTP Server : $smtpserver
-----------------------
"@

Write-Host -ForegroundColor Cyan $banner

#Get-HighPriv Account listing
$colAllPrivUsers = Get-AllPrivUsers

if (Test-Path $PSScriptRoot"\"$FLAT_FILE){ 
  $existing = Get-Content -Path $PSScriptRoot"\"$FLAT_FILE

  foreach ($item in $colAllPrivUsers) {
    if (!($existing.Contains( $item.SamAccountName + "|" + $item.MemberOf )) ){
        $msg = "NEW DOMAIN ADMIN DETECTED : " + $item.SamAccountName + " " + $item.MemberOf 
        Write-host -ForegroundColor red  $msg

        if ($sendEmail = $true) {Send_EmailLog $item }
    }
  }   
}
else{
  #First run, create file
  $colAllPrivUsers = $colAllPrivUsers | Sort-Object

  #add information to file
  foreach ($item in $allPrivUsers) {
    $data = $item.SamAccountName + "|" + $item.MemberOf
    Add-Content -Path $PSScriptRoot"\"$FLAT_FILE $data
  }
}


Stop-Transcript

