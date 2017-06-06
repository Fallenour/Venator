$comments = @' 
Script name: Powershell Script, Security Operation Center Multitool Interface, Powershell Version
Created on: Tuesday, February 21th, 2017 
Author: Logan Hicks 
Purpose: Security Operations Center Multi-purpose
'@










##   Automated Analysis Function, see script Automated Security Analysis.ps1   ##


Function AutomatedAnalysis
{
    
$IP = Read-Host -Prompt 'Input IP Address'
$ForiegnIP = Read-Host -Prompt 'Input External IP Address'
$VirusTotalIP = Read-Host -Prompt 'Please Input VirusTotal IP Address to be Scanned.'
$SourceDestinationSplunkSearch = " https://XXX.XXX.XXX.XXX:XXXX/en-US/app/search?q=search%20$IP%20$ForiegnIP&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-4h&latest=now "
$FirewallIndexSplunkSearch = " https://XXX.XXX.XXX.XXX:XXXX/en-US/app/search?q=search%20$ForiegnIP%20index%3Dfirewall%20%7C%20table%20_time%20src_ip%20src_port%20dest_ip%20dest_port%20msg%20action%20bytes_in&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-4h&latest=now "
$CiscoASASplunkSearch = " https://XXX.XXX.XXX.XXX:XXXX/en-US/app/search?q=search%20sourcetype%3Dcisco%3Aasa%20$IP%20$ForiegnIP%20url%20%7Ctable%20_time%20src_ip%20src_port%20dest_ip%20dest_port%20msg%20action%20bytes_in&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-4h&latest=now&display.page.search.tab=statistics&display.general.type=statistics "
$PanThreatSplunkSearch = " https://XXX.XXX.XXX.XXX:XXXX/en-US/app/search?q=search%20sourcetype%3Dpan%3Athreat%20$IP%20$ForiegnIP%20url%20%7Ctable%20_time%20src_ip%20src_port%20dest_ip%20dest_port%20msg%20action%20bytes_in&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-4h&latest=now&display.page.search.tab=statistics&display.general.type=statistics "
$BroSplunkSearch = " https://XXX.XXX.XXX.XXX:XXXX/en-US/app/search?q=search%20index%3Dbro%20$IP%20$ForiegnIP%20url%20%7Ctable%20_time%20src_ip%20src_port%20dest_ip%20dest_port%20msg%20action%20bytes_in&display.page.search.mode=smart&dispatch.sample_ratio=1&earliest=-4h&latest=now&display.page.search.tab=statistics&display.general.type=statistics "
$uname = read-host -Prompt 'Please Enter Username.'
$passwd = read-host -Prompt 'Please Enter Password.' -AsSecureString
$decodepasswd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwd))
$Date = Get-Date -format yyyy-MM-dd
$DateYear = Get-Date -format yyyy
$DateMonth = Get-Date -format MM
$DateDay = Get-date -format dd
$BroDirectoryNavigation = " cd /logs/bro/logs "
$BroDirectorynavigationLogs = " cd $Date "
$BroSearchFilesAll = " less files.* | bro-cut -d ts tx_hosts rx_hosts filename duration seen_bytes total_bytes missing_bytes | grep $VirusTotalIP "










## Start Chrome Process and run Splunk Searches ##


Start-Process "chrome.exe" -ArgumentList "$SourceDestinationSplunkSearch"










## Start Chrome Process and run Splunk Searches ##


Start-Process "chrome.exe" -ArgumentList "$FirewallIndexSplunkSearch"


sleep 15










##   Capture Screenshot of Splunk Firewall Search and save it to SplunkFW.bmp   ##


[Reflection.Assembly]::LoadWithPartialName("System.Drawing")


function screenshot([Drawing.Rectangle]$SplunkFW, $path)
 {
   $bmp = New-Object Drawing.Bitmap $SplunkFW.width, $SplunkFW.height
   $graphics = [Drawing.Graphics]::FromImage($bmp)


   $graphics.CopyFromScreen($SplunkFW.Location, [Drawing.Point]::Empty, $SplunkFW.size)


   $bmp.Save($path)


   $graphics.Dispose()
   $bmp.Dispose()
}


$SplunkFW = [Drawing.Rectangle]::FromLTRB(0, 0, 1000, 900)
screenshot $SplunkFW "C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\Other\screenshotsplunkfw.bmp"










## Start Chrome Process and run Splunk Searches ##


Start-Process "chrome.exe" -ArgumentList "$CiscoASASplunkSearch"


sleep 15










##   Capture Screenshot of Splunk Firewall Search and save it to SplunkCiscoASA.bmp   ##


[Reflection.Assembly]::LoadWithPartialName("System.Drawing")


function screenshot([Drawing.Rectangle]$SplunkCiscoASA, $path)
 {
   $bmp = New-Object Drawing.Bitmap $SplunkCiscoASA.width, $SplunkCiscoASA.height
   $graphics = [Drawing.Graphics]::FromImage($bmp)


   $graphics.CopyFromScreen($SplunkCiscoASA.Location, [Drawing.Point]::Empty, $SplunkCiscoASA.size)


   $bmp.Save($path)


   $graphics.Dispose()
   $bmp.Dispose()
}


$SplunkCiscoASA = [Drawing.Rectangle]::FromLTRB(0, 0, 1000, 900)
screenshot $SplunkCiscoASA "C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\Other\screenshotsplunkCiscoASA.bmp"








## Start Chrome Process and run Splunk Searches ##


Start-Process "chrome.exe" -ArgumentList "$PanThreatSplunkSearch"


sleep 15












##   Capture Screenshot of Splunk Firewall Search and save it to SplunkPanThreat.bmp   ##


[Reflection.Assembly]::LoadWithPartialName("System.Drawing")


function screenshot([Drawing.Rectangle]$SplunkPanThreat, $path)
 {
   $bmp = New-Object Drawing.Bitmap $SplunkPanThreat.width, $SplunkPanThreat.height
   $graphics = [Drawing.Graphics]::FromImage($bmp)


   $graphics.CopyFromScreen($SplunkPanThreat.Location, [Drawing.Point]::Empty, $SplunkPanThreat.size)


   $bmp.Save($path)


   $graphics.Dispose()
   $bmp.Dispose()
}


$SplunkPanThreat = [Drawing.Rectangle]::FromLTRB(0, 0, 1000, 900)
screenshot $SplunkPanThreat "C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\Other\screenshotSplunkPanThreat.bmp"










## Start Chrome Process and run Splunk Searches ##


Start-Process "chrome.exe" -ArgumentList "$BroSplunkSearch"


sleep 15










##   Capture Screenshot of Splunk Firewall Search and save it to SplunkBro.bmp   ##


[Reflection.Assembly]::LoadWithPartialName("System.Drawing")


function screenshot([Drawing.Rectangle]$SplunkBro, $path)
 {
   $bmp = New-Object Drawing.Bitmap $SplunkBro.width, $SplunkBro.height
   $graphics = [Drawing.Graphics]::FromImage($bmp)


   $graphics.CopyFromScreen($SplunkBro.Location, [Drawing.Point]::Empty, $SplunkBro.size)


   $bmp.Save($path)


   $graphics.Dispose()
   $bmp.Dispose()
}


$SplunkBro = [Drawing.Rectangle]::FromLTRB(0, 0, 1000, 900)
screenshot $SplunkBro "C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\Other\screenshotSplunkBro.bmp"










## Opens Chrome for Ipvoid ##


$Chrome = Start-Process "chrome.exe" ` -ArgumentList "http://www.ipvoid.com/ip-blacklist-check/";


[Microsoft.VisualBasic.Interaction]::AppActivate(“$Chrome”)


sleep 1


[System.Windows.Forms.SendKeys]::SendWait(“{TAB}{TAB}{TAB}{TAB}{TAB}{TAB}{TAB}”)


sleep 1


[System.Windows.Forms.SendKeys]::SendWait(“$ForiegnIP”)


[System.Windows.Forms.SendKeys]::SendWait(“{ENTER}”)




Sleep 10






### Added test content for screenshots   ###












[Reflection.Assembly]::LoadWithPartialName("System.Drawing")


function screenshot([Drawing.Rectangle]$IPVoidPic, $path)
 {
   $bmp = New-Object Drawing.Bitmap $IPVoidPic.width, $IPVoidPic.height
   $graphics = [Drawing.Graphics]::FromImage($bmp)


   $graphics.CopyFromScreen($IPVoidPic.Location, [Drawing.Point]::Empty, $IPVoidPic.size)


   $bmp.Save($path)


   $graphics.Dispose()
   $bmp.Dispose()
}


$IPVoidPic = [Drawing.Rectangle]::FromLTRB(0, 0, 1000, 900)
screenshot $IPVoidPic "C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\IPVoid\screenshotIPVoid.bmp"








#### End of Test Content for Screenshots   ###




## Opens Chrome for VirusTotal ##


Start-Process "chrome.exe" https://virustotal.com/en/ip-address/$VirusTotalIP/information/


Sleep 1










##   Opens Chrome for MxToolBox BlackList Check   ##


$Chrome = Start-Process "chrome.exe" ` -ArgumentList "https://mxtoolbox.com/SuperTool.aspx?action=blacklist:$ForiegnIP&run=problempage";


[Microsoft.VisualBasic.Interaction]::AppActivate(“$Chrome”)


[System.Windows.Forms.SendKeys]::SendWait(“{SPACE}”)




Sleep 1










##   Opens Chrome for SpamHaus BlackList Check   ##


$Chrome = Start-Process "chrome.exe" ` -ArgumentList "https://www.spamhaus.org/query/ip/$ForiegnIP";


[Microsoft.VisualBasic.Interaction]::AppActivate(“$Chrome”)










## Start Putty Process, Open Putty Session, Enter IP Address of Bro Box, navigate to current day directory, execute bro search via bro-cut from $BroSearchFileAll ##


$putty = Start-Process -FilePath "C:\Users\logan hicks\Downloads\Software\putty.exe" ` -ArgumentList 'XXX.XXX.XXX.XXX'


start-sleep -Milliseconds 1000


[Microsoft.VisualBasic.Interaction]::AppActivate(“$putty”)


[System.Windows.Forms.SendKeys]::SendWait(“$uname”)


[System.Windows.Forms.SendKeys]::SendWait(“{ENTER}”)


start-sleep -Milliseconds 800


[System.Windows.Forms.SendKeys]::SendWait(“$decodepasswd”)


[System.Windows.Forms.SendKeys]::SendWait(“{ENTER}”)


start-sleep -Milliseconds 800


[System.Windows.Forms.SendKeys]::SendWait(“$BroDirectoryNavigation”)


[System.Windows.Forms.SendKeys]::SendWait(“{ENTER}”)


start-sleep -Milliseconds 800


[System.Windows.Forms.SendKeys]::SendWait(“$BroDirectorynavigationLogs”)


[System.Windows.Forms.SendKeys]::SendWait(“{ENTER}”)


start-sleep -Milliseconds 800


[System.Windows.Forms.SendKeys]::SendWait(“$BroSearchFilesAll”)


[System.Windows.Forms.SendKeys]::SendWait(“{ENTER}”)










## Start Putty Process, Open Putty Session, Enter IP Address of Bro Box, navigate to current day directory, execute bro search via bro-cut from $BroSearchFileAll ##


$putty = Start-Process -FilePath "C:\Users\logan hicks\Downloads\Software\putty.exe" ` -ArgumentList 'XXX.XXX.XXX.XXX'


start-sleep -Milliseconds 800


[Microsoft.VisualBasic.Interaction]::AppActivate(“$putty”)


[System.Windows.Forms.SendKeys]::SendWait(“$uname”)


[System.Windows.Forms.SendKeys]::SendWait(“{ENTER}”)


start-sleep -Milliseconds 800


[System.Windows.Forms.SendKeys]::SendWait(“$decodepasswd”)


[System.Windows.Forms.SendKeys]::SendWait(“{ENTER}”)


start-sleep -Milliseconds 800


[System.Windows.Forms.SendKeys]::SendWait(“$BroDirectoryNavigation”)


[System.Windows.Forms.SendKeys]::SendWait(“{ENTER}”)


start-sleep -Milliseconds 800


[System.Windows.Forms.SendKeys]::SendWait(“$BroDirectorynavigationLogs”)


[System.Windows.Forms.SendKeys]::SendWait(“{ENTER}”)


start-sleep -Milliseconds 800


[System.Windows.Forms.SendKeys]::SendWait(“$BroSearchFilesAll”)


[System.Windows.Forms.SendKeys]::SendWait(“{ENTER}”)










##   Declare the Variables   ##


$TicketNumber = "*** Place Holder ***"
$Initials = Read-Host -Prompt 'Please Input Analyst Initial.'
$ArcsightDateandTime = Read-Host -Prompt 'Please Input Arcsight Event Date & Time.'
$ArcsightAlertname = Read-Host -Prompt 'Please Input Arcsight Alert Name.'
$AnnotationExport = 'C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\AnnotationExport.docx'










##   Create the Microsoft Word Instance, Generate the Word Document, and Populate the Word Document with Verbage   ##


$Word = New-Object -ComObject Word.Application
$Word.Visible= $True
$Document = $Word.Documents.Add()
$Selection = $Word.Selection
$Selection.TypeText("$TicketNumber")
$Selection.TypeText(" ($Initials)")
$Selection.TypeText(" On")
$Selection.TypeText(" $ArcsightDateandTime,")
$Selection.TypeText(" (DCN/PACER IP)")
$Selection.TypeText(" $IP")
$Selection.TypeText(" was observed communicating with $ForiegnIP,")
$Selection.TypeText(" triggering alert")
$Selection.TypeText(" $ArcsightAlertname")
$Selection.TypeText(" in the Arcsight console.")
$Selection.TypeText(" This text is a temporary place holder, fill it with relevant information.")
$Selection.TypeText(" This text is a temporary place holder, fill it with relevant information.")
$Selection.TypeText(" This text is a temporary place holder, fill it with relevant information.")
$Selection.TypeText(" Notification (is/is not) requested at this time.")










##   Create the Microsoft Word Instance, Generate the Word Document, and Populate the Word Document with Verbage   ##


$ArtifactwithoutpicturesExport = "C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\ArtifactsWithoutPictures"
$WordDocumentPath = "C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\ArtifactsWithoutPictures.docx"


$word = New-Object -ComObject word.application
$word.visible = $true
$doc = $word.documents.add()
$selection = $word.selection
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 1
$selection.typeText("Event Date/Time:")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$selection.typeText(" $ArcsightDateandTime")
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 1
$selection.typeText("Alert Name:")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$selection.typeText(" $ArcsightAlertname")
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 1
$selection.typeText("IP Addresses:")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$selection.typeText(" $IP ")
$selection.InsertSymbol(0224,"wingdings")
$Selection.typeText(" $ForiegnIP")
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 1
$selection.typeText("File Name:")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$selection.typeText(" XXX")
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 1
$selection.typeText("File MD5 Hash:")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$selection.typeText(" XXX")
$selection.TypeParagraph()
$selection.InsertSymbol(35,"wingdings2")
$selection.InsertSymbol(35,"wingdings2")
$selection.InsertSymbol(35,"wingdings2")
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 1
$selection.typeText("BLUF:")
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$selection.typeText("Place Annotations here.")
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText("$TicketNumber")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" ($Initials)")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" On")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" $ArcsightDateandTime,")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" Offending IP $ForiegnIP")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" was observed communicating with DCN IP $IP,")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" triggering alert $ArcsightAlertname in the Arcsight console.")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" This text is a temporary place holder, fill it with relevant information.")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" This text is a temporary place holder, fill it with relevant information.")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" This text is a temporary place holder, fill it with relevant information.")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" This text is a temporary place holder, fill it with relevant information.")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" Notification (is/is not) requested at this time.")
$selection.TypeParagraph()
$selection.TypeParagraph()
$selection.TypeParagraph()
$selection.InsertSymbol(35,"wingdings2")
$selection.InsertSymbol(35,"wingdings2")
$selection.InsertSymbol(35,"wingdings2")
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 11
$selection.font.bold = 1
$Selection.font.underline = 1
$selection.typeText("Splunk:")
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 11
$selection.font.bold = 0
$Selection.font.underline = 1
$selection.typeText("Logs attached in ticket as other documents.")
$selection.TypeParagraph()
$selection.TypeParagraph()
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 11
$selection.font.bold = 1
$Selection.font.underline = 1
$Selection.typeText("Sourcefire:")
$selection.TypeParagraph()










##   Save and Gracefully Exit the Word Document   ##


$doc.SaveAs([ref]$ArtifactwithoutpicturesExport,[ref]$SaveFormat::wdFormatDocumentDefault)
$word.Quit()










##   Declare Path for Images, Declare Document, Add All Images in Declared Path to Declared Word Document   ##


$WordDocumentPath = "C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\ArtifactsWithoutPictures.docx"
$ImageFolderPath = "C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\Sourcefire"
        
If(Test-Path -Path $WordDocumentPath)
{
If(Test-Path -Path $ImageFolderPath)
{
$WordExtension = (Get-Item -Path $WordDocumentPath).Extension
If($WordExtension -like ".doc" -or $WordExtension -like ".docx")
{
$ImageFiles = Get-ChildItem -Path $ImageFolderPath -Recurse -Include *.emf,*.wmf,*.jpg,*.jpeg,*.jfif,*.png,*.jpe,*.bmp,*.dib,*.rle,*.gif,*.emz,*.wmz,*.pcz,*.tif,*.tiff,*.eps,*.pct,*.pict,*.wpg
If($ImageFiles)
{
#Create the Word application object
$WordAPP = New-Object -ComObject Word.Application
$WordDoc = $WordAPP.Documents.Open("$WordDocumentPath")
Foreach($ImageFile in $ImageFiles)
{
$ImageFilePath = $ImageFile.FullName 
$Properties = @{'ImageName' = $ImageFile.Name
'Action(Insert)' = Try
{
$WordAPP.Selection.EndKey(6)|Out-Null
$WordApp.Selection.InlineShapes.AddPicture("$ImageFilePath")|Out-Null
$WordApp.Selection.InsertNewPage() #insert new page to word
"Finished"
}
Catch
{
"Unfinished"
}
}


$objWord = New-Object -TypeName PSObject -Property $Properties
$objWord
}


$WordDoc.Save()
$WordDoc.Close()
$WordAPP.Quit()   #release the object
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($WordAPP)|Out-Null
Remove-Variable WordAPP
}
Else
{
Write-Warning "There is no image in this '$ImageFolderPath' folder."
}
}
Else
{
Write-Warning "There is no word document file in this '$WordDocumentPath' folder."
}
}
Else
{
Write-Warning "Cannot find path '$ImageFolderPath' because it does not exist."
}
}
Else
{
Write-Warning "Cannot find path '$WordDocumentPath' because it does not exist."
}
   
  
   




##   Add Next Segment to Add Images For   ##


$wdStory = 6 
$wdMove = 0 
 
$word = New-object -comobject Word.Application  
$word.Visible = $True 
 
$doc = $word.Documents.Open("$WordDocumentPath") 


$selection = $word.Selection
$a = $selection.EndKey($wdStory, $wdMove) 
$selection.TypeParagraph()
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 11
$selection.font.bold = 1
$Selection.font.underline = 1
$selection.typeText("FireEye:")
$selection.TypeParagraph()










##   Save and Gracefully Exit the Word Document   ##


$doc.Save()
$doc.close()
$word.quit()










##   Declare Path for Images, Declare Document, Add All Images in Declared Path to Declared Word Document   ##


$WordDocumentPath = "C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\ArtifactsWithoutPictures.docx"
$ImageFolderPath = "C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\FireEye"
        
If(Test-Path -Path $WordDocumentPath)
{
If(Test-Path -Path $ImageFolderPath)
{
$WordExtension = (Get-Item -Path $WordDocumentPath).Extension
If($WordExtension -like ".doc" -or $WordExtension -like ".docx")
{
$ImageFiles = Get-ChildItem -Path $ImageFolderPath -Recurse -Include *.emf,*.wmf,*.jpg,*.jpeg,*.jfif,*.png,*.jpe,*.bmp,*.dib,*.rle,*.gif,*.emz,*.wmz,*.pcz,*.tif,*.tiff,*.eps,*.pct,*.pict,*.wpg
If($ImageFiles)
{
#Create the Word application object
$WordAPP = New-Object -ComObject Word.Application
$WordDoc = $WordAPP.Documents.Open("$WordDocumentPath")
Foreach($ImageFile in $ImageFiles)
{
$ImageFilePath = $ImageFile.FullName 
$Properties = @{'ImageName' = $ImageFile.Name
'Action(Insert)' = Try
{
$WordAPP.Selection.EndKey(6)|Out-Null
$WordApp.Selection.InlineShapes.AddPicture("$ImageFilePath")|Out-Null
$WordApp.Selection.InsertNewPage() #insert new page to word
"Finished"
}
Catch
{
"Unfinished"
}
}


$objWord = New-Object -TypeName PSObject -Property $Properties
$objWord
}


$WordDoc.Save()
$WordDoc.Close()
$WordAPP.Quit()#release the object
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($WordAPP)|Out-Null
Remove-Variable WordAPP
}
Else
{
Write-Warning "There is no image in this '$ImageFolderPath' folder."
}
}
Else
{
Write-Warning "There is no word document file in this '$WordDocumentPath' folder."
}
}
Else
{
Write-Warning "Cannot find path '$ImageFolderPath' because it does not exist."
}
}
Else
{
Write-Warning "Cannot find path '$WordDocumentPath' because it does not exist."
}
   
  






##   Add Next Segment to Add Images For   ##


$wdStory = 6 
$wdMove = 0 
 
$word = New-object -comobject Word.Application  
$word.Visible = $True 
 
$doc = $word.Documents.Open("$WordDocumentPath") 


$selection = $word.Selection
$a = $selection.EndKey($wdStory, $wdMove) 
$selection.TypeParagraph()
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 11
$selection.font.bold = 1
$Selection.font.underline = 1
$selection.typeText("VirusTotal:")
$selection.TypeParagraph()










##   Save and Gracefully Exit the Word Document   ##


$doc.Save()
$doc.close()
$word.quit()










##   Declare Path for Images, Declare Document, Add All Images in Declared Path to Declared Word Document   ##


$WordDocumentPath = "C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\ArtifactsWithoutPictures.docx"
$ImageFolderPath = "C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\VirusTotal"
        
If(Test-Path -Path $WordDocumentPath)
{
If(Test-Path -Path $ImageFolderPath)
{
$WordExtension = (Get-Item -Path $WordDocumentPath).Extension
If($WordExtension -like ".doc" -or $WordExtension -like ".docx")
{
$ImageFiles = Get-ChildItem -Path $ImageFolderPath -Recurse -Include *.emf,*.wmf,*.jpg,*.jpeg,*.jfif,*.png,*.jpe,*.bmp,*.dib,*.rle,*.gif,*.emz,*.wmz,*.pcz,*.tif,*.tiff,*.eps,*.pct,*.pict,*.wpg
If($ImageFiles)
{
#Create the Word application object
$WordAPP = New-Object -ComObject Word.Application
$WordDoc = $WordAPP.Documents.Open("$WordDocumentPath")
Foreach($ImageFile in $ImageFiles)
{
$ImageFilePath = $ImageFile.FullName 
$Properties = @{'ImageName' = $ImageFile.Name
'Action(Insert)' = Try
{
$WordAPP.Selection.EndKey(6)|Out-Null
$WordApp.Selection.InlineShapes.AddPicture("$ImageFilePath")|Out-Null
$WordApp.Selection.InsertNewPage() #insert new page to word
"Finished"
}
Catch
{
"Unfinished"
}
}


$objWord = New-Object -TypeName PSObject -Property $Properties
$objWord
}


$WordDoc.Save()
$WordDoc.Close()
$WordAPP.Quit()#release the object
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($WordAPP)|Out-Null
Remove-Variable WordAPP
}
Else
{
Write-Warning "There is no image in this '$ImageFolderPath' folder."
}
}
Else
{
Write-Warning "There is no word document file in this '$WordDocumentPath' folder."
}
}
Else
{
Write-Warning "Cannot find path '$ImageFolderPath' because it does not exist."
}
}
Else
{
Write-Warning "Cannot find path '$WordDocumentPath' because it does not exist."
}
   
  




   
##   Add Next Segment to Add Images For   ##


$wdStory = 6 
$wdMove = 0 
 
$word = New-object -comobject Word.Application  
$word.Visible = $True 
 
$doc = $word.Documents.Open("$WordDocumentPath") 


$selection = $word.Selection
$a = $selection.EndKey($wdStory, $wdMove) 
$selection.TypeParagraph()
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 11
$selection.font.bold = 1
$Selection.font.underline = 1
$selection.typeText("Bro(in putty):")
$selection.TypeParagraph()










##   Save and Gracefully Exit the Word Document   ##


$doc.Save()
$doc.close()
$word.quit()










##   Declare Path for Images, Declare Document, Add All Images in Declared Path to Declared Word Document   ##


$WordDocumentPath = "C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\ArtifactsWithoutPictures.docx"
$ImageFolderPath = "C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\Bro(in putty)"
        
If(Test-Path -Path $WordDocumentPath)
{
If(Test-Path -Path $ImageFolderPath)
{
$WordExtension = (Get-Item -Path $WordDocumentPath).Extension
If($WordExtension -like ".doc" -or $WordExtension -like ".docx")
{
$ImageFiles = Get-ChildItem -Path $ImageFolderPath -Recurse -Include *.emf,*.wmf,*.jpg,*.jpeg,*.jfif,*.png,*.jpe,*.bmp,*.dib,*.rle,*.gif,*.emz,*.wmz,*.pcz,*.tif,*.tiff,*.eps,*.pct,*.pict,*.wpg
If($ImageFiles)
{
#Create the Word application object
$WordAPP = New-Object -ComObject Word.Application
$WordDoc = $WordAPP.Documents.Open("$WordDocumentPath")
Foreach($ImageFile in $ImageFiles)
{
$ImageFilePath = $ImageFile.FullName 
$Properties = @{'ImageName' = $ImageFile.Name
'Action(Insert)' = Try
{
$WordAPP.Selection.EndKey(6)|Out-Null
$WordApp.Selection.InlineShapes.AddPicture("$ImageFilePath")|Out-Null
$WordApp.Selection.InsertNewPage() #insert new page to word
"Finished"
}
Catch
{
"Unfinished"
}
}


$objWord = New-Object -TypeName PSObject -Property $Properties
$objWord
}


$WordDoc.Save()
$WordDoc.Close()
$WordAPP.Quit()#release the object
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($WordAPP)|Out-Null
Remove-Variable WordAPP
}
Else
{
Write-Warning "There is no image in this '$ImageFolderPath' folder."
}
}
Else
{
Write-Warning "There is no word document file in this '$WordDocumentPath' folder."
}
}
Else
{
Write-Warning "Cannot find path '$ImageFolderPath' because it does not exist."
}
}
Else
{
Write-Warning "Cannot find path '$WordDocumentPath' because it does not exist."
}
   
  
   




##   Add Next Segment to Add Images For   ##


$wdStory = 6 
$wdMove = 0 
 
$word = New-object -comobject Word.Application  
$word.Visible = $True 
 
$doc = $word.Documents.Open("$WordDocumentPath") 


$selection = $word.Selection
$a = $selection.EndKey($wdStory, $wdMove) 
$selection.TypeParagraph()
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 11
$selection.font.bold = 1
$Selection.font.underline = 1
$selection.typeText("IP Void:")
$selection.TypeParagraph()










##   Save and Gracefully Exit the Word Document   ##


$doc.Save()
$doc.close()
$word.quit()










##   Declare Path for Images, Declare Document, Add All Images in Declared Path to Declared Word Document   ##


$WordDocumentPath = "C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\ArtifactsWithoutPictures.docx"
$ImageFolderPath = "C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\IPVoid"
        
If(Test-Path -Path $WordDocumentPath)
{
If(Test-Path -Path $ImageFolderPath)
{
$WordExtension = (Get-Item -Path $WordDocumentPath).Extension
If($WordExtension -like ".doc" -or $WordExtension -like ".docx")
{
$ImageFiles = Get-ChildItem -Path $ImageFolderPath -Recurse -Include *.emf,*.wmf,*.jpg,*.jpeg,*.jfif,*.png,*.jpe,*.bmp,*.dib,*.rle,*.gif,*.emz,*.wmz,*.pcz,*.tif,*.tiff,*.eps,*.pct,*.pict,*.wpg
If($ImageFiles)
{
#Create the Word application object
$WordAPP = New-Object -ComObject Word.Application
$WordDoc = $WordAPP.Documents.Open("$WordDocumentPath")
Foreach($ImageFile in $ImageFiles)
{
$ImageFilePath = $ImageFile.FullName 
$Properties = @{'ImageName' = $ImageFile.Name
'Action(Insert)' = Try
{
$WordAPP.Selection.EndKey(6)|Out-Null
$WordApp.Selection.InlineShapes.AddPicture("$ImageFilePath")|Out-Null
$WordApp.Selection.InsertNewPage() #insert new page to word
"Finished"
}
Catch
{
"Unfinished"
}
}


$objWord = New-Object -TypeName PSObject -Property $Properties
$objWord
}


$WordDoc.Save()
$WordDoc.Close()
$WordAPP.Quit()#release the object
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($WordAPP)|Out-Null
Remove-Variable WordAPP
}
Else
{
Write-Warning "There is no image in this '$ImageFolderPath' folder."
}
}
Else
{
Write-Warning "There is no word document file in this '$WordDocumentPath' folder."
}
}
Else
{
Write-Warning "Cannot find path '$ImageFolderPath' because it does not exist."
}
}
Else
{
Write-Warning "Cannot find path '$WordDocumentPath' because it does not exist."
}
   
  
   




##   Add Next Segment to Add Images For   ##


$wdStory = 6 
$wdMove = 0 
 
$word = New-object -comobject Word.Application  
$word.Visible = $True 
 
$doc = $word.Documents.Open("$WordDocumentPath") 


$selection = $word.Selection
$a = $selection.EndKey($wdStory, $wdMove) 
$selection.TypeParagraph()
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 11
$selection.font.bold = 1
$Selection.font.underline = 1
$selection.typeText("Other:")
$selection.TypeParagraph()










##   Save and Gracefully Exit the Word Document   ##


$doc.Save()
$doc.close()
$word.quit()










##   Declare Path for Images, Declare Document, Add All Images in Declared Path to Declared Word Document   ##


$WordDocumentPath = "C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\ArtifactsWithoutPictures.docx"
$ImageFolderPath = "C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\Other"
        
If(Test-Path -Path $WordDocumentPath)
{
If(Test-Path -Path $ImageFolderPath)
{
$WordExtension = (Get-Item -Path $WordDocumentPath).Extension
If($WordExtension -like ".doc" -or $WordExtension -like ".docx")
{
$ImageFiles = Get-ChildItem -Path $ImageFolderPath -Recurse -Include *.emf,*.wmf,*.jpg,*.jpeg,*.jfif,*.png,*.jpe,*.bmp,*.dib,*.rle,*.gif,*.emz,*.wmz,*.pcz,*.tif,*.tiff,*.eps,*.pct,*.pict,*.wpg
If($ImageFiles)
{
#Create the Word application object
$WordAPP = New-Object -ComObject Word.Application
$WordDoc = $WordAPP.Documents.Open("$WordDocumentPath")
Foreach($ImageFile in $ImageFiles)
{
$ImageFilePath = $ImageFile.FullName 
$Properties = @{'ImageName' = $ImageFile.Name
'Action(Insert)' = Try
{
$WordAPP.Selection.EndKey(6)|Out-Null
$WordApp.Selection.InlineShapes.AddPicture("$ImageFilePath")|Out-Null
$WordApp.Selection.InsertNewPage() #insert new page to word
"Finished"
}
Catch
{
"Unfinished"
}
}


$objWord = New-Object -TypeName PSObject -Property $Properties
$objWord
}


$WordDoc.Save()
$WordDoc.Close()
$WordAPP.Quit()#release the object
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($WordAPP)|Out-Null
Remove-Variable WordAPP
}
Else
{
Write-Warning "There is no image in this '$ImageFolderPath' folder."
}
}
Else
{
Write-Warning "There is no word document file in this '$WordDocumentPath' folder."
}
}
Else
{
Write-Warning "Cannot find path '$ImageFolderPath' because it does not exist."
}
}
Else
{
Write-Warning "Cannot find path '$WordDocumentPath' because it does not exist."
}










##  Nullify all configured variables for security reasons  ##


$SourceIP = $null
$DestinationIP = $null
$VirusTotalIP = $null
$SourceDestinationSplunkSearch = $null
$FirewallIndexSplunkSearch = $null
$CiscoASASplunkSearch = $null
$PanThreatSplunkSearch = $null
$BroSplunkSearch = $null
$uname = $null
$passwd = $null
$decodepasswd = $null
$Date = $null
$DateYear = $null
$DateMonth = $null
$DateDay = $null
$BroDirectoryNavigation = $null
$BroDirectorynavigationLogs = $null
$BroSearchFilesAll = $null
$TicketNumber = $null
$Initials = $null
$IP = $null
$ForeignIP = $null
$ArcsightDateandTime = $null
$ArcsightAlertname = $null
$AnnotationExport = $null
$SplunkFW = $null
$SplunkCiscoASA = $null
$SplunkPanThreat = $null
$SplunkBro = $null
$IPVoidPic = $null

} # end Function AutomatedAnalysis










##  Defines the Menu Options  ##


function Show-Menu
{
     param (
           [string]$Title = 'Security Operation Center Multitool'
     )
     cls
     Write-Host -BackgroundColor 'Black' -ForegroundColor 'Green' "================= $Title ================="
     Write-Host -BackgroundColor 'Black' -ForegroundColor 'Green'  "1: Press '1' to run the Security Analyst Accelerated Search Expression."
     Write-Host -BackgroundColor 'Black' -ForegroundColor 'Green'  "2: Press '2' to run the Ticket Generation Expression."
     Write-Host -BackgroundColor 'Black' -ForegroundColor 'Green'  "3: Press '3' to run the Firewall Blocking Expression."
     Write-Host -BackgroundColor 'Black' -ForegroundColor 'Green'  "Q: Press 'Q' to quit."
} # End Function Show-Menu










##   Ticket Generation Function, see script Ticket Generation.ps1   ##


Function TicketGeneration
{
$title = "Ticket Generation"
$message = "Would you like to make a ticket?"


$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
    "Generating required files now."


$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
    "Exiting application now."


$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)


$result = $host.ui.PromptForChoice($title, $message, $options, 0) 


switch ($result)
    {
        0 {"Generating required files now."}
        1 {"Exiting application now."}
    }
} # End Function TicketGeneration










Function FirewallAutomation
{
##   Declare the Variables   ##


$FirewallIP = Read-Host -Prompt 'Input IP Address'
$FirewallForiegnIP = Read-Host -Prompt 'Input External IP Address'
#$tacacsuname = read-host -Prompt 'Please Enter Tacacs Username.'
#$tacacspasswd = read-host -Prompt 'Please Enter Tacacs Password.' -AsSecureString
#$tacacsdecodepasswd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($tacacspasswd))
#$SourcefireLogin = " https://XXX.XXX.XXX.XXX/login.cgi "
$Sourcefire = " https://XXX.XXX.XXX.XXX/events/?table=event&constraints=src%3D$FirewallForiegnIP!%2C!dst%3D$FirewallIP&workflow=Events%20By%20Priority%20and%20Classification "
#$ImpervaLogin = " https://XXX.XXX.XXX.XXX:XXXX/SecureSphere/secsphLogin.jsp "
$Imperva = " https://XXX.XXX.XXX.XXX:XXXX/SecureSphere/index.html#newalerts "










##   Open Chrome for Sourcefire Login  ###
@'
$Chrome = Start-Process "chrome.exe" ` -ArgumentList " $SourcefireLogin "


[System.Windows.Forms.SendKeys]::SendWait(“{TAB}{TAB}{TAB}{TAB}{TAB}{TAB}{TAB}”)


[System.Windows.Forms.SendKeys]::SendWait(“$tacacsuname”)


[System.Windows.Forms.SendKeys]::SendWait(“{TAB}”)


[System.Windows.Forms.SendKeys]::SendWait(“$tacacsdecodepasswd”)


[System.Windows.Forms.SendKeys]::SendWait(“{ENTER}”)
'@










##   Open Chrome for Sourcefire Search   ##


$Chrome = Start-Process "chrome.exe" ` -ArgumentList " $Sourcefire "
2
[Microsoft.VisualBasic.Interaction]::AppActivate(“$Chrome”)










@'
##   Open Chrome for Imperva WAF Login   ##


$Chrome = Start-Process "chrome.exe" ` -ArgumentList " $ImpervaLogin "


[Microsoft.VisualBasic.Interaction]::AppActivate(“$Chrome”)


[System.Windows.Forms.SendKeys]::SendWait(“$tacacsuname”)


[System.Windows.Forms.SendKeys]::SendWait(“{TAB}”)


[System.Windows.Forms.SendKeys]::SendWait(“$tacacsdecodepasswd”)


[System.Windows.Forms.SendKeys]::SendWait(“{ENTER}”)


sleep 8
'@










##   Open Chrome for Imperva Search   ##


$Chrome = Start-Process "chrome.exe" ` -ArgumentList " $Imperva "


[Microsoft.VisualBasic.Interaction]::AppActivate(“$Chrome”)


Sleep 8


[System.Windows.Forms.SendKeys]::SendWait(“{TAB}{TAB}{TAB}{TAB}{TAB}{TAB}{TAB}{TAB}{TAB}{TAB}{TAB}{TAB}{TAB}{TAB}”)


Sleep 3


[System.Windows.Forms.SendKeys]::SendWait(“$FirewallForiegnIP”)


[System.Windows.Forms.SendKeys]::SendWait(“{ENTER}”)










##   Declare the Variables   ##


$TicketNumber = "*** Place Holder ***"
$Initials = Read-Host -Prompt 'Please Input Analyst Initial.'
$ArcsightDateandTime = Read-Host -Prompt 'Please Input Arcsight Event Date & Time.'
$ArcsightAlertname = Read-Host -Prompt 'Please Input Arcsight Alert Name.'
$FirewallAnnotationExport = 'C:\Users\logan hicks\Documents\Corporate\Powershell\Test Folder\FirewallAnnotationExport.docx'










##   Create the Microsoft Word Instance, Generate the Word Document, and Populate the Word Document with Text   ##


$Word = New-Object -ComObject Word.Application
$Word.Visible= $True
$Document = $Word.Documents.Add()
$Selection = $Word.Selection
$Selection.TypeText("$TicketNumber")
$Selection.TypeText(" ($Initials)")
$Selection.TypeText(" On")
$Selection.TypeText(" $ArcsightDateandTime,")
$Selection.TypeText(" Offending IP (address/addresses) $FirewallForiegnIP")
$Selection.TypeText(" was observed triggering $ArcsightAlertname in the Arcsight console.")
$Selection.TypeText(" Packet text data confirms attempts were made against asset (Asset), IP $FirewallIP.")
$Selection.TypeText(" Rule content fired on "" (Rule Content) "", which was observed in the packet text data.")
$Selection.TypeText(" However, Sourcefire confirms that this traffic (was/was not) dropped.")
$Selection.TypeText(" This asset (is/is not) behind the WAF.")
$Selection.TypeText(" Firewall Block (is/is not) requested at this time.")








##   Create the Microsoft Word Instance, Generate the Word Document, and Populate the Word Document with Verbage   ##


$word = New-Object -ComObject word.application
$word.visible = $true
$doc = $word.documents.add()
$selection = $word.selection
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 1
$selection.typeText("Event Date/Time:")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$selection.typeText(" EDATE")
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 1
$selection.typeText("Alert Name:")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$selection.typeText(" ANAME")
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 1
$selection.typeText("IP Addresses:")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$selection.typeText(" $FirewallIP ")
$selection.InsertSymbol(0224,"wingdings")
$Selection.typeText(" $FirewallForiegnIP")
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 1
$selection.typeText("File Name:")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$selection.typeText(" XXX")
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 1
$selection.typeText("File MD5 Hash:")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$selection.typeText(" XXX")
$selection.TypeParagraph()
$selection.InsertSymbol(35,"wingdings2")
$selection.InsertSymbol(35,"wingdings2")
$selection.InsertSymbol(35,"wingdings2")
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 1
$selection.typeText("BLUF:")
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$selection.typeText("Place Annotations here.")
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText("$TicketNumber")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" ($Initials)")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" On")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" $ArcsightDateandTime,")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" Offending IP $FirewallForiegnIP")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" was observed triggering $ArcsightAlertname in the Arcsight console.")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" Packet text data confirms attempts were made against asset (Asset), IP $FirewallIP.")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" Rule content fired on "" (Rule Content) "", which was observed in the packet text data.")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" However, Sourcefire confirms that this traffic (was/was not) dropped.")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" This IP (is/is not) behind the WAF.")
$selection.Font.Name="Arial"
$selection.font.size = 12
$selection.font.bold = 0
$Selection.TypeText(" Firewall Block (is/is not) requested at this time.")
$selection.TypeParagraph()
$selection.TypeParagraph()
$selection.TypeParagraph()
$selection.InsertSymbol(35,"wingdings2")
$selection.InsertSymbol(35,"wingdings2")
$selection.InsertSymbol(35,"wingdings2")
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 11
$selection.font.bold = 1
$Selection.font.underline = 1
$selection.typeText("Splunk:")
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 11
$selection.font.bold = 0
$Selection.font.underline = 1
$selection.typeText("Logs attached in ticket as other documents.")
$selection.TypeParagraph()
$selection.TypeParagraph()
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 11
$selection.font.bold = 1
$Selection.font.underline = 1
$Selection.typeText("Sourcefire:")
$selection.TypeParagraph()










##   Save and Gracefully Exit the Word Document   ##


$doc.SaveAs([ref]$ArtifactwithoutpicturesExport,[ref]$SaveFormat::wdFormatDocumentDefault)
$word.Quit()










##   Declare Path for Images, Declare Document, Add All Images in Declared Path to Declared Word Document   ##


$WordDocumentPath = "C:\Users\LHicks-PC\Documents\Projects\Powershell\Test Folder\ArtifactsWithoutPictures.docx"
$ImageFolderPath = "C:\Users\LHicks-PC\Documents\Projects\Powershell\Test Folder\Sourcefire"
        
If(Test-Path -Path $WordDocumentPath)
{
If(Test-Path -Path $ImageFolderPath)
{
$WordExtension = (Get-Item -Path $WordDocumentPath).Extension
If($WordExtension -like ".doc" -or $WordExtension -like ".docx")
{
$ImageFiles = Get-ChildItem -Path $ImageFolderPath -Recurse -Include *.emf,*.wmf,*.jpg,*.jpeg,*.jfif,*.png,*.jpe,*.bmp,*.dib,*.rle,*.gif,*.emz,*.wmz,*.pcz,*.tif,*.tiff,*.eps,*.pct,*.pict,*.wpg
If($ImageFiles)
{
#Create the Word application object
$WordAPP = New-Object -ComObject Word.Application
$WordDoc = $WordAPP.Documents.Open("$WordDocumentPath")
Foreach($ImageFile in $ImageFiles)
{
$ImageFilePath = $ImageFile.FullName 
$Properties = @{'ImageName' = $ImageFile.Name
'Action(Insert)' = Try
{
$WordAPP.Selection.EndKey(6)|Out-Null
$WordApp.Selection.InlineShapes.AddPicture("$ImageFilePath")|Out-Null
$WordApp.Selection.InsertNewPage() #insert new page to word
"Finished"
}
Catch
{
"Unfinished"
}
}


$objWord = New-Object -TypeName PSObject -Property $Properties
$objWord
}


$WordDoc.Save()
$WordDoc.Close()
$WordAPP.Quit()   #release the object
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($WordAPP)|Out-Null
Remove-Variable WordAPP
}
Else
{
Write-Warning "There is no image in this '$ImageFolderPath' folder."
}
}
Else
{
Write-Warning "There is no word document file in this '$WordDocumentPath' folder."
}
}
Else
{
Write-Warning "Cannot find path '$ImageFolderPath' because it does not exist."
}
}
Else
{
Write-Warning "Cannot find path '$WordDocumentPath' because it does not exist."
}
   
  
   




##   Add Next Segment to Add Images For   ##


$wdStory = 6 
$wdMove = 0 
 
$word = New-object -comobject Word.Application  
$word.Visible = $True 
 
$doc = $word.Documents.Open("$WordDocumentPath") 


$selection = $word.Selection
$a = $selection.EndKey($wdStory, $wdMove) 
$selection.TypeParagraph()
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 11
$selection.font.bold = 1
$Selection.font.underline = 1
$selection.typeText("FireEye:")
$selection.TypeParagraph()










##   Save and Gracefully Exit the Word Document   ##


$doc.Save()
$doc.close()
$word.quit()










##   Declare Path for Images, Declare Document, Add All Images in Declared Path to Declared Word Document   ##


$WordDocumentPath = "C:\Users\LHicks-PC\Documents\Projects\Powershell\Test Folder\ArtifactsWithoutPictures.docx"
$ImageFolderPath = "C:\Users\LHicks-PC\Documents\Projects\Powershell\Test Folder\FireEye"
        
If(Test-Path -Path $WordDocumentPath)
{
If(Test-Path -Path $ImageFolderPath)
{
$WordExtension = (Get-Item -Path $WordDocumentPath).Extension
If($WordExtension -like ".doc" -or $WordExtension -like ".docx")
{
$ImageFiles = Get-ChildItem -Path $ImageFolderPath -Recurse -Include *.emf,*.wmf,*.jpg,*.jpeg,*.jfif,*.png,*.jpe,*.bmp,*.dib,*.rle,*.gif,*.emz,*.wmz,*.pcz,*.tif,*.tiff,*.eps,*.pct,*.pict,*.wpg
If($ImageFiles)
{
#Create the Word application object
$WordAPP = New-Object -ComObject Word.Application
$WordDoc = $WordAPP.Documents.Open("$WordDocumentPath")
Foreach($ImageFile in $ImageFiles)
{
$ImageFilePath = $ImageFile.FullName 
$Properties = @{'ImageName' = $ImageFile.Name
'Action(Insert)' = Try
{
$WordAPP.Selection.EndKey(6)|Out-Null
$WordApp.Selection.InlineShapes.AddPicture("$ImageFilePath")|Out-Null
$WordApp.Selection.InsertNewPage() #insert new page to word
"Finished"
}
Catch
{
"Unfinished"
}
}


$objWord = New-Object -TypeName PSObject -Property $Properties
$objWord
}


$WordDoc.Save()
$WordDoc.Close()
$WordAPP.Quit()#release the object
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($WordAPP)|Out-Null
Remove-Variable WordAPP
}
Else
{
Write-Warning "There is no image in this '$ImageFolderPath' folder."
}
}
Else
{
Write-Warning "There is no word document file in this '$WordDocumentPath' folder."
}
}
Else
{
Write-Warning "Cannot find path '$ImageFolderPath' because it does not exist."
}
}
Else
{
Write-Warning "Cannot find path '$WordDocumentPath' because it does not exist."
}
   
  






##   Add Next Segment to Add Images For   ##


$wdStory = 6 
$wdMove = 0 
 
$word = New-object -comobject Word.Application  
$word.Visible = $True 
 
$doc = $word.Documents.Open("$WordDocumentPath") 


$selection = $word.Selection
$a = $selection.EndKey($wdStory, $wdMove) 
$selection.TypeParagraph()
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 11
$selection.font.bold = 1
$Selection.font.underline = 1
$selection.typeText("VirusTotal:")
$selection.TypeParagraph()










##   Save and Gracefully Exit the Word Document   ##


$doc.Save()
$doc.close()
$word.quit()










##   Declare Path for Images, Declare Document, Add All Images in Declared Path to Declared Word Document   ##


$WordDocumentPath = "C:\Users\LHicks-PC\Documents\Projects\Powershell\Test Folder\ArtifactsWithoutPictures.docx"
$ImageFolderPath = "C:\Users\LHicks-PC\Documents\Projects\Powershell\Test Folder\VirusTotal"
        
If(Test-Path -Path $WordDocumentPath)
{
If(Test-Path -Path $ImageFolderPath)
{
$WordExtension = (Get-Item -Path $WordDocumentPath).Extension
If($WordExtension -like ".doc" -or $WordExtension -like ".docx")
{
$ImageFiles = Get-ChildItem -Path $ImageFolderPath -Recurse -Include *.emf,*.wmf,*.jpg,*.jpeg,*.jfif,*.png,*.jpe,*.bmp,*.dib,*.rle,*.gif,*.emz,*.wmz,*.pcz,*.tif,*.tiff,*.eps,*.pct,*.pict,*.wpg
If($ImageFiles)
{
#Create the Word application object
$WordAPP = New-Object -ComObject Word.Application
$WordDoc = $WordAPP.Documents.Open("$WordDocumentPath")
Foreach($ImageFile in $ImageFiles)
{
$ImageFilePath = $ImageFile.FullName 
$Properties = @{'ImageName' = $ImageFile.Name
'Action(Insert)' = Try
{
$WordAPP.Selection.EndKey(6)|Out-Null
$WordApp.Selection.InlineShapes.AddPicture("$ImageFilePath")|Out-Null
$WordApp.Selection.InsertNewPage() #insert new page to word
"Finished"
}
Catch
{
"Unfinished"
}
}


$objWord = New-Object -TypeName PSObject -Property $Properties
$objWord
}


$WordDoc.Save()
$WordDoc.Close()
$WordAPP.Quit()#release the object
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($WordAPP)|Out-Null
Remove-Variable WordAPP
}
Else
{
Write-Warning "There is no image in this '$ImageFolderPath' folder."
}
}
Else
{
Write-Warning "There is no word document file in this '$WordDocumentPath' folder."
}
}
Else
{
Write-Warning "Cannot find path '$ImageFolderPath' because it does not exist."
}
}
Else
{
Write-Warning "Cannot find path '$WordDocumentPath' because it does not exist."
}
   
  




   
##   Add Next Segment to Add Images For   ##


$wdStory = 6 
$wdMove = 0 
 
$word = New-object -comobject Word.Application  
$word.Visible = $True 
 
$doc = $word.Documents.Open("$WordDocumentPath") 


$selection = $word.Selection
$a = $selection.EndKey($wdStory, $wdMove) 
$selection.TypeParagraph()
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 11
$selection.font.bold = 1
$Selection.font.underline = 1
$selection.typeText("Bro(in putty):")
$selection.TypeParagraph()










##   Save and Gracefully Exit the Word Document   ##


$doc.Save()
$doc.close()
$word.quit()










##   Declare Path for Images, Declare Document, Add All Images in Declared Path to Declared Word Document   ##


$WordDocumentPath = "C:\Users\LHicks-PC\Documents\Projects\Powershell\Test Folder\ArtifactsWithoutPictures.docx"
$ImageFolderPath = "C:\Users\LHicks-PC\Documents\Projects\Powershell\Test Folder\Bro(in putty)"
        
If(Test-Path -Path $WordDocumentPath)
{
If(Test-Path -Path $ImageFolderPath)
{
$WordExtension = (Get-Item -Path $WordDocumentPath).Extension
If($WordExtension -like ".doc" -or $WordExtension -like ".docx")
{
$ImageFiles = Get-ChildItem -Path $ImageFolderPath -Recurse -Include *.emf,*.wmf,*.jpg,*.jpeg,*.jfif,*.png,*.jpe,*.bmp,*.dib,*.rle,*.gif,*.emz,*.wmz,*.pcz,*.tif,*.tiff,*.eps,*.pct,*.pict,*.wpg
If($ImageFiles)
{
#Create the Word application object
$WordAPP = New-Object -ComObject Word.Application
$WordDoc = $WordAPP.Documents.Open("$WordDocumentPath")
Foreach($ImageFile in $ImageFiles)
{
$ImageFilePath = $ImageFile.FullName 
$Properties = @{'ImageName' = $ImageFile.Name
'Action(Insert)' = Try
{
$WordAPP.Selection.EndKey(6)|Out-Null
$WordApp.Selection.InlineShapes.AddPicture("$ImageFilePath")|Out-Null
$WordApp.Selection.InsertNewPage() #insert new page to word
"Finished"
}
Catch
{
"Unfinished"
}
}


$objWord = New-Object -TypeName PSObject -Property $Properties
$objWord
}


$WordDoc.Save()
$WordDoc.Close()
$WordAPP.Quit()#release the object
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($WordAPP)|Out-Null
Remove-Variable WordAPP
}
Else
{
Write-Warning "There is no image in this '$ImageFolderPath' folder."
}
}
Else
{
Write-Warning "There is no word document file in this '$WordDocumentPath' folder."
}
}
Else
{
Write-Warning "Cannot find path '$ImageFolderPath' because it does not exist."
}
}
Else
{
Write-Warning "Cannot find path '$WordDocumentPath' because it does not exist."
}
   
  
   




##   Add Next Segment to Add Images For   ##


$wdStory = 6 
$wdMove = 0 
 
$word = New-object -comobject Word.Application  
$word.Visible = $True 
 
$doc = $word.Documents.Open("$WordDocumentPath") 


$selection = $word.Selection
$a = $selection.EndKey($wdStory, $wdMove) 
$selection.TypeParagraph()
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 11
$selection.font.bold = 1
$Selection.font.underline = 1
$selection.typeText("IP Void:")
$selection.TypeParagraph()










##   Save and Gracefully Exit the Word Document   ##


$doc.Save()
$doc.close()
$word.quit()










##   Declare Path for Images, Declare Document, Add All Images in Declared Path to Declared Word Document   ##


$WordDocumentPath = "C:\Users\LHicks-PC\Documents\Projects\Powershell\Test Folder\ArtifactsWithoutPictures.docx"
$ImageFolderPath = "C:\Users\LHicks-PC\Documents\Projects\Powershell\Test Folder\IPVoid"
        
If(Test-Path -Path $WordDocumentPath)
{
If(Test-Path -Path $ImageFolderPath)
{
$WordExtension = (Get-Item -Path $WordDocumentPath).Extension
If($WordExtension -like ".doc" -or $WordExtension -like ".docx")
{
$ImageFiles = Get-ChildItem -Path $ImageFolderPath -Recurse -Include *.emf,*.wmf,*.jpg,*.jpeg,*.jfif,*.png,*.jpe,*.bmp,*.dib,*.rle,*.gif,*.emz,*.wmz,*.pcz,*.tif,*.tiff,*.eps,*.pct,*.pict,*.wpg
If($ImageFiles)
{
#Create the Word application object
$WordAPP = New-Object -ComObject Word.Application
$WordDoc = $WordAPP.Documents.Open("$WordDocumentPath")
Foreach($ImageFile in $ImageFiles)
{
$ImageFilePath = $ImageFile.FullName 
$Properties = @{'ImageName' = $ImageFile.Name
'Action(Insert)' = Try
{
$WordAPP.Selection.EndKey(6)|Out-Null
$WordApp.Selection.InlineShapes.AddPicture("$ImageFilePath")|Out-Null
$WordApp.Selection.InsertNewPage() #insert new page to word
"Finished"
}
Catch
{
"Unfinished"
}
}


$objWord = New-Object -TypeName PSObject -Property $Properties
$objWord
}


$WordDoc.Save()
$WordDoc.Close()
$WordAPP.Quit()#release the object
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($WordAPP)|Out-Null
Remove-Variable WordAPP
}
Else
{
Write-Warning "There is no image in this '$ImageFolderPath' folder."
}
}
Else
{
Write-Warning "There is no word document file in this '$WordDocumentPath' folder."
}
}
Else
{
Write-Warning "Cannot find path '$ImageFolderPath' because it does not exist."
}
}
Else
{
Write-Warning "Cannot find path '$WordDocumentPath' because it does not exist."
}
   
  
   




##   Add Next Segment to Add Images For   ##


$wdStory = 6 
$wdMove = 0 
 
$word = New-object -comobject Word.Application  
$word.Visible = $True 
 
$doc = $word.Documents.Open("$WordDocumentPath") 


$selection = $word.Selection
$a = $selection.EndKey($wdStory, $wdMove) 
$selection.TypeParagraph()
$selection.TypeParagraph()
$selection.Font.Name="Arial"
$selection.font.size = 11
$selection.font.bold = 1
$Selection.font.underline = 1
$selection.typeText("Other:")
$selection.TypeParagraph()










##   Save and Gracefully Exit the Word Document   ##


$doc.Save()
$doc.close()
$word.quit()










##   Declare Path for Images, Declare Document, Add All Images in Declared Path to Declared Word Document   ##


$WordDocumentPath = "C:\Users\LHicks-PC\Documents\Projects\Powershell\Test Folder\ArtifactsWithoutPictures.docx"
$ImageFolderPath = "C:\Users\LHicks-PC\Documents\Projects\Powershell\Test Folder\Other"
        
If(Test-Path -Path $WordDocumentPath)
{
If(Test-Path -Path $ImageFolderPath)
{
$WordExtension = (Get-Item -Path $WordDocumentPath).Extension
If($WordExtension -like ".doc" -or $WordExtension -like ".docx")
{
$ImageFiles = Get-ChildItem -Path $ImageFolderPath -Recurse -Include *.emf,*.wmf,*.jpg,*.jpeg,*.jfif,*.png,*.jpe,*.bmp,*.dib,*.rle,*.gif,*.emz,*.wmz,*.pcz,*.tif,*.tiff,*.eps,*.pct,*.pict,*.wpg
If($ImageFiles)
{
#Create the Word application object
$WordAPP = New-Object -ComObject Word.Application
$WordDoc = $WordAPP.Documents.Open("$WordDocumentPath")
Foreach($ImageFile in $ImageFiles)
{
$ImageFilePath = $ImageFile.FullName 
$Properties = @{'ImageName' = $ImageFile.Name
'Action(Insert)' = Try
{
$WordAPP.Selection.EndKey(6)|Out-Null
$WordApp.Selection.InlineShapes.AddPicture("$ImageFilePath")|Out-Null
$WordApp.Selection.InsertNewPage() #insert new page to word
"Finished"
}
Catch
{
"Unfinished"
}
}


$objWord = New-Object -TypeName PSObject -Property $Properties
$objWord
}


$WordDoc.Save()
$WordDoc.Close()
$WordAPP.Quit()#release the object
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($WordAPP)|Out-Null
Remove-Variable WordAPP
}
Else
{
Write-Warning "There is no image in this '$ImageFolderPath' folder."
}
}
Else
{
Write-Warning "There is no word document file in this '$WordDocumentPath' folder."
}
}
Else
{
Write-Warning "Cannot find path '$ImageFolderPath' because it does not exist."
}
}
Else
{
Write-Warning "Cannot find path '$WordDocumentPath' because it does not exist."
}








##   Save the Word Document, and Exit Gracefully   ##


$Document.SaveAs([ref]$FirewallAnnotationExport)
$word.Quit()










##  Nullify all configured variables for security reasons  ##


$FirewallIP = $Null
$FirewallForiegnIP = $Null
#$tacacsuname = $Null
#$tacacspasswd = $Null
#$tacacsdecodepasswd = $Null
#$SourcefireLogin = $Null
$Sourcefire = $Null
#$ImpervaLogin = $Null
$Imperva = $Null
$TicketNumber = $Null
$Initials = $Null
$ArcsightDateandTime = $Null
$ArcsightAlertname = $Null
$FirewallAnnotationExport = $Null
} # End Function FirewallAutomation




##  Interprets the Menu Response and Conducts an action based on input  ##


do
{
     Show-Menu
     $input = Read-Host "Please make a selection"
     switch ($input)
     {
           '1' {
                cls
                'Launching Security Analyst Accelerated Search Expression now...'
                Invoke-Expression AutomatedAnalysis
           } '2' {
                cls
                'Launching Ticket & Notification Expression now...'
                Invoke-Expression TicketGeneration
           } '3' {
                cls
                'Launching Firewall Blocking Expression now...'
                Invoke-Expression FirewallAutomation
           } 'q' {
                return
           }
     }
     pause
}
until ($input -eq 'q' -Or 'exit')










##  Return to Menu  ##


do
{
     Show-Menu
     $input = Read-Host "Please make a selection"
     switch ($input)
     {
           '1' {
                cls
                'Launching Security Analyst Accelerated Search Expression now...'
                invoke-expression AutomatedAnalysis
           } '2' {
                cls
                'Launching Ticket & Notification Expression now...'
                Invoke-Expression TicketGeneration
           } '3' {
                cls
                'Launching Firewall Blocking Expression now...'
                Invoke-Expression FirewallAutomation
           } 'q' {
                return
           }
     }


     pause
}
until ($input -eq 'q' -Or 'exit')










##  Return to Menu  ##


do
{
     Show-Menu
     $input = Read-Host "Please make a selection"
     switch ($input)
     {
           '1' {
                cls
                'Launching Security Analyst Accelerated Search Expression now...'
                invoke-expression AutomatedAnalysis
           } '2' {
                cls
                'Launching Ticket & Notification Expression now...'
                Invoke-Expression TicketGeneration
           } '3' {
                cls
                'Launching Firewall Blocking Expression now...'
                Invoke-Expression FirewallAutomation
           } 'q' {
                return
           }
     }
     pause
}
until ($input -eq 'q' -Or 'exit')