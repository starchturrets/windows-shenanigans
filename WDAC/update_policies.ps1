$FilePaths =  "C:\Users\Admin\Group Policies\LGPO", "C:\Users\Admin\AppData\Local\PowerToys"

Foreach ($ScanPath in $FilePaths)

{
$PolicyName = ($ScanPath. Split("\"))[-1]
Write-Host $PolicyName
$OutputPath = "C:\Users\Admin\WDAC Experiments\Component Policies\" + $PolicyName + ".xml"

New-CIPolicy -Level FilePublisher -Fallback Hash -UserPEs -ScanPath $ScanPath -FilePath $OutputPath 
New-CIPolicy -Level FilePublisher -Fallback Hash -UserPEs -ScanPath $ScanPath -FilePath $OutputPath 

}

$PoliciesToBeMerged = (dir "C:\Users\Admin\WDAC Experiments\Component Policies\*.xml").FullName

Merge-CIPolicy -PolicyPaths $PoliciesToBeMerged -OutputFilePath 'C:\Users\Admin\WDAC Experiments\MergedPolicy.xml'


Set-RuleOption -FilePath 'C:\Users\Admin\WDAC Experiments\MergedPolicy.xml' -Option 3 -Delete
Set-RuleOption -FilePath 'C:\Users\Admin\WDAC Experiments\MergedPolicy.xml' -Option 4 
Set-HVCIOptions -Strict -FilePath 'C:\Users\Admin\WDAC Experiments\MergedPolicy.xml'

[xml] $XmlFile = get-content "C:\Users\Admin\WDAC Experiments\MergedPolicy.xml"
$PolicyID = $XmlFile.SiPolicy.PolicyID

# ConvertFrom-CIPolicy -XmlFilePath "C:\Users\Admin\WDAC Experiments\MergedPolicy.xml" -BinaryFilePath "C:\Users\Admin\WDAC Experiments\$PolicyID.cip"

# citool.exe --update-policy "C:\Users\Admin\WDAC Experiments\$PolicyID.cip"


