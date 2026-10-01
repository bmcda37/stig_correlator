<#
.SYNOPSIS
    StigCorrelator GUI: compare a Tenable STIG scan with a GPO backup, correlated by STIG ID.
.DESCRIPTION
    Pick the STIG Manual XCCDF, one or more Tenable .nessus files and a GPO backup folder, choose which
    GPOs to include, and click Run. Results appear in a sortable, filterable grid and can be exported to
    CSV or to STIG Viewer 3 checklists (.cklb, needs a blank CKLB).
    The Compare GPO backups tab compares two backups setting by setting, with optional STIG correlation.
    The analysis runs in a background runspace so the window stays responsive.
    Last-used paths are saved to %APPDATA%\StigCorrelator\gui-settings.json.
.NOTES
    Requires Windows, PowerShell 7.2+ and the StigCorrelator module one folder up from this script.
    Launch with:  pwsh -STA -NoProfile -File Start-StigCorrelatorGui.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

if (-not $IsWindows) { throw 'The StigCorrelator GUI requires Windows.' }
if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    # WPF needs a single-threaded apartment. Relaunch this script in STA mode.
    Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList @('-STA', '-NoProfile', '-File', "`"$PSCommandPath`"") -WindowStyle Hidden
    return
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

$script:ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'StigCorrelator.psd1'
Import-Module $script:ModulePath -Force
$script:SettingsPath = Join-Path $env:APPDATA 'StigCorrelator\gui-settings.json'
$script:Merged = @()
$script:GpoListPath = $null
$script:Worker = $null

#region XAML
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="StigCorrelator" Height="820" Width="1280" MinHeight="600" MinWidth="900"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" FontSize="12">
  <Window.Resources>
    <Style TargetType="Button"><Setter Property="Padding" Value="10,3"/><Setter Property="Margin" Value="4,2"/></Style>
    <Style TargetType="TextBox"><Setter Property="Margin" Value="4,2"/><Setter Property="VerticalContentAlignment" Value="Center"/></Style>
    <Style TargetType="Label"><Setter Property="VerticalAlignment" Value="Center"/></Style>
  </Window.Resources>
  <DockPanel Margin="8">
    <StatusBar DockPanel.Dock="Bottom"><StatusBarItem><TextBlock x:Name="StatusText" Text="Ready."/></StatusBarItem></StatusBar>
    <TabControl x:Name="Tabs">
    <TabItem Header="Scan vs. GPO backup">
    <DockPanel Margin="4">

    <Grid DockPanel.Dock="Top">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/><ColumnDefinition Width="340"/>
      </Grid.ColumnDefinitions>

      <GroupBox Header="Inputs" Grid.Column="0" Padding="4">
        <Grid>
          <Grid.ColumnDefinitions><ColumnDefinition Width="150"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
          <Grid.RowDefinitions><RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/></Grid.RowDefinitions>
          <Label Grid.Row="0" Content="STIG Manual XCCDF"/>
          <TextBox Grid.Row="0" Grid.Column="1" x:Name="XccdfBox"/>
          <Button Grid.Row="0" Grid.Column="2" x:Name="XccdfBtn" Content="Browse..."/>
          <Label Grid.Row="1" Content="Tenable scan (.nessus)"/>
          <TextBox Grid.Row="1" Grid.Column="1" x:Name="NessusBox" ToolTip="Separate multiple files with ;"/>
          <Button Grid.Row="1" Grid.Column="2" x:Name="NessusBtn" Content="Browse..."/>
          <Label Grid.Row="2" Content="GPO backup folder"/>
          <TextBox Grid.Row="2" Grid.Column="1" x:Name="GpoBox" ToolTip="Folder containing the {GUID} backup folders"/>
          <Button Grid.Row="2" Grid.Column="2" x:Name="GpoBtn" Content="Browse..."/>
          <Label Grid.Row="3" Content="Blank CKLB (optional)"/>
          <TextBox Grid.Row="3" Grid.Column="1" x:Name="CklbBox" ToolTip="Only needed for Export CKLB"/>
          <Button Grid.Row="3" Grid.Column="2" x:Name="CklbBtn" Content="Browse..."/>
          <StackPanel Grid.Row="4" Grid.Column="1" Grid.ColumnSpan="2" Orientation="Horizontal" Margin="0,6,0,0">
            <Label Content="GPO scope:"/>
            <RadioButton x:Name="ScopeBackup" Content="All selected GPOs in the backup" IsChecked="True" VerticalAlignment="Center" Margin="4,0,12,0"/>
            <RadioButton x:Name="ScopeAd" Content="Host's real GPO links (Active Directory)" VerticalAlignment="Center"/>
            <Button x:Name="RunBtn" Content="  Run  " FontWeight="Bold" Margin="24,2,4,2"/>
          </StackPanel>
        </Grid>
      </GroupBox>

      <GroupBox Header="GPOs to include" Grid.Column="1" Padding="4" Margin="8,0,0,0">
        <DockPanel>
          <StackPanel DockPanel.Dock="Bottom" Orientation="Horizontal">
            <Button x:Name="AllGpoBtn" Content="All"/>
            <Button x:Name="NoneGpoBtn" Content="None"/>
            <Button x:Name="NoDcBtn" Content="Exclude DC GPOs" ToolTip="Clears GPOs with 'DC' in the name"/>
          </StackPanel>
          <ScrollViewer VerticalScrollBarVisibility="Auto" Height="130">
            <StackPanel x:Name="GpoList"><TextBlock Foreground="Gray" Text="Choose a GPO backup folder to list its GPOs." TextWrapping="Wrap"/></StackPanel>
          </ScrollViewer>
        </DockPanel>
      </GroupBox>
    </Grid>

    <Grid DockPanel.Dock="Top" Margin="0,8,0,4">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="Auto"/><ColumnDefinition Width="220"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="120"/>
        <ColumnDefinition Width="Auto"/><ColumnDefinition Width="120"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <Label Grid.Column="0" Content="Search:"/>
      <TextBox Grid.Column="1" x:Name="FilterBox" ToolTip="Matches STIG ID, V-ID, title, GPO or value"/>
      <Label Grid.Column="2" Content="Tenable:"/>
      <ComboBox Grid.Column="3" x:Name="ResultCombo" Margin="4,2" SelectedIndex="0">
        <ComboBoxItem Content="All"/><ComboBoxItem Content="FAILED"/><ComboBoxItem Content="PASSED"/><ComboBoxItem Content="WARNING"/>
      </ComboBox>
      <Label Grid.Column="4" Content="GPO state:"/>
      <ComboBox Grid.Column="5" x:Name="StateCombo" Margin="4,2" SelectedIndex="0">
        <ComboBoxItem Content="All"/><ComboBoxItem Content="Compliant"/><ComboBoxItem Content="Mismatch"/><ComboBoxItem Content="Configured"/>
        <ComboBoxItem Content="None"/><ComboBoxItem Content="NotMapped"/>
      </ComboBox>
      <CheckBox Grid.Column="6" x:Name="UncheckedBox" Content="Show rules Tenable didn't check" VerticalAlignment="Center" Margin="12,0"/>
      <TextBlock Grid.Column="7" x:Name="SummaryText" VerticalAlignment="Center" HorizontalAlignment="Right" Foreground="#444"/>
    </Grid>

    <DockPanel DockPanel.Dock="Bottom" Margin="0,4,0,0">
      <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Bottom">
        <Button x:Name="CsvBtn" Content="Export CSV..." IsEnabled="False"/>
        <Button x:Name="CklbExportBtn" Content="Export CKLB..." IsEnabled="False"/>
      </StackPanel>
      <TextBox x:Name="DetailBox" Height="110" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
               FontFamily="Consolas" Text="Select a row to see the finding details and recommended action."/>
    </DockPanel>

    <DataGrid x:Name="ResultsGrid" AutoGenerateColumns="False" IsReadOnly="True" CanUserSortColumns="True" SelectionMode="Single"
              GridLinesVisibility="Horizontal" HeadersVisibility="Column" AlternatingRowBackground="#F7F7F7">
      <DataGrid.RowStyle>
        <Style TargetType="DataGridRow">
          <Style.Triggers>
            <DataTrigger Binding="{Binding TenableResult}" Value="FAILED"><Setter Property="Background" Value="#FDE2E1"/></DataTrigger>
            <DataTrigger Binding="{Binding TenableResult}" Value="WARNING"><Setter Property="Background" Value="#FFF4CE"/></DataTrigger>
          </Style.Triggers>
        </Style>
      </DataGrid.RowStyle>
      <DataGrid.Columns>
        <DataGridTextColumn Header="Host" Binding="{Binding HostKey}"/>
        <DataGridTextColumn Header="CAT" Binding="{Binding Cat}"/>
        <DataGridTextColumn Header="STIG ID" Binding="{Binding StigId}"/>
        <DataGridTextColumn Header="V-ID" Binding="{Binding VulnId}"/>
        <DataGridTextColumn Header="Tenable" Binding="{Binding TenableResult}"/>
        <DataGridTextColumn Header="GPO state" Binding="{Binding GpoState}"/>
        <DataGridTextColumn Header="Winning GPO" Binding="{Binding WinningGpo}" Width="220"/>
        <DataGridTextColumn Header="GPO value" Binding="{Binding WinningGpoValue}" Width="140"/>
        <DataGridTextColumn Header="Conflict" Binding="{Binding GpoConflict}"/>
        <DataGridTextColumn Header="Type" Binding="{Binding RuleType}"/>
        <DataGridTextColumn Header="Title" Binding="{Binding Title}" Width="*"/>
      </DataGrid.Columns>
    </DataGrid>
    </DockPanel>
    </TabItem>

    <TabItem Header="Compare GPO backups">
      <DockPanel Margin="4">
        <GroupBox DockPanel.Dock="Top" Header="Backups to compare" Padding="4">
          <Grid>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="150"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="Auto"/><ColumnDefinition Width="110"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="140"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions><RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/></Grid.RowDefinitions>
            <Label Grid.Row="0" Content="Reference backup"/>
            <TextBox Grid.Row="0" Grid.Column="1" x:Name="CmpABox" ToolTip="Folder containing {GUID} backup folders, or one {GUID} folder"/>
            <Button Grid.Row="0" Grid.Column="2" x:Name="CmpABtn" Content="Browse..."/>
            <Label Grid.Row="0" Grid.Column="3" Content="Label:"/>
            <TextBox Grid.Row="0" Grid.Column="4" x:Name="CmpALabel" Text="Production"/>
            <Label Grid.Row="0" Grid.Column="5" Content="Exclude GPOs (regex):"/>
            <TextBox Grid.Row="0" Grid.Column="6" x:Name="CmpAExclude" ToolTip="GPO names matching this are ignored, e.g. \bDC\b"/>
            <Label Grid.Row="1" Content="Difference backup"/>
            <TextBox Grid.Row="1" Grid.Column="1" x:Name="CmpBBox" ToolTip="Folder containing {GUID} backup folders, or one {GUID} folder"/>
            <Button Grid.Row="1" Grid.Column="2" x:Name="CmpBBtn" Content="Browse..."/>
            <Label Grid.Row="1" Grid.Column="3" Content="Label:"/>
            <TextBox Grid.Row="1" Grid.Column="4" x:Name="CmpBLabel" Text="Baseline"/>
            <Label Grid.Row="1" Grid.Column="5" Content="Exclude GPOs (regex):"/>
            <TextBox Grid.Row="1" Grid.Column="6" x:Name="CmpBExclude" ToolTip="GPO names matching this are ignored, e.g. \bDC\b"/>
            <Label Grid.Row="2" Content="STIG XCCDF (optional)"/>
            <TextBox Grid.Row="2" Grid.Column="1" x:Name="CmpXccdfBox" ToolTip="Adds STIG ID, V-ID, CAT and a STIG evaluation for each side"/>
            <Button Grid.Row="2" Grid.Column="2" x:Name="CmpXccdfBtn" Content="Browse..."/>
            <StackPanel Grid.Row="3" Grid.Column="1" Grid.ColumnSpan="6" Orientation="Horizontal" Margin="0,6,0,0">
              <Button x:Name="CmpSwapBtn" Content="Swap reference / difference"/>
              <Button x:Name="CmpRunBtn" Content="  Compare  " FontWeight="Bold" Margin="24,2,4,2"/>
            </StackPanel>
          </Grid>
        </GroupBox>

        <Grid DockPanel.Dock="Top" Margin="0,8,0,4">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/><ColumnDefinition Width="220"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="150"/>
            <ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <Label Grid.Column="0" Content="Search:"/>
          <TextBox Grid.Column="1" x:Name="CmpFilterBox" ToolTip="Matches STIG ID, V-ID, setting, values or GPO names"/>
          <Label Grid.Column="2" Content="Change:"/>
          <ComboBox Grid.Column="3" x:Name="CmpChangeCombo" Margin="4,2" SelectedIndex="0">
            <ComboBoxItem Content="All"/><ComboBoxItem Content="Different value"/><ComboBoxItem Content="Only in reference"/>
            <ComboBoxItem Content="Only in difference"/><ComboBoxItem Content="Same"/>
          </ComboBox>
          <CheckBox Grid.Column="4" x:Name="CmpHideSameBox" Content="Hide identical settings" IsChecked="True" VerticalAlignment="Center" Margin="12,0"/>
          <CheckBox Grid.Column="5" x:Name="CmpStigOnlyBox" Content="STIG settings only" VerticalAlignment="Center" Margin="4,0"/>
          <TextBlock Grid.Column="6" x:Name="CmpSummaryText" VerticalAlignment="Center" HorizontalAlignment="Right" Foreground="#444"/>
        </Grid>

        <DockPanel DockPanel.Dock="Bottom" Margin="0,4,0,0">
          <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Bottom">
            <Button x:Name="CmpCsvBtn" Content="Export CSV..." IsEnabled="False"/>
          </StackPanel>
          <TextBox x:Name="CmpDetailBox" Height="90" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
                   FontFamily="Consolas" Text="Select a row to see both values and the GPOs that set them."/>
        </DockPanel>

        <DataGrid x:Name="CmpGrid" AutoGenerateColumns="False" IsReadOnly="True" CanUserSortColumns="True" SelectionMode="Single"
                  GridLinesVisibility="Horizontal" HeadersVisibility="Column" AlternatingRowBackground="#F7F7F7">
          <DataGrid.RowStyle>
            <Style TargetType="DataGridRow">
              <Style.Triggers>
                <DataTrigger Binding="{Binding Change}" Value="Different value"><Setter Property="Background" Value="#FDE2E1"/></DataTrigger>
                <DataTrigger Binding="{Binding Change}" Value="Only in reference"><Setter Property="Background" Value="#FFF4CE"/></DataTrigger>
                <DataTrigger Binding="{Binding Change}" Value="Only in difference"><Setter Property="Background" Value="#E3F0FF"/></DataTrigger>
              </Style.Triggers>
            </Style>
          </DataGrid.RowStyle>
          <DataGrid.Columns>
            <DataGridTextColumn Header="Change" Binding="{Binding Change}"/>
            <DataGridTextColumn Header="CAT" Binding="{Binding Cat}"/>
            <DataGridTextColumn Header="STIG ID" Binding="{Binding StigId}"/>
            <DataGridTextColumn Header="V-ID" Binding="{Binding VulnId}"/>
            <DataGridTextColumn Header="Setting" Binding="{Binding Setting}" Width="*"/>
            <DataGridTextColumn Header="Reference value" Binding="{Binding ReferenceValue}" Width="130"/>
            <DataGridTextColumn Header="Difference value" Binding="{Binding DifferenceValue}" Width="130"/>
            <DataGridTextColumn Header="Reference STIG" Binding="{Binding ReferenceStig}"/>
            <DataGridTextColumn Header="Difference STIG" Binding="{Binding DifferenceStig}"/>
            <DataGridTextColumn Header="Conflict" Binding="{Binding InternalConflict}"/>
          </DataGrid.Columns>
        </DataGrid>
      </DockPanel>
    </TabItem>
    </TabControl>
  </DockPanel>
</Window>
'@
#endregion

$window = [Windows.Markup.XamlReader]::Load([Xml.XmlNodeReader]::new($xaml))
$ui = @{}
$xaml.SelectNodes('//*[@*[local-name()="Name"]]') | ForEach-Object {
    $name = $_.Attributes | Where-Object LocalName -eq 'Name' | Select-Object -ExpandProperty Value
    $ui[$name] = $window.FindName($name)
}

#region Helpers
function Set-Status([string]$Text) { $ui.StatusText.Text = $Text }

function Save-Settings {
    try {
        $dir = Split-Path $script:SettingsPath
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        [pscustomobject]@{
            Xccdf = $ui.XccdfBox.Text; Nessus = $ui.NessusBox.Text; Gpo = $ui.GpoBox.Text; Cklb = $ui.CklbBox.Text
            ScopeAd = [bool]$ui.ScopeAd.IsChecked
            CmpA = $ui.CmpABox.Text; CmpB = $ui.CmpBBox.Text; CmpALabel = $ui.CmpALabel.Text; CmpBLabel = $ui.CmpBLabel.Text
            CmpAExclude = $ui.CmpAExclude.Text; CmpBExclude = $ui.CmpBExclude.Text; CmpXccdf = $ui.CmpXccdfBox.Text
        } | ConvertTo-Json | Set-Content -Path $script:SettingsPath -Encoding utf8
    } catch { }
}

function Import-Settings {
    if (-not (Test-Path $script:SettingsPath)) { return }
    try {
        $s = Get-Content $script:SettingsPath -Raw | ConvertFrom-Json
        $ui.XccdfBox.Text = "$($s.Xccdf)"; $ui.NessusBox.Text = "$($s.Nessus)"
        $ui.GpoBox.Text = "$($s.Gpo)"; $ui.CklbBox.Text = "$($s.Cklb)"
        if ($s.ScopeAd) { $ui.ScopeAd.IsChecked = $true }
        foreach ($pair in @(@('CmpA', 'CmpABox'), @('CmpB', 'CmpBBox'), @('CmpALabel', 'CmpALabel'), @('CmpBLabel', 'CmpBLabel'),
                            @('CmpAExclude', 'CmpAExclude'), @('CmpBExclude', 'CmpBExclude'), @('CmpXccdf', 'CmpXccdfBox'))) {
            $v = $s.PSObject.Properties[$pair[0]]
            if ($v -and $v.Value) { $ui[$pair[1]].Text = "$($v.Value)" }
        }
        if (-not $ui.CmpXccdfBox.Text) { $ui.CmpXccdfBox.Text = $ui.XccdfBox.Text }
    } catch { }
}

function Select-File([string]$Filter, [switch]$Multi, [string]$Current) {
    $dlg = [Microsoft.Win32.OpenFileDialog]::new()
    $dlg.Filter = $Filter; $dlg.Multiselect = [bool]$Multi
    $first = ($Current -split ';')[0].Trim()
    if ($first -and (Test-Path (Split-Path $first -Parent) -ErrorAction SilentlyContinue)) { $dlg.InitialDirectory = Split-Path $first -Parent }
    if ($dlg.ShowDialog($window)) { return ($dlg.FileNames -join '; ') }
    $null
}

function Select-Folder([string]$Description, [string]$Current) {
    $dlg = [System.Windows.Forms.FolderBrowserDialog]::new()
    $dlg.Description = $Description; $dlg.UseDescriptionForTitle = $true
    if ($Current -and (Test-Path $Current)) { $dlg.SelectedPath = $Current }
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $dlg.SelectedPath }
    $null
}

function Show-Error([string]$Message) {
    [System.Windows.MessageBox]::Show($window, $Message, 'StigCorrelator', 'OK', 'Error') | Out-Null
}

function Get-GpoBackupList([string]$Path) {
    # Lists GPO name + GUID for each backup folder without parsing every setting.
    $module = Get-Module StigCorrelator
    $folders = if (Test-Path -LiteralPath (Join-Path $Path 'DomainSysvol')) { @(Get-Item -LiteralPath $Path) }
               else { @(Get-ChildItem -LiteralPath $Path -Directory) }
    foreach ($f in $folders) {
        $meta = & $module { param($p) Read-GpoBackupInfo -BackupFolder $p } $f.FullName
        if ($meta) { $meta }
    }
}

function Add-GpoListMessage([string]$Text, $Brush) {
    $tb = [Windows.Controls.TextBlock]::new()
    $tb.Text = $Text; $tb.Foreground = $Brush; $tb.TextWrapping = [Windows.TextWrapping]::Wrap
    [void]$ui.GpoList.Children.Add($tb)
}

function Update-GpoList {
    $path = $ui.GpoBox.Text.Trim()
    $script:GpoListPath = $path
    $ui.GpoList.Children.Clear()
    if (-not $path -or -not (Test-Path -LiteralPath $path)) {
        Add-GpoListMessage 'Choose a GPO backup folder to list its GPOs.' ([Windows.Media.Brushes]::Gray)
        return
    }
    $gpos = @(Get-GpoBackupList $path | Sort-Object GpoName)
    if (-not $gpos.Count) {
        Add-GpoListMessage 'No GPO backups found in this folder.' ([Windows.Media.Brushes]::Firebrick)
        return
    }
    foreach ($g in $gpos) {
        $cb = [Windows.Controls.CheckBox]::new()
        $cb.Content = $g.GpoName; $cb.Tag = $g.GpoGuid; $cb.IsChecked = $true; $cb.Margin = [Windows.Thickness]::new(2)
        $cb.ToolTip = "{$($g.GpoGuid)}"
        $ui.GpoList.Children.Add($cb) | Out-Null
    }
    Set-Status "$($gpos.Count) GPO(s) found in the backup."
}

function Get-GpoCheckBoxes { @($ui.GpoList.Children | Where-Object { $_ -is [Windows.Controls.CheckBox] }) }

function ConvertTo-LikeLiteral([string]$Text) {
    # Escapes a string for use inside a DataView RowFilter LIKE pattern.
    $sb = [Text.StringBuilder]::new()
    foreach ($ch in $Text.ToCharArray()) {
        switch ($ch) {
            '['     { [void]$sb.Append('[[]') }
            ']'     { [void]$sb.Append('[]]') }
            '*'     { [void]$sb.Append('[*]') }
            '%'     { [void]$sb.Append('[%]') }
            "'"     { [void]$sb.Append("''") }
            default { [void]$sb.Append($ch) }
        }
    }
    $sb.ToString()
}

$script:Columns = 'HostKey', 'Cat', 'StigId', 'VulnId', 'RuleId', 'Title', 'RuleType', 'TenableResult', 'TenableActual',
                  'TenableExpected', 'GpoState', 'WinningGpo', 'WinningGpoValue', 'GpoConflict', 'Status', 'Action', 'FindingDetails'

function Set-GridData([object[]]$Rows) {
    $table = [Data.DataTable]::new('Results')
    foreach ($c in $script:Columns) { [void]$table.Columns.Add($c, [string]) }
    foreach ($r in $Rows) {
        $dr = $table.NewRow()
        foreach ($c in $script:Columns) { $dr[$c] = "$($r.$c)" }
        [void]$table.Rows.Add($dr)
    }
    $script:Table = $table
    $ui.ResultsGrid.ItemsSource = $table.DefaultView
    Update-Filter
}

function Update-Filter {
    if (-not $script:Table) { return }
    $parts = [Collections.Generic.List[string]]::new()
    if (-not $ui.UncheckedBox.IsChecked) { $parts.Add("TenableResult <> 'NO RESULT'") }
    $res = $ui.ResultCombo.SelectedItem.Content
    if ($res -and $res -ne 'All') { $parts.Add("TenableResult = '$res'") }
    $state = $ui.StateCombo.SelectedItem.Content
    if ($state -and $state -ne 'All') { $parts.Add("GpoState = '$state'") }
    $q = $ui.FilterBox.Text.Trim()
    if ($q) {
        $l = ConvertTo-LikeLiteral $q
        $parts.Add("(StigId LIKE '*$l*' OR VulnId LIKE '*$l*' OR Title LIKE '*$l*' OR WinningGpo LIKE '*$l*' OR WinningGpoValue LIKE '*$l*' OR HostKey LIKE '*$l*')")
    }
    $view = $script:Table.DefaultView
    $view.RowFilter = $parts -join ' AND '

    $shown = $view.Count
    $failed = @($view | Where-Object { $_['TenableResult'] -eq 'FAILED' }).Count
    $mismatch = @($view | Where-Object { $_['GpoState'] -eq 'Mismatch' }).Count
    $none = @($view | Where-Object { $_['GpoState'] -eq 'None' }).Count
    $ui.SummaryText.Text = "Showing $shown   |   FAILED: $failed   GPO mismatch: $mismatch   Not in any GPO: $none"
}

function Set-Busy([bool]$Busy) {
    foreach ($n in 'RunBtn', 'XccdfBtn', 'NessusBtn', 'GpoBtn', 'CklbBtn', 'AllGpoBtn', 'NoneGpoBtn', 'NoDcBtn') { $ui[$n].IsEnabled = -not $Busy }
    $ui.CsvBtn.IsEnabled = (-not $Busy) -and $script:Merged.Count -gt 0
    $ui.CklbExportBtn.IsEnabled = (-not $Busy) -and $script:Merged.Count -gt 0
    $window.Cursor = if ($Busy) { [Windows.Input.Cursors]::Wait } else { $null }
}
#endregion

#region Events
$ui.XccdfBtn.Add_Click({ $f = Select-File 'XCCDF (*.xml)|*.xml|All files (*.*)|*.*' -Current $ui.XccdfBox.Text; if ($f) { $ui.XccdfBox.Text = $f } })
$ui.NessusBtn.Add_Click({ $f = Select-File 'Tenable scan (*.nessus)|*.nessus|All files (*.*)|*.*' -Multi -Current $ui.NessusBox.Text; if ($f) { $ui.NessusBox.Text = $f } })
$ui.CklbBtn.Add_Click({ $f = Select-File 'STIG Viewer 3 checklist (*.cklb)|*.cklb|All files (*.*)|*.*' -Current $ui.CklbBox.Text; if ($f) { $ui.CklbBox.Text = $f } })
$ui.GpoBtn.Add_Click({
    $f = Select-Folder 'Select the GPO backup folder (the one containing the {GUID} folders)' $ui.GpoBox.Text
    if ($f) { $ui.GpoBox.Text = $f; try { Update-GpoList } catch { Show-Error $_.Exception.Message } }
})
# Re-list GPOs only when the typed path actually changes, so manual unchecks are kept.
$ui.GpoBox.Add_LostFocus({ if ($ui.GpoBox.Text.Trim() -ne $script:GpoListPath) { try { Update-GpoList } catch { } } })

$ui.AllGpoBtn.Add_Click({ Get-GpoCheckBoxes | ForEach-Object { $_.IsChecked = $true } })
$ui.NoneGpoBtn.Add_Click({ Get-GpoCheckBoxes | ForEach-Object { $_.IsChecked = $false } })
$ui.NoDcBtn.Add_Click({ Get-GpoCheckBoxes | Where-Object { "$($_.Content)" -match '\bDC\b' } | ForEach-Object { $_.IsChecked = $false } })

$ui.FilterBox.Add_TextChanged({ Update-Filter })
$ui.ResultCombo.Add_SelectionChanged({ Update-Filter })
$ui.StateCombo.Add_SelectionChanged({ Update-Filter })
$ui.UncheckedBox.Add_Click({ Update-Filter })

$ui.ResultsGrid.Add_SelectionChanged({
    $row = $ui.ResultsGrid.SelectedItem
    if ($row -is [Data.DataRowView]) {
        $ui.DetailBox.Text = "$($row['StigId'])  $($row['VulnId'])  $($row['Cat'])  -  $($row['Title'])`r`n" +
                             "Type: $($row['RuleType'])    Checklist status: $($row['Status'])`r`n`r`n" +
                             "$($row['FindingDetails'])`r`n`r`nAction: $($row['Action'])"
    }
})

$ui.RunBtn.Add_Click({
    $xccdf  = $ui.XccdfBox.Text.Trim()
    $nessus = @($ui.NessusBox.Text -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $gpo    = $ui.GpoBox.Text.Trim()
    $missing = @()
    if (-not $xccdf -or -not (Test-Path -LiteralPath $xccdf)) { $missing += 'STIG Manual XCCDF' }
    if (-not $nessus.Count -or @($nessus | Where-Object { -not (Test-Path -LiteralPath $_) }).Count) { $missing += 'Tenable .nessus file(s)' }
    if (-not $gpo -or -not (Test-Path -LiteralPath $gpo)) { $missing += 'GPO backup folder' }
    if ($missing) { Show-Error ("Check these inputs:`r`n - " + ($missing -join "`r`n - ")); return }

    $boxes = Get-GpoCheckBoxes
    if (-not $boxes.Count) { Update-GpoList; $boxes = Get-GpoCheckBoxes }
    $selected = @($boxes | Where-Object IsChecked | ForEach-Object { "$($_.Tag)" })
    if ($boxes.Count -and -not $selected.Count) { Show-Error 'Select at least one GPO to include.'; return }

    Save-Settings
    $params = @{
        XccdfPath = $xccdf; NessusPath = $nessus; GpoBackupPath = $gpo; IncludeUnchecked = $true
        Scope = $(if ($ui.ScopeAd.IsChecked) { 'ActiveDirectory' } else { 'GpoBackup' })
    }
    if ($selected.Count -and $selected.Count -lt $boxes.Count) { $params.IncludeGpoGuid = $selected }

    Set-Busy $true
    Set-Status 'Running analysis: parsing scan, XCCDF and GPO backup...'
    $script:Worker = [powershell]::Create()
    [void]$script:Worker.AddScript({
        param($ModulePath, $Params)
        Import-Module $ModulePath -Force
        Invoke-StigAnalysis @Params
    }).AddArgument($script:ModulePath).AddArgument($params)
    $script:Handle = $script:Worker.BeginInvoke()
    $script:Timer.Start()
})

$script:Timer = [Windows.Threading.DispatcherTimer]::new()
$script:Timer.Interval = [TimeSpan]::FromMilliseconds(300)
$script:Timer.Add_Tick({
    if (-not $script:Handle.IsCompleted) { return }
    $script:Timer.Stop()
    try {
        $output = @($script:Worker.EndInvoke($script:Handle))
        $errors = @($script:Worker.Streams.Error)
        $analysis = $output | Where-Object { $_.PSObject.Properties.Name -contains 'AllResults' } | Select-Object -First 1
        $warnings = @($script:Worker.Streams.Warning | ForEach-Object { $_.Message } | Select-Object -Unique)
        if (-not $analysis) {
            $msg = if ($errors.Count) { $errors[0].Exception.Message } else { 'The analysis returned no results.' }
            throw $msg
        }
        $script:Merged = @($analysis.AllResults)
        Set-GridData $script:Merged
        $scopeNote = ($analysis.Scope | Group-Object Source | ForEach-Object { "$($_.Count) host(s) via $($_.Name)" }) -join ', '
        $status = "Done. Hosts: $($analysis.Hosts.Count)  |  Tenable checks: $($analysis.TenableChecks)  |  Scan STIG IDs found in XCCDF: $($analysis.TenableMatchPercent)%  |  " +
                  "GPOs: $($analysis.GpoCount)  |  GPO-to-STIG matches: $($analysis.GpoStigMatches)  |  Scope: $scopeNote"
        if ($warnings.Count) { $status += "  |  Warnings: $($warnings.Count) (hover)"; $ui.StatusText.ToolTip = ($warnings -join "`n") }
        Set-Status $status
        if ($null -ne $analysis.TenableMatchPercent -and $analysis.TenableMatchPercent -lt 95) {
            Show-Error "Only $($analysis.TenableMatchPercent)% of the scan's STIG IDs exist in this XCCDF. The scan and the XCCDF are probably from different STIG releases."
        }
    } catch {
        $e = $_.Exception
        while ($e.InnerException) { $e = $e.InnerException }
        Set-Status 'Analysis failed.'
        Show-Error "Analysis failed:`r`n$($e.Message)"
    } finally {
        $script:Worker.Dispose(); $script:Worker = $null
        Set-Busy $false
    }
})

$ui.CsvBtn.Add_Click({
    $dlg = [Microsoft.Win32.SaveFileDialog]::new()
    $dlg.Filter = 'CSV (*.csv)|*.csv'; $dlg.FileName = "stig-gpo-results-$(Get-Date -Format yyyyMMdd-HHmm).csv"
    if (-not $dlg.ShowDialog($window)) { return }
    try {
        $view = $script:Table.DefaultView
        $rows = foreach ($r in $view) { $o = [ordered]@{}; foreach ($c in $script:Columns) { $o[$c] = $r[$c] }; [pscustomobject]$o }
        @($rows) | Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding utf8
        Set-Status "Exported $(@($rows).Count) row(s) (current filter) to $($dlg.FileName)"
    } catch { Show-Error $_.Exception.Message }
})

$ui.CklbExportBtn.Add_Click({
    $template = $ui.CklbBox.Text.Trim()
    if (-not $template -or -not (Test-Path -LiteralPath $template)) {
        Show-Error 'Choose a blank CKLB first (STIG Viewer 3 checklist created from the same STIG release as the XCCDF).'; return
    }
    $out = Select-Folder 'Select the output folder for the .cklb checklists' (Split-Path $template -Parent)
    if (-not $out) { return }
    try {
        Save-Settings
        $made = @(Export-StigCklb -CklbTemplatePath $template -MergedResults $script:Merged -OutDir $out)
        $unmatched = ($made | Measure-Object UnmatchedTemplateRules -Sum).Sum
        $msg = "Wrote $($made.Count) checklist(s) to $out."
        if ($unmatched) { $msg += " $unmatched template rule(s) had no match; the CKLB may be from a different STIG release." }
        Set-Status $msg
    } catch { Show-Error $_.Exception.Message }
})

$window.Add_Closing({
    Save-Settings
    foreach ($w in $script:Worker, $script:CmpWorker) { if ($w) { try { $w.Stop() } catch { } } }
})
#endregion

#region Compare tab
$script:CmpColumns = 'Change', 'Cat', 'StigId', 'VulnId', 'RuleTitle', 'Setting', 'ReferenceValue', 'DifferenceValue',
                     'ReferenceStig', 'DifferenceStig', 'ReferenceGpos', 'DifferenceGpos', 'InternalConflict'
$script:CmpRows = @()
$script:CmpWorker = $null

function Set-CmpBusy([bool]$Busy) {
    foreach ($n in 'CmpRunBtn', 'CmpABtn', 'CmpBBtn', 'CmpXccdfBtn', 'CmpSwapBtn') { $ui[$n].IsEnabled = -not $Busy }
    $ui.CmpCsvBtn.IsEnabled = (-not $Busy) -and $script:CmpRows.Count -gt 0
    $window.Cursor = if ($Busy) { [Windows.Input.Cursors]::Wait } else { $null }
}

function Set-CmpGridData([object[]]$Rows) {
    $table = [Data.DataTable]::new('Compare')
    foreach ($c in $script:CmpColumns) { [void]$table.Columns.Add($c, [string]) }
    foreach ($r in $Rows) {
        $dr = $table.NewRow()
        foreach ($c in $script:CmpColumns) { $dr[$c] = "$($r.$c)" }
        [void]$table.Rows.Add($dr)
    }
    $script:CmpTable = $table
    $ui.CmpGrid.ItemsSource = $table.DefaultView
    Update-CmpFilter
}

function Update-CmpFilter {
    if (-not $script:CmpTable) { return }
    $parts = [Collections.Generic.List[string]]::new()
    $change = $ui.CmpChangeCombo.SelectedItem.Content
    if ($change -and $change -ne 'All') { $parts.Add("Change = '$change'") }
    elseif ($ui.CmpHideSameBox.IsChecked) { $parts.Add("Change <> 'Same'") }
    if ($ui.CmpStigOnlyBox.IsChecked) { $parts.Add("StigId <> ''") }
    $q = $ui.CmpFilterBox.Text.Trim()
    if ($q) {
        $l = ConvertTo-LikeLiteral $q
        $parts.Add("(StigId LIKE '*$l*' OR VulnId LIKE '*$l*' OR Setting LIKE '*$l*' OR ReferenceValue LIKE '*$l*' OR DifferenceValue LIKE '*$l*' OR ReferenceGpos LIKE '*$l*' OR DifferenceGpos LIKE '*$l*' OR RuleTitle LIKE '*$l*')")
    }
    $view = $script:CmpTable.DefaultView
    $view.RowFilter = $parts -join ' AND '
    $all = $script:CmpTable.Rows
    $count = { param($v) @($all | Where-Object { $_['Change'] -eq $v }).Count }
    $ui.CmpSummaryText.Text = "Showing $($view.Count)   |   Different: $(& $count 'Different value')   Only in reference: $(& $count 'Only in reference')   Only in difference: $(& $count 'Only in difference')   Same: $(& $count 'Same')"
}

$ui.CmpABtn.Add_Click({ $f = Select-Folder 'Select the reference GPO backup folder' $ui.CmpABox.Text; if ($f) { $ui.CmpABox.Text = $f } })
$ui.CmpBBtn.Add_Click({ $f = Select-Folder 'Select the difference GPO backup folder' $ui.CmpBBox.Text; if ($f) { $ui.CmpBBox.Text = $f } })
$ui.CmpXccdfBtn.Add_Click({ $f = Select-File 'XCCDF (*.xml)|*.xml|All files (*.*)|*.*' -Current $ui.CmpXccdfBox.Text; if ($f) { $ui.CmpXccdfBox.Text = $f } })
$ui.CmpSwapBtn.Add_Click({
    foreach ($pair in @(@('CmpABox', 'CmpBBox'), @('CmpALabel', 'CmpBLabel'), @('CmpAExclude', 'CmpBExclude'))) {
        $t = $ui[$pair[0]].Text; $ui[$pair[0]].Text = $ui[$pair[1]].Text; $ui[$pair[1]].Text = $t
    }
})
$ui.CmpFilterBox.Add_TextChanged({ Update-CmpFilter })
$ui.CmpChangeCombo.Add_SelectionChanged({ Update-CmpFilter })
$ui.CmpHideSameBox.Add_Click({ Update-CmpFilter })
$ui.CmpStigOnlyBox.Add_Click({ Update-CmpFilter })

$ui.CmpGrid.Add_SelectionChanged({
    $row = $ui.CmpGrid.SelectedItem
    if ($row -is [Data.DataRowView]) {
        $ra = $ui.CmpALabel.Text; $rb = $ui.CmpBLabel.Text
        $head = if ($row['StigId']) { "$($row['StigId'])  $($row['VulnId'])  $($row['Cat'])  -  $($row['RuleTitle'])`r`n" } else { "(not a STIG setting)`r`n" }
        $ui.CmpDetailBox.Text = $head + "Setting: $($row['Setting'])`r`n" +
            "$ra : $($row['ReferenceValue'])   [$($row['ReferenceStig'])]   set by: $($row['ReferenceGpos'])`r`n" +
            "$rb : $($row['DifferenceValue'])   [$($row['DifferenceStig'])]   set by: $($row['DifferenceGpos'])"
    }
})

$ui.CmpRunBtn.Add_Click({
    $a = $ui.CmpABox.Text.Trim(); $b = $ui.CmpBBox.Text.Trim(); $x = $ui.CmpXccdfBox.Text.Trim()
    $missing = @()
    if (-not $a -or -not (Test-Path -LiteralPath $a)) { $missing += 'Reference backup folder' }
    if (-not $b -or -not (Test-Path -LiteralPath $b)) { $missing += 'Difference backup folder' }
    if ($x -and -not (Test-Path -LiteralPath $x)) { $missing += 'STIG XCCDF (leave blank to compare without STIG IDs)' }
    foreach ($rx in $ui.CmpAExclude.Text, $ui.CmpBExclude.Text) {
        if ($rx) { try { [void][regex]::new($rx) } catch { $missing += "Exclude pattern '$rx' is not a valid regex" } }
    }
    if ($missing) { Show-Error ("Check these inputs:`r`n - " + ($missing -join "`r`n - ")); return }

    $labelA = if ($ui.CmpALabel.Text.Trim()) { $ui.CmpALabel.Text.Trim() } else { 'Reference' }
    $labelB = if ($ui.CmpBLabel.Text.Trim()) { $ui.CmpBLabel.Text.Trim() } else { 'Difference' }
    $ui.CmpGrid.Columns[5].Header = "$labelA value"; $ui.CmpGrid.Columns[6].Header = "$labelB value"
    $ui.CmpGrid.Columns[7].Header = "$labelA STIG";  $ui.CmpGrid.Columns[8].Header = "$labelB STIG"

    Save-Settings
    $params = @{ ReferencePath = $a; DifferencePath = $b; ReferenceLabel = $labelA; DifferenceLabel = $labelB; IncludeSame = $true }
    if ($x) { $params.XccdfPath = $x }
    if ($ui.CmpAExclude.Text) { $params.ReferenceExclude = $ui.CmpAExclude.Text }
    if ($ui.CmpBExclude.Text) { $params.DifferenceExclude = $ui.CmpBExclude.Text }

    Set-CmpBusy $true
    Set-Status "Comparing $labelA with $labelB..."
    $script:CmpWorker = [powershell]::Create()
    [void]$script:CmpWorker.AddScript({
        param($ModulePath, $Params)
        Import-Module $ModulePath -Force
        Compare-GpoBackup @Params
    }).AddArgument($script:ModulePath).AddArgument($params)
    $script:CmpHandle = $script:CmpWorker.BeginInvoke()
    $script:CmpTimer.Start()
})

$script:CmpTimer = [Windows.Threading.DispatcherTimer]::new()
$script:CmpTimer.Interval = [TimeSpan]::FromMilliseconds(300)
$script:CmpTimer.Add_Tick({
    if (-not $script:CmpHandle.IsCompleted) { return }
    $script:CmpTimer.Stop()
    try {
        $output = @($script:CmpWorker.EndInvoke($script:CmpHandle))
        $errors = @($script:CmpWorker.Streams.Error)
        if (-not $output.Count -and $errors.Count) { throw $errors[0].Exception }
        $warnings = @($script:CmpWorker.Streams.Warning | ForEach-Object { $_.Message } | Select-Object -Unique)
        $script:CmpRows = $output
        Set-CmpGridData $script:CmpRows
        $status = "Compare done: $($output.Count) setting(s) across both backups."
        if (-not $ui.CmpXccdfBox.Text.Trim()) { $status += ' No XCCDF selected, so STIG columns are empty.' }
        if ($warnings.Count) { $status += "  |  Warnings: $($warnings.Count) (hover)"; $ui.StatusText.ToolTip = ($warnings -join "`n") }
        Set-Status $status
    } catch {
        $e = $_.Exception
        while ($e.InnerException) { $e = $e.InnerException }
        Set-Status 'Compare failed.'
        Show-Error "Compare failed:`r`n$($e.Message)"
    } finally {
        $script:CmpWorker.Dispose(); $script:CmpWorker = $null
        Set-CmpBusy $false
    }
})

$ui.CmpCsvBtn.Add_Click({
    $dlg = [Microsoft.Win32.SaveFileDialog]::new()
    $dlg.Filter = 'CSV (*.csv)|*.csv'; $dlg.FileName = "gpo-backup-compare-$(Get-Date -Format yyyyMMdd-HHmm).csv"
    if (-not $dlg.ShowDialog($window)) { return }
    try {
        $la = $ui.CmpALabel.Text.Trim(); $lb = $ui.CmpBLabel.Text.Trim()
        $rows = foreach ($r in $script:CmpTable.DefaultView) {
            [pscustomobject][ordered]@{
                Change = $r['Change']; Cat = $r['Cat']; StigId = $r['StigId']; VulnId = $r['VulnId']; RuleTitle = $r['RuleTitle']
                Setting = $r['Setting']
                "$la Value" = $r['ReferenceValue']; "$lb Value" = $r['DifferenceValue']
                "$la STIG" = $r['ReferenceStig'];   "$lb STIG" = $r['DifferenceStig']
                "$la GPOs" = $r['ReferenceGpos'];   "$lb GPOs" = $r['DifferenceGpos']
                InternalConflict = $r['InternalConflict']
            }
        }
        @($rows) | Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding utf8
        Set-Status "Exported $(@($rows).Count) row(s) (current filter) to $($dlg.FileName)"
    } catch { Show-Error $_.Exception.Message }
})
#endregion

Import-Settings
if ($ui.GpoBox.Text) { try { Update-GpoList } catch { } }
[void]$window.ShowDialog()
