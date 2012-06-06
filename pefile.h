#pragma once

/* Check our build platform. */
#ifdef _MSC_VER
/* Using the MSVC compiler on Windows */
//	Speed up build process with minimal headers.
#	define WIN32_LEAN_AND_MEAN
#	define VC_EXTRALEAN

//	Eliminate some warnings.
#	ifndef _CRT_SECURE_NO_WARNINGS
#		define _CRT_SECURE_NO_WARNINGS
#	endif

#	ifndef _CRT_NONSTDC_NO_WARNINGS
#		define _CRT_NONSTDC_NO_WARNINGS
#	endif
#	include <windows.h>
#else
/* On Wine */
#	include "windef.h"
#	include "winnt.h"
#endif

#include <stdexcept>
#include <algorithm>
#include <fstream>
#include <vector>

const DWORD PAGE_SIZE = 0x1000;
typedef unsigned long long QWORD, *PQWORD, *LPQWORD;

class PEFile
{
public:
	PEFile(std::string FilePath);
	QWORD getImageBase() const { return _ImageBase; }
	QWORD getEntryPointVA() const { return _EntryPointVA; }
	std::vector<BYTE> getBuffer(QWORD VirtualAddress, size_t Size);

protected:
	bool isMZFile();
	bool isPEFile();
	DWORD alignValue(DWORD Value, DWORD Alignment);

	std::string _FilePath;
	std::vector<BYTE> _File;

	std::vector<BYTE> _Image;

	bool _is64Bit;
	QWORD _ImageBase;
	QWORD _EntryPointVA;

	PIMAGE_DOS_HEADER _PtrFileDOSHeader;
	PIMAGE_NT_HEADERS _PtrFileNTHeaders;
	PIMAGE_NT_HEADERS64 _PtrFileNTHeaders64;
	PIMAGE_SECTION_HEADER _PtrFileSectionHeaders;

	PIMAGE_DOS_HEADER _PtrImageDOSHeader;
	PIMAGE_NT_HEADERS _PtrImageNTHeaders;
	PIMAGE_NT_HEADERS64 _PtrImageNTHeaders64;
	PIMAGE_SECTION_HEADER _PtrImageSectionHeaders;
};
