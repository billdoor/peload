#include "pefile.h"

#include <iostream>

using namespace std;

PEFile::PEFile(std::string FilePath) :
	_FilePath(FilePath),
	_ImageBase(0)
{
	ifstream InFile(FilePath.c_str(), ios::binary);
	InFile.seekg(0, ios::end);
	_File.resize(InFile.tellg());
	InFile.seekg(0);
	InFile.read((char*)&_File[0], _File.size());

	if(!isPEFile())
		throw runtime_error("Not a valid PE file.");

	_PtrFileDOSHeader = (PIMAGE_DOS_HEADER)&_File[0];
	_PtrFileNTHeaders = (PIMAGE_NT_HEADERS)&_File[_PtrFileDOSHeader->e_lfanew];
	_PtrFileNTHeaders64 = (PIMAGE_NT_HEADERS64)&_File[_PtrFileDOSHeader->e_lfanew];
	_PtrFileSectionHeaders = (PIMAGE_SECTION_HEADER)&_File[_PtrFileDOSHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + _PtrFileNTHeaders->FileHeader.SizeOfOptionalHeader];

	_is64Bit = false;
	if(_PtrFileNTHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		_is64Bit = true;

	// pad file to minimum size needed to read from the whole optional header structure (for TinyPE and friends)
	if(_File.size() < _PtrFileDOSHeader->e_lfanew + max(sizeof(IMAGE_NT_HEADERS), sizeof(IMAGE_NT_HEADERS64)) + _PtrFileNTHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER))
		_File.insert(_File.end(), _PtrFileDOSHeader->e_lfanew + max(sizeof(IMAGE_NT_HEADERS), sizeof(IMAGE_NT_HEADERS64)) + _PtrFileNTHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) - _File.size(), 0);

	// ensure file buffer is aligned to a Windows page
	if(_File.size() % PAGE_SIZE != 0)
		_File.insert(_File.end(), PAGE_SIZE - (_File.size() % PAGE_SIZE), 0);

	// reset the header pointers as the previous resizing may have moved the _File vector's buffer in memory
	_PtrFileDOSHeader = (PIMAGE_DOS_HEADER)&_File[0];
	_PtrFileNTHeaders = (PIMAGE_NT_HEADERS)&_File[_PtrFileDOSHeader->e_lfanew];
	_PtrFileNTHeaders64 = (PIMAGE_NT_HEADERS64)&_File[_PtrFileDOSHeader->e_lfanew];
	_PtrFileSectionHeaders = (PIMAGE_SECTION_HEADER)&_File[_PtrFileDOSHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + _PtrFileNTHeaders->FileHeader.SizeOfOptionalHeader];

	// find the real size of the image
	DWORD LastSectionStartRVA = 0;
	size_t ImageSize;
	for(size_t i = 0; i < _PtrFileNTHeaders->FileHeader.NumberOfSections; ++i)
		if(_PtrFileSectionHeaders[i].VirtualAddress > LastSectionStartRVA)
		{
			LastSectionStartRVA = _PtrFileSectionHeaders[i].VirtualAddress;
			ImageSize = alignValue(LastSectionStartRVA + alignValue(max(_PtrFileSectionHeaders[i].Misc.VirtualSize, _PtrFileSectionHeaders[i].SizeOfRawData), _is64Bit ? _PtrFileNTHeaders64->OptionalHeader.SectionAlignment : _PtrFileNTHeaders->OptionalHeader.SectionAlignment), PAGE_SIZE);
		}

	_Image.clear();
	_Image.insert(_Image.end(), ImageSize, 0);

	// load PE header
	size_t HeaderSize = _PtrFileDOSHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + _PtrFileNTHeaders->FileHeader.SizeOfOptionalHeader + _PtrFileNTHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
	for(size_t i = 0; i < HeaderSize; ++i)
		_Image[i] = _File[i];

	// load sections
	for(size_t i = 0; i < _PtrFileNTHeaders->FileHeader.NumberOfSections; ++i)
	{
		size_t AlignedRawSize = alignValue(_PtrFileSectionHeaders[i].SizeOfRawData, _is64Bit ? _PtrFileNTHeaders64->OptionalHeader.FileAlignment : _PtrFileNTHeaders->OptionalHeader.FileAlignment);
		size_t AmountToLoad = min(min(AlignedRawSize, _File.size() - _PtrFileSectionHeaders[i].PointerToRawData), _Image.size() - _PtrFileSectionHeaders[i].VirtualAddress);
		for(size_t j = 0; j < AmountToLoad; ++j)
			_Image[_PtrFileSectionHeaders[i].VirtualAddress + j] = _File[_PtrFileSectionHeaders[i].PointerToRawData + j];
	}

	_PtrImageDOSHeader = (PIMAGE_DOS_HEADER)&_Image[0];
	_PtrImageNTHeaders = (PIMAGE_NT_HEADERS)&_Image[_PtrImageDOSHeader->e_lfanew];
	_PtrImageNTHeaders64 = (PIMAGE_NT_HEADERS64)&_Image[_PtrImageDOSHeader->e_lfanew];
	_PtrImageSectionHeaders = (PIMAGE_SECTION_HEADER)&_Image[_PtrImageDOSHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + _PtrImageNTHeaders->FileHeader.SizeOfOptionalHeader];

	_ImageBase = _is64Bit ? _PtrImageNTHeaders64->OptionalHeader.ImageBase : _PtrImageNTHeaders->OptionalHeader.ImageBase;
	_EntryPointVA = _ImageBase + (_is64Bit ? _PtrImageNTHeaders64->OptionalHeader.AddressOfEntryPoint : _PtrImageNTHeaders->OptionalHeader.AddressOfEntryPoint);
}

bool PEFile::isMZFile()
{
	if(_File.size() < sizeof(IMAGE_DOS_HEADER))
		return false;
	if(((PIMAGE_DOS_HEADER)&_File[0])->e_magic != IMAGE_DOS_SIGNATURE)
		return false;
	return true;
}

bool PEFile::isPEFile()
{
	if(!isMZFile())
		return false;
	DWORD e_lfanew = ((PIMAGE_DOS_HEADER)&_File[0])->e_lfanew;
	if(_File.size() < e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))
		return false;
	PIMAGE_NT_HEADERS PtrNTHeaders = (PIMAGE_NT_HEADERS)&_File[e_lfanew];
	if(PtrNTHeaders->Signature != IMAGE_NT_SIGNATURE)
		return false;
	if(_File.size() < e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + PtrNTHeaders->FileHeader.SizeOfOptionalHeader + PtrNTHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER))
		return false;
	return true;
}

DWORD PEFile::alignValue(DWORD Value, DWORD Alignment)
{
	if(Value % Alignment == 0)
		return Value;
	return Value + Alignment - (Value % Alignment);
}

std::vector<BYTE> PEFile::getBuffer(QWORD VirtualAddress, size_t Size)
{
	size_t RVA = VirtualAddress - _ImageBase;
	size_t AmountToCopy = min(Size, _Image.size() - RVA);
	return vector<BYTE>(_Image.begin() + RVA, _Image.begin() + RVA + AmountToCopy);
}
