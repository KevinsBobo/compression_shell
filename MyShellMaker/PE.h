#pragma once
#include <windows.h>
class CPE
{
public:
  CPE();
  ~CPE();

  BOOL CheckMask();
  BOOL OpenPE(TCHAR* szPEPath);
  BOOL ClosePE();
  PBYTE GetPEData();
  DWORD GetPEDataLen();
  DWORD GetAllSectionVirtualSize();
  DWORD GetAlignedValue(DWORD dwValue);
  DWORD GetAlignedFileValue(DWORD dwValue);
  PIMAGE_SECTION_HEADER GetSetionHdrs();
  PIMAGE_DOS_HEADER GetDosHdr();
  PIMAGE_NT_HEADERS GetNtHdr();
private:
  HANDLE m_hPEFile;
  HANDLE m_hPEFileMapping;
  PBYTE m_pPeBuffer;

  //PE文件的信息
private:
  PIMAGE_DOS_HEADER m_pHdrDos;
  PIMAGE_NT_HEADERS m_pHdrNt;
  PIMAGE_SECTION_HEADER m_pHdrSections;
  DWORD m_dwNumberOfSections;

};

