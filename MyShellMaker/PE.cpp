#include "stdafx.h"
#include "PE.h"


CPE::CPE():
m_hPEFile(INVALID_HANDLE_VALUE),
m_hPEFileMapping(NULL),
m_pPeBuffer(NULL),
m_pHdrDos(NULL),
m_pHdrNt(NULL),
m_pHdrSections(NULL),
m_dwNumberOfSections(0)
{
}


CPE::~CPE()
{
}



BOOL CPE::CheckMask()
{
  return TRUE;
}
BOOL CPE::OpenPE(TCHAR* szPEPath)
{
  /*
  *  打开文件映射
  */
  m_hPEFile = CreateFile(szPEPath, 
    GENERIC_READ, 
    0, 
    NULL, 
    OPEN_EXISTING, 
    FILE_ATTRIBUTE_NORMAL, 
    NULL);
  if (m_hPEFile == INVALID_HANDLE_VALUE)
  {
    return FALSE;
  }

  m_hPEFileMapping =  CreateFileMapping(m_hPEFile, NULL, PAGE_READONLY, 0, 0, NULL);
  if (m_hPEFileMapping == NULL)
  {
    return FALSE;
  }

  m_pPeBuffer = (PBYTE)MapViewOfFile(m_hPEFileMapping, FILE_MAP_READ, 0, 0, 0);
  if (m_pPeBuffer == NULL)
  {
    return FALSE;
  }
  

  /*
  * 获取PE文件信息
  */
  m_pHdrDos = (PIMAGE_DOS_HEADER)m_pPeBuffer;
  m_pHdrNt = (PIMAGE_NT_HEADERS)(m_pPeBuffer + m_pHdrDos->e_lfanew);
  if (m_pHdrDos->e_magic != 'ZM' || m_pHdrNt->Signature != 0x4550)
  {
    return FALSE;
  }
  m_dwNumberOfSections = m_pHdrNt->FileHeader.NumberOfSections;
  m_pHdrSections = (PIMAGE_SECTION_HEADER)((PBYTE)&m_pHdrNt->OptionalHeader + m_pHdrNt->FileHeader.SizeOfOptionalHeader);

  return TRUE;
}
BOOL CPE::ClosePE()
{
  //释放资源
  return TRUE;
}


PBYTE CPE::GetPEData()
{
  return m_pPeBuffer;
}
DWORD CPE::GetPEDataLen()
{
  //DWORD dwFileSize = 0;
  return GetFileSize(m_hPEFile, NULL);
}

DWORD CPE::GetAlignedValue(DWORD dwValue)
{
  DWORD dwAlignment = m_pHdrNt->OptionalHeader.SectionAlignment;
  if (dwValue % dwAlignment == 0) //整除
  {
    return dwValue;
  }
  return (dwValue / dwAlignment + 1) * dwAlignment;
}

DWORD CPE::GetAlignedFileValue(DWORD dwValue)
{
  DWORD dwAlignment = m_pHdrNt->OptionalHeader.FileAlignment;
  if (dwValue % dwAlignment == 0) //整除
  {
    return dwValue;
  }
  return (dwValue / dwAlignment + 1) * dwAlignment;
}

DWORD CPE::GetAllSectionVirtualSize()
{
  DWORD dwAllSize = 0;
  for (int i = 0; i < m_dwNumberOfSections; ++i)
  {
    DWORD dwValue = m_pHdrSections[i].Misc.VirtualSize > m_pHdrSections[i].SizeOfRawData ?
      m_pHdrSections[i].Misc.VirtualSize : m_pHdrSections[i].SizeOfRawData;
    dwAllSize += GetAlignedValue(dwValue);
  }

  return dwAllSize;
}

PIMAGE_SECTION_HEADER CPE::GetSetionHdrs()
{
  return m_pHdrSections;
}


PIMAGE_DOS_HEADER CPE::GetDosHdr()
{
  return m_pHdrDos;
}
PIMAGE_NT_HEADERS CPE::GetNtHdr()
{
  return m_pHdrNt;
}