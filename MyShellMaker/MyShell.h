#pragma once
#include <windows.h>
#include "PE.h"
class CMyShell
{
public:
  CMyShell();
  ~CMyShell();


  BOOL Pack(TCHAR* szSrcPEPath, TCHAR* szDesPEPath);

private:
  typedef struct tagConfigInfo
  {
    DWORD m_dwCompressSize; //ѹ�����ݵĴ�С
    DWORD m_dwDecompressSize; //��ѹ�����ݵĴ�С
  }CONFIGINFO, *PCONFIGINFO;
};

