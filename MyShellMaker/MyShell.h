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
    DWORD m_dwCompressSize; //压缩数据的大小
    DWORD m_dwDecompressSize; //解压缩数据的大小
  }CONFIGINFO, *PCONFIGINFO;
};

