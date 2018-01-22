#include "stdafx.h"
#include "MyShell.h"
#include "lzo.h"


CMyShell::CMyShell()
{
}


CMyShell::~CMyShell()
{
}



BOOL CMyShell::Pack(TCHAR* szSrcPEPath, TCHAR* szDesPEPath)
{
  // 打开PE文件并检查标志
  CPE pe;
  if (!pe.OpenPE(szSrcPEPath))
  {
    pe.ClosePE();
    return FALSE;
  }

  /*
     构造新的PE
     新PE的节区分布
         PE头
         空节(.)
         壳和压缩数据节(.shell)
  */
  //1. 获取压缩数据
  PBYTE pPeBuffer = pe.GetPEData();
  DWORD dwPeSize = pe.GetPEDataLen();
  PBYTE pCompressBuff = new BYTE[dwPeSize / 2]();
  //check ..
  DWORD dwCompressSize = compress(pPeBuffer, dwPeSize, pCompressBuff);

  // 填写配置信息
  CONFIGINFO ci;
  ci.m_dwCompressSize = dwCompressSize;
  ci.m_dwDecompressSize = dwPeSize;

  //2. 获取shell的代码
  CPE peShellCode;
  if (!peShellCode.OpenPE("ShellCode.exe"))
  {
    peShellCode.ClosePE();
    //release resrouce
    return FALSE;
  }
  DWORD dwShellCodeSize = peShellCode.GetSetionHdrs()[0].SizeOfRawData;
  PBYTE pShellCode = peShellCode.GetPEData() 
    + peShellCode.GetSetionHdrs()[0].PointerToRawData;

  //构造节区数据
   //1) 空节
   //2) .shell节
  DWORD dwShellDataSize = dwCompressSize + dwShellCodeSize + sizeof(ci);
  PBYTE pShellDataBuff = new BYTE[dwShellDataSize]();
  //check.. 
  memcpy_s(pShellDataBuff, sizeof(ci), &ci, sizeof(ci)); //拷贝配置信息
  memcpy_s(pShellDataBuff + sizeof(ci), dwCompressSize,
    pCompressBuff, dwCompressSize); //拷贝压缩数据
  memcpy_s(pShellDataBuff + sizeof(ci) + dwCompressSize, dwShellCodeSize, 
    pShellCode, dwShellCodeSize); //拷贝shellcode

   //3) 构造节表
  enum 
  {
    IDX_EMPTY, //空节的索引 
    IDX_SHELL //shell节的索引
  };
  const DWORD dwNumberOfsections = 2;
  IMAGE_SECTION_HEADER hdrSections[dwNumberOfsections] = { 0 };
  /*
  * 构造空节
  */
  strcpy_s((char*)hdrSections[IDX_EMPTY].Name, 
    sizeof(hdrSections[IDX_EMPTY].Name), 
    ".empty");
  //原PE的所有节在内存中的总大小(取每个节对齐后的值)
  hdrSections[IDX_EMPTY].Misc.VirtualSize = pe.GetAllSectionVirtualSize();
  //空节的虚拟地址,保持与原pe的第一个节的虚拟地址相同
  hdrSections[IDX_EMPTY].VirtualAddress = pe.GetSetionHdrs()[0].VirtualAddress;
  hdrSections[IDX_EMPTY].SizeOfRawData = 0; //空节没有文件大小,用在在进程空间中占位
  //空节在文件中的偏移,保持与原pe的第一个节的偏移相同
  hdrSections[IDX_EMPTY].PointerToRawData = pe.GetSetionHdrs()[0].PointerToRawData;
  //内存属性,可读可写可执行
  hdrSections[IDX_EMPTY].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

  /*
  * 构造shell节
  */
  strcpy_s((char*)hdrSections[IDX_SHELL].Name,
    sizeof(hdrSections[IDX_SHELL].Name),
    ".shell");
  //虚拟大小,此处填写的是shell节的文件大小
  hdrSections[IDX_SHELL].Misc.VirtualSize = dwShellDataSize;
  //虚拟地址,空节的虚拟地址+空节的虚拟大小
  hdrSections[IDX_SHELL].VirtualAddress =
    hdrSections[IDX_EMPTY].VirtualAddress + hdrSections[IDX_EMPTY].Misc.VirtualSize;
  //文件大小, 压缩数据的大小+shellcode的大小
  hdrSections[IDX_SHELL].SizeOfRawData = dwShellDataSize;
  //文件偏移,与空节的文件偏移相同,因为空节没有文件数据
  hdrSections[IDX_SHELL].PointerToRawData =hdrSections[IDX_EMPTY].PointerToRawData;
  //属性,可读,可执行
  hdrSections[IDX_SHELL].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;

  /*
  *   构造PE头
  */
  DWORD dwNewPEHdrSize = pe.GetNtHdr()->OptionalHeader.SizeOfHeaders;
  DWORD dwAlignedHdrSize = pe.GetAlignedFileValue(dwNewPEHdrSize);
  PBYTE pNewPeHdrBuff = new BYTE[dwAlignedHdrSize]();  //为新的PE头申请内存
  // checkk..
  //拷贝原来PE的PE头
  memcpy_s(pNewPeHdrBuff, dwNewPEHdrSize, pe.GetDosHdr(), dwNewPEHdrSize);
  PIMAGE_DOS_HEADER pNewDosHdr = (PIMAGE_DOS_HEADER)pNewPeHdrBuff;
  PIMAGE_NT_HEADERS pNewNtHdr = 
    (PIMAGE_NT_HEADERS)(pNewPeHdrBuff + pNewDosHdr->e_lfanew);
  PIMAGE_SECTION_HEADER pNewHdrSections = 
    (PIMAGE_SECTION_HEADER)((PBYTE)&pNewNtHdr->OptionalHeader + pNewNtHdr->FileHeader.SizeOfOptionalHeader);
  pNewNtHdr->FileHeader.NumberOfSections = dwNumberOfsections; //新PE的节个数
  //获取shellcode中oep与oep所在的节的首地址的偏移
  DWORD dwOffset = peShellCode.GetNtHdr()->OptionalHeader.AddressOfEntryPoint
    - peShellCode.GetSetionHdrs()[0].VirtualAddress;
  pNewNtHdr->OptionalHeader.AddressOfEntryPoint = 
    hdrSections[IDX_SHELL].VirtualAddress + sizeof(ci)+dwCompressSize + dwOffset; //新OEP,应该是shellcode执行的起始地址
   //新PE在进程中所占内存的总大小, 新PE头 + 空节的大小 + shell节的大小(对齐后的值)
  pNewNtHdr->OptionalHeader.SizeOfImage = pe.GetAlignedValue(dwNewPEHdrSize)
    + hdrSections[IDX_EMPTY].Misc.VirtualSize
    + pe.GetAlignedValue(hdrSections[IDX_SHELL].Misc.VirtualSize);
  // 清空数据目录
  memset(pNewNtHdr->OptionalHeader.DataDirectory, 
    0,
    IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(IMAGE_DATA_DIRECTORY));
  //把新的节表拷贝到新的PE头
  memcpy_s(pNewHdrSections, sizeof(hdrSections),
    hdrSections, sizeof(hdrSections));

  //写入文件
  HANDLE hFile = CreateFile(szDesPEPath, GENERIC_READ | GENERIC_WRITE,
    0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE)
  {
    //释放内存资源
    // ...

    pe.ClosePE();
    return FALSE;
  }
  DWORD dwBytesWrited = 0;
  //写入PE头
  BOOL bRet = WriteFile(hFile, 
    pNewPeHdrBuff, dwAlignedHdrSize, 
    &dwBytesWrited, NULL);
  //check ..

  //写入shell节的数据
  bRet = WriteFile(hFile, 
    pShellDataBuff, dwShellDataSize, 
    &dwBytesWrited, NULL);

  //释放各种指针

  CloseHandle(hFile);
  pe.ClosePE();

  return TRUE;
}

