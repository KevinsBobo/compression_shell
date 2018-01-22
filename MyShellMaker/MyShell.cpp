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
  // ��PE�ļ�������־
  CPE pe;
  if (!pe.OpenPE(szSrcPEPath))
  {
    pe.ClosePE();
    return FALSE;
  }

  /*
     �����µ�PE
     ��PE�Ľ����ֲ�
         PEͷ
         �ս�(.)
         �Ǻ�ѹ�����ݽ�(.shell)
  */
  //1. ��ȡѹ������
  PBYTE pPeBuffer = pe.GetPEData();
  DWORD dwPeSize = pe.GetPEDataLen();
  PBYTE pCompressBuff = new BYTE[dwPeSize / 2]();
  //check ..
  DWORD dwCompressSize = compress(pPeBuffer, dwPeSize, pCompressBuff);

  // ��д������Ϣ
  CONFIGINFO ci;
  ci.m_dwCompressSize = dwCompressSize;
  ci.m_dwDecompressSize = dwPeSize;

  //2. ��ȡshell�Ĵ���
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

  //�����������
   //1) �ս�
   //2) .shell��
  DWORD dwShellDataSize = dwCompressSize + dwShellCodeSize + sizeof(ci);
  PBYTE pShellDataBuff = new BYTE[dwShellDataSize]();
  //check.. 
  memcpy_s(pShellDataBuff, sizeof(ci), &ci, sizeof(ci)); //����������Ϣ
  memcpy_s(pShellDataBuff + sizeof(ci), dwCompressSize,
    pCompressBuff, dwCompressSize); //����ѹ������
  memcpy_s(pShellDataBuff + sizeof(ci) + dwCompressSize, dwShellCodeSize, 
    pShellCode, dwShellCodeSize); //����shellcode

   //3) ����ڱ�
  enum 
  {
    IDX_EMPTY, //�սڵ����� 
    IDX_SHELL //shell�ڵ�����
  };
  const DWORD dwNumberOfsections = 2;
  IMAGE_SECTION_HEADER hdrSections[dwNumberOfsections] = { 0 };
  /*
  * ����ս�
  */
  strcpy_s((char*)hdrSections[IDX_EMPTY].Name, 
    sizeof(hdrSections[IDX_EMPTY].Name), 
    ".empty");
  //ԭPE�����н����ڴ��е��ܴ�С(ȡÿ���ڶ�����ֵ)
  hdrSections[IDX_EMPTY].Misc.VirtualSize = pe.GetAllSectionVirtualSize();
  //�սڵ������ַ,������ԭpe�ĵ�һ���ڵ������ַ��ͬ
  hdrSections[IDX_EMPTY].VirtualAddress = pe.GetSetionHdrs()[0].VirtualAddress;
  hdrSections[IDX_EMPTY].SizeOfRawData = 0; //�ս�û���ļ���С,�����ڽ��̿ռ���ռλ
  //�ս����ļ��е�ƫ��,������ԭpe�ĵ�һ���ڵ�ƫ����ͬ
  hdrSections[IDX_EMPTY].PointerToRawData = pe.GetSetionHdrs()[0].PointerToRawData;
  //�ڴ�����,�ɶ���д��ִ��
  hdrSections[IDX_EMPTY].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

  /*
  * ����shell��
  */
  strcpy_s((char*)hdrSections[IDX_SHELL].Name,
    sizeof(hdrSections[IDX_SHELL].Name),
    ".shell");
  //�����С,�˴���д����shell�ڵ��ļ���С
  hdrSections[IDX_SHELL].Misc.VirtualSize = dwShellDataSize;
  //�����ַ,�սڵ������ַ+�սڵ������С
  hdrSections[IDX_SHELL].VirtualAddress =
    hdrSections[IDX_EMPTY].VirtualAddress + hdrSections[IDX_EMPTY].Misc.VirtualSize;
  //�ļ���С, ѹ�����ݵĴ�С+shellcode�Ĵ�С
  hdrSections[IDX_SHELL].SizeOfRawData = dwShellDataSize;
  //�ļ�ƫ��,��սڵ��ļ�ƫ����ͬ,��Ϊ�ս�û���ļ�����
  hdrSections[IDX_SHELL].PointerToRawData =hdrSections[IDX_EMPTY].PointerToRawData;
  //����,�ɶ�,��ִ��
  hdrSections[IDX_SHELL].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;

  /*
  *   ����PEͷ
  */
  DWORD dwNewPEHdrSize = pe.GetNtHdr()->OptionalHeader.SizeOfHeaders;
  DWORD dwAlignedHdrSize = pe.GetAlignedFileValue(dwNewPEHdrSize);
  PBYTE pNewPeHdrBuff = new BYTE[dwAlignedHdrSize]();  //Ϊ�µ�PEͷ�����ڴ�
  // checkk..
  //����ԭ��PE��PEͷ
  memcpy_s(pNewPeHdrBuff, dwNewPEHdrSize, pe.GetDosHdr(), dwNewPEHdrSize);
  PIMAGE_DOS_HEADER pNewDosHdr = (PIMAGE_DOS_HEADER)pNewPeHdrBuff;
  PIMAGE_NT_HEADERS pNewNtHdr = 
    (PIMAGE_NT_HEADERS)(pNewPeHdrBuff + pNewDosHdr->e_lfanew);
  PIMAGE_SECTION_HEADER pNewHdrSections = 
    (PIMAGE_SECTION_HEADER)((PBYTE)&pNewNtHdr->OptionalHeader + pNewNtHdr->FileHeader.SizeOfOptionalHeader);
  pNewNtHdr->FileHeader.NumberOfSections = dwNumberOfsections; //��PE�Ľڸ���
  //��ȡshellcode��oep��oep���ڵĽڵ��׵�ַ��ƫ��
  DWORD dwOffset = peShellCode.GetNtHdr()->OptionalHeader.AddressOfEntryPoint
    - peShellCode.GetSetionHdrs()[0].VirtualAddress;
  pNewNtHdr->OptionalHeader.AddressOfEntryPoint = 
    hdrSections[IDX_SHELL].VirtualAddress + sizeof(ci)+dwCompressSize + dwOffset; //��OEP,Ӧ����shellcodeִ�е���ʼ��ַ
   //��PE�ڽ�������ռ�ڴ���ܴ�С, ��PEͷ + �սڵĴ�С + shell�ڵĴ�С(������ֵ)
  pNewNtHdr->OptionalHeader.SizeOfImage = pe.GetAlignedValue(dwNewPEHdrSize)
    + hdrSections[IDX_EMPTY].Misc.VirtualSize
    + pe.GetAlignedValue(hdrSections[IDX_SHELL].Misc.VirtualSize);
  // �������Ŀ¼
  memset(pNewNtHdr->OptionalHeader.DataDirectory, 
    0,
    IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(IMAGE_DATA_DIRECTORY));
  //���µĽڱ������µ�PEͷ
  memcpy_s(pNewHdrSections, sizeof(hdrSections),
    hdrSections, sizeof(hdrSections));

  //д���ļ�
  HANDLE hFile = CreateFile(szDesPEPath, GENERIC_READ | GENERIC_WRITE,
    0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE)
  {
    //�ͷ��ڴ���Դ
    // ...

    pe.ClosePE();
    return FALSE;
  }
  DWORD dwBytesWrited = 0;
  //д��PEͷ
  BOOL bRet = WriteFile(hFile, 
    pNewPeHdrBuff, dwAlignedHdrSize, 
    &dwBytesWrited, NULL);
  //check ..

  //д��shell�ڵ�����
  bRet = WriteFile(hFile, 
    pShellDataBuff, dwShellDataSize, 
    &dwBytesWrited, NULL);

  //�ͷŸ���ָ��

  CloseHandle(hFile);
  pe.ClosePE();

  return TRUE;
}

