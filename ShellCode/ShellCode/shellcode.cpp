#include "MyAPIDef.h"
#include "lzo.h"

void Start()
{
  //��:׼������,��ȡ������Ҫ��API��ָ��
  PFNAPIS apis;
  InitPfnApis(&apis);

  //1. ��ȡѹ������,��ѹ��,��ȡԭ����PE
  PBYTE pSrcPe = GetSourcePE(&apis);

  //2. load PE,���ݸ��ڵ���Ϣ,�������ݿ�������Ӧ�Ľ��̵�ַ
  PBYTE pOep = LoadPE(&apis, pSrcPe);

  //3. ��ת��ԭOEP
  __asm
  {
    jmp pOep;
  }
}

PBYTE LoadPE(PPFNAPIS pApis, PBYTE pPeData)
{
  // ���������ݵ���Ӧ�Ľ��̵�ַ�ռ�(�ս�)

  // ��дIAT

  // �����ض�λ(DLL)

  // ����OEP
  IMAGE_DOS_HEADER *pDos = (IMAGE_DOS_HEADER *)pPeData;
  IMAGE_NT_HEADERS32 *pNT = (IMAGE_NT_HEADERS32 *)((DWORD)pPeData + pDos->e_lfanew);
  DWORD numSection = pNT->FileHeader.NumberOfSections;
  DWORD optionalSize = pNT->FileHeader.SizeOfOptionalHeader;
  DWORD headersSize = pNT->OptionalHeader.SizeOfHeaders;
  DWORD imageBase = pNT->OptionalHeader.ImageBase;
  DWORD imageSize = pNT->OptionalHeader.SizeOfImage;
  DWORD entryPoint = pNT->OptionalHeader.AddressOfEntryPoint + imageBase;

//   mymemset((LPVOID)imageBase, 0, imageSize);
//   mymemcpy((LPVOID)imageBase, pPeData, headersSize);
  IMAGE_SECTION_HEADER *pSection = (IMAGE_SECTION_HEADER *)((DWORD)(&pNT->OptionalHeader) + optionalSize);
  for (DWORD i = 0; i < numSection; i++)
  {
    mymemcpy((LPVOID)(pSection->VirtualAddress + imageBase), (LPVOID)((DWORD)pPeData + pSection->PointerToRawData), pSection->SizeOfRawData);
    pSection++;
  }
  IMAGE_IMPORT_DESCRIPTOR *pImportTable = (IMAGE_IMPORT_DESCRIPTOR *)(imageBase + pNT->OptionalHeader.DataDirectory[1].VirtualAddress);
  IMAGE_IMPORT_DESCRIPTOR zeroImport = { 0 };
  while (mymemcmp(pImportTable, &zeroImport, sizeof(IMAGE_IMPORT_DESCRIPTOR) != 0))
  {
    if (*(DWORD*)(imageBase + pImportTable->FirstThunk) == NULL)
    {
      pImportTable++;
      continue;
    }
    LPSTR pName = (LPSTR)(imageBase + pImportTable->Name);
    HMODULE hDll = pApis->m_pfnLoadLibrary(pName);
    if (!hDll)
    {
      pImportTable++;
      continue;
    }
    IMAGE_THUNK_DATA32 *pINT = pImportTable->OriginalFirstThunk == 0 ? (IMAGE_THUNK_DATA32 *)(imageBase + pImportTable->FirstThunk) : (IMAGE_THUNK_DATA32 *)(imageBase + pImportTable->OriginalFirstThunk);
    IMAGE_THUNK_DATA32 *pIAT = (IMAGE_THUNK_DATA32 *)(imageBase + pImportTable->FirstThunk);
    IMAGE_THUNK_DATA32 zeroThunk = { 0 };
    while (mymemcmp(pINT, &zeroThunk, sizeof(IMAGE_THUNK_DATA32)) != 0)
    {
      if (pINT->u1.Ordinal & 0x80000000)
      {
        DWORD procAddr = (DWORD)pApis->m_pfnGetProcAddress(hDll, (LPCSTR)(pINT->u1.Ordinal & 0xffff));
        if (procAddr)
        {
          pIAT->u1.Ordinal = procAddr;
        }
      }
      else
      {
        IMAGE_IMPORT_BY_NAME *pName = (IMAGE_IMPORT_BY_NAME *)(pINT->u1.Ordinal + imageBase);
        DWORD procAddr = (DWORD)pApis->m_pfnGetProcAddress(hDll, (LPCSTR)(pName->Name));
        if (procAddr)
        {
          pIAT->u1.Ordinal = procAddr;
        }
      }
      pINT++;
      pIAT++;
    }
    pImportTable++;
  }
  return (PBYTE)entryPoint;
}

PBYTE GetSourcePE(PPFNAPIS pAois)
{
  // ��ȡģ���ַ
  HMODULE hImageBase = GetImageBaseAdress();
  // ��ȡshell��
  PIMAGE_DOS_HEADER pHdrDos = (PIMAGE_DOS_HEADER)hImageBase;
  PIMAGE_NT_HEADERS pHdrNt = (PIMAGE_NT_HEADERS)((PBYTE)hImageBase + pHdrDos->e_lfanew);
  DWORD dwNumberOfSections = pHdrNt->FileHeader.NumberOfSections;
  PIMAGE_SECTION_HEADER pHdrSections = (PIMAGE_SECTION_HEADER)((PBYTE)&pHdrNt->OptionalHeader + pHdrNt->FileHeader.SizeOfOptionalHeader);
  PBYTE pShellData = (PBYTE)hImageBase + pHdrSections[1].VirtualAddress;

  // ��ȡ������Ϣ
  PCONFIGINFO pCi = (PCONFIGINFO)pShellData;

  // ��ȡѹ������
  PBYTE pCompressData = pShellData + sizeof(CONFIGINFO);

  // ��ѹ��
  PBYTE pDecompressBuf = (PBYTE)pAois->m_pfnVirtualAlloc(NULL, 
    pCi->m_dwDecompressSize,
    MEM_COMMIT,
    PAGE_READWRITE);
  if (pDecompressBuf == NULL)
  {
    return NULL;
  }

  decompress(pCompressData, pCi->m_dwCompressSize, pDecompressBuf);

  return pDecompressBuf;
}

BOOL InitPfnApis(PPFNAPIS pAois)
{
  //ʹ���ַ��ķ�ʽ��ʼ������,��ֹ���ɷ��ʾ��Ե�ַ��ָ��
  char szGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0' };
  char szLoadLibrary[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0'};
  char szVirtualAlloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', '\0'};
 char szVirtualFree[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', '\0' };
  char szVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', '\0' };
  HMODULE hKernel32 = GetKernelBase();
  pAois->m_pfnGetProcAddress = (PFN_GetProcAddress)MyGetProcAddress(hKernel32, szGetProcAddress);
  // check
  pAois->m_pfnLoadLibrary = (PFN_LoadLibraryA)pAois->m_pfnGetProcAddress(hKernel32, szLoadLibrary);
  // check
  pAois->m_pfnVirtualAlloc = (PFN_VirtualAlloc)pAois->m_pfnGetProcAddress(hKernel32, szVirtualAlloc);
  // check
  pAois->m_pfnVirtualFree = (PFN_VirtualFree)pAois->m_pfnGetProcAddress(hKernel32, szVirtualFree);
  // check
  pAois->m_pfnVirtualProtect = (PFN_VirtualProtect)pAois->m_pfnGetProcAddress(hKernel32, szVirtualProtect);
  return TRUE;
}

HMODULE GetImageBaseAdress()
{
  HMODULE hImageBase;
  __asm
  {
    mov eax, fs:[0x18];
    mov eax, [eax + 0x18]; //��ȡteb
    mov eax, [eax + 0x30]; //��ȡpeb
    mov eax, [eax + 0x08]; //��ȡpeb.ImageBaseAddress
    mov hImageBase, eax;
  }
  return hImageBase;

}

HMODULE GetKernelBase()
{
  HMODULE hKernel32;
  __asm
  {
    mov eax, fs:[0x18]; 
    mov eax, [eax + 0x18]; //��ȡteb
    mov eax, [eax + 0x30]; //��ȡpeb

    mov eax, [eax + 0x0c]; //��ȡpet.Ldr
    mov eax, [eax + 0x1c]; //��ȡLdr.InInitializationOrderModuleList, ntdll
    mov eax, [eax]; //��ȡkernalbase
    mov eax, [eax]; //��ȡkernel32
    mov eax, [eax + 0x08]; //��ȡkernel32��ģ���ַ
    mov hKernel32, eax;
  }
  return hKernel32;
}


void * __cdecl mymemcpy(
  void * dst,
  const void * src,
  size_t count
  )
{
  void * ret = dst;

  /*
  * copy from lower addresses to higher addresses
  */
  while (count--) {
    *(char *)dst = *(char *)src;
    dst = (char *)dst + 1;
    src = (char *)src + 1;
  }

  return(ret);
}

int __cdecl mystrcmp(
  const char * src,
  const char * dst
  )
{
  int ret = 0;

  while (!(ret = *(unsigned char *)src - *(unsigned char *)dst) && *dst)
    ++src, ++dst;

  if (ret < 0)
    ret = -1;
  else if (ret > 0)
    ret = 1;

  return(ret);
}


int __cdecl mymemcmp(
  const void * buf1,
  const void * buf2,
  size_t count
  )
{
  if (!count)
    return(0);

  while (--count && *(char *)buf1 == *(char *)buf2) {
    buf1 = (char *)buf1 + 1;
    buf2 = (char *)buf2 + 1;
  }

  return(*((unsigned char *)buf1) - *((unsigned char *)buf2));
}


void * __cdecl mymemset(
  void *dst,
  int val,
  size_t count
  )
{
  void *start = dst;

  while (count--) {
    *(char *)dst = (char)val;
    dst = (char *)dst + 1;
  }

  return(start);
}

void * __cdecl mymemccpy(
  void * dest,
  const void * src,
  int c,
  unsigned count
  )
{
  while (count && (*((char *)(dest = (char *)dest + 1) - 1) =
    *((char *)(src = (char *)src + 1) - 1)) != (char)c)
    count--;

  return(count ? dest : NULL);
}
DWORD MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
  /*˼·:
  1.����Dosͷ
  2.ͨ��dosͷ��λPEͷ(NT)
  3.ͨ��NTͷ��ѡ��ͷ������Ŀ¼,��λ������
  4.ת���������RVA,�����С
  5.��λ������ĺ�����ַ�� + ģ���ַ = ʵ�ʺ�����ַ
  6.��λ�������Ʊ�
  7.��λʵ�ʺ�������
  8.��λBase��ʼ��ŵĳ�Ա
  9.��λ��ű�
  10.�ж�һ����ʲô��ʽ������,��Ż�������
  */
  int i = 0;
  char *pRet = NULL;
  PIMAGE_DOS_HEADER pImageDos = NULL;/*����DOSͷ*/
  PIMAGE_NT_HEADERS pImageNt = NULL;/*����NTͷ*/
  PIMAGE_EXPORT_DIRECTORY pImageExport = NULL;/*���嵼����*/
  /*����ģ���׵�ַ*/
  pImageDos = (PIMAGE_DOS_HEADER)hModule;
  /*����NTͷ(Dosͷ����Dosͷ�еĳ�Ա)*/
  pImageNt = (PIMAGE_NT_HEADERS)((DWORD)hModule + pImageDos->e_lfanew);
  /*���㵼����*/
  pImageExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hModule + pImageNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  /*�õ�RVA*/
  DWORD dwExportRva = pImageNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  /*�õ���С*/
  DWORD dwExportSize = pImageNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

  /*�õ�������ַ��,�����ŵ��ƺ�����ַ��ƫ��*/
  DWORD *pAddressOfFunction = (DWORD*)(pImageExport->AddressOfFunctions + (DWORD)hModule);
  /*�õ����Ʊ�*/
  DWORD *pAddressOfName = (DWORD*)(pImageExport->AddressOfNames + (DWORD)hModule);
  /*�õ���ű�*/
  WORD *pAddressofNameOrdinals = (WORD*)(pImageExport->AddressOfNameOrdinals + (DWORD)hModule);
  /*�õ�Base*/
  DWORD dwBase = (DWORD)(pImageExport->Base);
  /*�õ������ĸ���*/
  DWORD dwFunctionNumber = (DWORD)(pImageExport->NumberOfNames);/*�������ֵ����ĸ���*/
  /*��ѯʲô��ʽ������*/
  DWORD dwName = (DWORD)lpProcName;
  if ((dwName & 0xFFFF0000) == 0)
  {
    /*��λ��ȫF,��ô������ŵ���*/
    if (dwName < dwBase || dwName >dwBase + pImageExport->NumberOfFunctions - 1)
    {
      return 0;
    }
    pRet = (char *)(pAddressOfFunction[dwName - dwBase] + (DWORD)hModule);

  }
  /*��ѯ����*/
  for (i = 0; i < (int)dwFunctionNumber; i++)
  {
    char *szFunctionName = (char *)(pAddressOfName[i] + (DWORD)hModule);
    if (mystrcmp(szFunctionName, (char *)lpProcName) == 0)
    {
      /*��ô���ҵ�������*/
      pRet = (char *)(pAddressOfFunction[i+1] + (DWORD)hModule);/*ע�������п�,������ַ+ģ���ַ�ŵ���ʵ�ʵĺ�����ַ,����˵Ӧ��Ѱ�����,����λ��,����ֱ��ģ��+ƫ����*/
      /*�жϺ�����ַ�Ƿ����*/
      if ((DWORD)pRet < dwExportRva + (DWORD)hModule || (DWORD)pRet> dwExportRva + (DWORD)hModule + dwExportSize)
      {
        return (DWORD)pRet;
      }

    }

  }
  return 0;
//   /*ƴ���ַ���,����DLL*/
//   char pTempDll[100] = { 0 };
//   char pTempFuction[100] = { 0 };
//   lstrcpy(pTempDll, pRet);
//   char *p = strchr(pTempDll, '.');
//   if (!p)
//   {
//     return (DWORD)pRet;
//   }
//   *p = 0;
//   lstrcpy(pTempFuction, p + 1);
//   lstrcat(pTempDll, ".dll");
//   HMODULE h = LoadLibrary(pTempDll);
//   if (h == NULL)
//   {
//     return (DWORD)pRet;
//   }
//   return MyGetProcAddress(h, pTempFuction);
}
