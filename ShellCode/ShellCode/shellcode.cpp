#include "MyAPIDef.h"
#include "lzo.h"

void Start()
{
  //序:准备工作,获取所有需要的API的指针
  PFNAPIS apis;
  InitPfnApis(&apis);

  //1. 读取压缩数据,解压缩,获取原来的PE
  PBYTE pSrcPe = GetSourcePE(&apis);

  //2. load PE,根据各节的信息,将节数据拷贝到对应的进程地址
  PBYTE pOep = LoadPE(&apis, pSrcPe);

  //3. 跳转到原OEP
  __asm
  {
    jmp pOep;
  }
}

PBYTE LoadPE(PPFNAPIS pApis, PBYTE pPeData)
{
  // 拷贝节数据到对应的进程地址空间(空节)

  // 填写IAT

  // 处理重定位(DLL)

  // 计算OEP
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
  // 获取模块基址
  HMODULE hImageBase = GetImageBaseAdress();
  // 获取shell节
  PIMAGE_DOS_HEADER pHdrDos = (PIMAGE_DOS_HEADER)hImageBase;
  PIMAGE_NT_HEADERS pHdrNt = (PIMAGE_NT_HEADERS)((PBYTE)hImageBase + pHdrDos->e_lfanew);
  DWORD dwNumberOfSections = pHdrNt->FileHeader.NumberOfSections;
  PIMAGE_SECTION_HEADER pHdrSections = (PIMAGE_SECTION_HEADER)((PBYTE)&pHdrNt->OptionalHeader + pHdrNt->FileHeader.SizeOfOptionalHeader);
  PBYTE pShellData = (PBYTE)hImageBase + pHdrSections[1].VirtualAddress;

  // 获取配置信息
  PCONFIGINFO pCi = (PCONFIGINFO)pShellData;

  // 获取压缩数据
  PBYTE pCompressData = pShellData + sizeof(CONFIGINFO);

  // 解压缩
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
  //使用字符的方式初始化数组,防止生成访问绝对地址的指令
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
    mov eax, [eax + 0x18]; //获取teb
    mov eax, [eax + 0x30]; //获取peb
    mov eax, [eax + 0x08]; //获取peb.ImageBaseAddress
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
    mov eax, [eax + 0x18]; //获取teb
    mov eax, [eax + 0x30]; //获取peb

    mov eax, [eax + 0x0c]; //获取pet.Ldr
    mov eax, [eax + 0x1c]; //获取Ldr.InInitializationOrderModuleList, ntdll
    mov eax, [eax]; //获取kernalbase
    mov eax, [eax]; //获取kernel32
    mov eax, [eax + 0x08]; //获取kernel32的模块基址
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
  /*思路:
  1.定义Dos头
  2.通过dos头定位PE头(NT)
  3.通过NT头的选项头的数据目录,定位导出表
  4.转换导出表的RVA,保存大小
  5.定位导出表的函数地址表 + 模块地址 = 实际函数地址
  6.定位函数名称表
  7.定位实际函数个数
  8.定位Base起始序号的成员
  9.定位序号表
  10.判断一下是什么方式导出的,序号还是名字
  */
  int i = 0;
  char *pRet = NULL;
  PIMAGE_DOS_HEADER pImageDos = NULL;/*定义DOS头*/
  PIMAGE_NT_HEADERS pImageNt = NULL;/*定义NT头*/
  PIMAGE_EXPORT_DIRECTORY pImageExport = NULL;/*定义导出表*/
  /*计算模块首地址*/
  pImageDos = (PIMAGE_DOS_HEADER)hModule;
  /*计算NT头(Dos头加上Dos头中的成员)*/
  pImageNt = (PIMAGE_NT_HEADERS)((DWORD)hModule + pImageDos->e_lfanew);
  /*计算导出表*/
  pImageExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hModule + pImageNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  /*得到RVA*/
  DWORD dwExportRva = pImageNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  /*得到大小*/
  DWORD dwExportSize = pImageNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

  /*得到函数地址表,里面存放的势函数地址的偏移*/
  DWORD *pAddressOfFunction = (DWORD*)(pImageExport->AddressOfFunctions + (DWORD)hModule);
  /*得到名称表*/
  DWORD *pAddressOfName = (DWORD*)(pImageExport->AddressOfNames + (DWORD)hModule);
  /*得到序号表*/
  WORD *pAddressofNameOrdinals = (WORD*)(pImageExport->AddressOfNameOrdinals + (DWORD)hModule);
  /*得到Base*/
  DWORD dwBase = (DWORD)(pImageExport->Base);
  /*得到函数的个数*/
  DWORD dwFunctionNumber = (DWORD)(pImageExport->NumberOfNames);/*按照名字导出的个数*/
  /*查询什么方式导出的*/
  DWORD dwName = (DWORD)lpProcName;
  if ((dwName & 0xFFFF0000) == 0)
  {
    /*高位是全F,那么就是序号导出*/
    if (dwName < dwBase || dwName >dwBase + pImageExport->NumberOfFunctions - 1)
    {
      return 0;
    }
    pRet = (char *)(pAddressOfFunction[dwName - dwBase] + (DWORD)hModule);

  }
  /*查询名字*/
  for (i = 0; i < (int)dwFunctionNumber; i++)
  {
    char *szFunctionName = (char *)(pAddressOfName[i] + (DWORD)hModule);
    if (mystrcmp(szFunctionName, (char *)lpProcName) == 0)
    {
      /*那么就找到了名字*/
      pRet = (char *)(pAddressOfFunction[i+1] + (DWORD)hModule);/*注意这里有坑,函数地址+模块地址才等于实际的函数地址,按理说应该寻找序号,再找位置,这里直接模块+偏移了*/
      /*判断函数地址是否出错*/
      if ((DWORD)pRet < dwExportRva + (DWORD)hModule || (DWORD)pRet> dwExportRva + (DWORD)hModule + dwExportSize)
      {
        return (DWORD)pRet;
      }

    }

  }
  return 0;
//   /*拼接字符串,加载DLL*/
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
