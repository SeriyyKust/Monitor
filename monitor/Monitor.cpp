#define WIN32_LEAN_AND_MEAN 
#include <winsock2.h> 
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <comdef.h>
#include <vector>
#include <tchar.h>
#include <ShlObj.h>
#define BUFSIZE 512

DWORD WINAPI InstanceThread(LPVOID);
int LoadLibByPID(DWORD processId);


DWORD getPidByName(std::string processname) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD result = NULL;
    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(0x00000002, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnap) return(FALSE);
    pe32.dwSize = sizeof(PROCESSENTRY32); // <----- IMPORTANT
    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);          // clean the snapshot object
        printf("!!! Failed to gather information on system processes! \n");
        return(NULL);
    }
    do {
        _bstr_t b(pe32.szExeFile);
        const char* c = b;
        if (0 == strcmp(processname.c_str(), c)) {
            result = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);
    return result;
}
int LoadLibByPID(DWORD processId) {
    char dllName[BUFSIZE];
    GetModuleFileNameA(NULL, dllName, BUFSIZE);
    size_t len = sizeof(dllName);
    while (dllName[--len] != '\\')
        dllName[len] = 0;
    strncat_s(dllName, "hook.dll",BUFSIZE);
    HANDLE openedProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (openedProcess == NULL) {
        printf("OpenProcess error code: %d\r\n", GetLastError());
        return 0;
    }
    HMODULE kernelModule = GetModuleHandleW(L"kernel32.dll");
    if (kernelModule == NULL) {
        printf("GetModuleHandleW error code: %d\r\n", GetLastError());
        CloseHandle(openedProcess);
        return 0;
    }
    LPVOID loadLibraryAddr = GetProcAddress(kernelModule, "LoadLibraryA");
    if (loadLibraryAddr == NULL) {
        printf("GetProcAddress error code: %d\r\n", GetLastError());
        CloseHandle(openedProcess);
        return 0;
    }
    LPVOID argLoadLibrary = (LPVOID)VirtualAllocEx(openedProcess, NULL, strlen(dllName), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (argLoadLibrary == NULL) {
        printf("VirtualAllocEx error code: %d\r\n", GetLastError());
        CloseHandle(openedProcess);
        return 0;
    }
    int countWrited = WriteProcessMemory(openedProcess, argLoadLibrary, dllName, strlen(dllName), NULL);
    if (countWrited == NULL) {
        printf("WriteProcessMemory error code: %d\r\n", GetLastError());
        CloseHandle(openedProcess);
        return 0;
    }
    // Создаем поток, передаем адрес LoadLibrary и адрес ее аргумента
    HANDLE threadID = CreateRemoteThread(openedProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, argLoadLibrary, NULL, NULL);
    if (threadID == NULL) {
        printf("CreateRemoteThread error code: %d\r\n", GetLastError());
        CloseHandle(openedProcess);
        return 0;
    }
    // Закрываем поток.
    CloseHandle(openedProcess);
    return 1;
}

int main(int argc, char* argv[])
{
    if (!IsUserAnAdmin()) {
        std::cout << "Administrator privileges required\n";
        return 0;
    }
    if (argc != 5) {
        std::cout << "Number of arguments error!";
        return 0;
    }

    DWORD pid;

    if (strcmp(argv[1] ,"-pid") == 0)
    {
        pid = atoi(argv[2]);
    }
    else if (strcmp(argv[1] ,"-name")==0)
    {
        pid = getPidByName(argv[2]);
        if (!pid) {
            std::cout << "Process " << argv[2] << " not found";
            return 0;
        }
    }
    else
    {
        std::cout << "Bad arguments: -pid or -name not found";
        return 0;
    }

    if ((strcmp(argv[3], "-func") == 0) || (strcmp(argv[3], "-hide") == 0))
    {

    }
    else
    {
        std::cout << "Bad arguments: -func or -hide not found";
        return 0;
    }
    
    std::string sendStr;

    for (u_int i = 0; i < 3; i++) {
        sendStr += argv[i+1];
        sendStr += " ";
    }
    sendStr += argv[4];
    
    WSADATA wsaData;
    SOCKET ListenSocket, ClientSocket;       // впускающий сокет и сокет для клиентов
    sockaddr_in ServerAddr;                  //  адрес сервера
    int err, maxlen = 512;                   // код ошибки и размер буферов
    char* recvbuf = new char[maxlen];        // буфер приема
    char* result_string = new char[maxlen];  // буфер отправки
    // Initialize Winsock
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    // Create a SOCKET for connecting to server
    ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    // Setup the TCP listening socket
    ServerAddr.sin_family = AF_INET;
    InetPton(AF_INET, _T("127.0.0.1"), &ServerAddr.sin_addr.s_addr);
    ServerAddr.sin_port = htons(9000);
    err = bind(ListenSocket, (sockaddr*)&ServerAddr, sizeof(ServerAddr));
    if (err == SOCKET_ERROR) {
        printf("bind failed: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    err = listen(ListenSocket, 50);
    if (err == SOCKET_ERROR) {
        printf("listen failed: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    if (!LoadLibByPID(pid))
        return 0;
    // Accept a client socket
    ClientSocket = accept(ListenSocket, NULL, NULL);
    err = recv(ClientSocket, recvbuf, maxlen, 0);
    if (err > 0) {
        recvbuf[err] = 0;
        printf("Connected\n");
        send(ClientSocket, sendStr.c_str(), strlen(sendStr.c_str())+1, 0);
        printf("Reply sent\n");
    }
    else {
        printf("recv failed: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
        return 0;
    }
    if (strcmp(argv[3] , "-func") == 0) while (1) {
        err = recv(ClientSocket, recvbuf, maxlen, 0);
        if (err > 0) {
            recvbuf[err] = 0;
        }
        else if (err == 0) {
            printf("Connection closing...\n");
            break;
        }
        else {
            printf("recv failed: %d\n", WSAGetLastError());
            closesocket(ClientSocket);
            WSACleanup();
            return 1;
        }
        printf("%s",recvbuf);
    }
    // shutdown the connection since we're done
    closesocket(ClientSocket);
    WSACleanup();
    return 1;
}