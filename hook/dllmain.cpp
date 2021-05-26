#include "pch.h"
#include <stdio.h>
#include <iostream>
#include "windows.h"


#include "Hide.h"
#include "..\detours\detours.h"
#define WIN32_LEAN_AND_MEAN 
#include <WinSock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define BUFSIZE 512
#pragma warning(disable  : 4996);

CHAR funName[BUFSIZE];
SOCKET ConnectSocket;
bool gConnect = false;
char* recvbuf = new char[BUFSIZE];  // буфер приема
char timer[BUFSIZE] = { 0 };
char dt[BUFSIZE] = { 0 };
extern "C" void Lab2Hook_x64();
extern "C" LPVOID DynamicTarget = NULL;

void sendMsg() 
{
    if (gConnect)
    {
        CHAR sendMsg[BUFSIZE];
        SYSTEMTIME st;
        GetLocalTime(&st);
        sprintf_s(dt, "%02d:%02d:%02d\n", st.wHour, st.wMinute, st.wSecond);
        if (timer == NULL || strcmp(dt, timer))
        {
            sprintf_s(timer, "%02d:%02d:%02d\n", st.wHour, st.wMinute, st.wSecond);
            sprintf_s(sendMsg, "%s(): %s", funName, timer);
            send(ConnectSocket, sendMsg, strlen(sendMsg) + 1, 0);
        }

        gConnect = FALSE;
    }
}
extern "C" VOID DynamicDetour()  //Это – функция-перехватчик
{
    gConnect = TRUE;
    sendMsg();
}
int tcp_connect() {
    WSAData wsaData;
    sockaddr_in ServerAddr;
    int err;
    // Initialize Winsock
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ServerAddr.sin_family = AF_INET;
    ServerAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    ServerAddr.sin_port = htons(9000);
    err = connect(ConnectSocket, (sockaddr*)&ServerAddr, sizeof(ServerAddr));
    if (err == SOCKET_ERROR) {
        closesocket(ConnectSocket);
        WSACleanup();
        return 0;
    }
    return 1;
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        char param[BUFSIZE];
        if (!tcp_connect()) break;
        sprintf(recvbuf, "OK");
        send(ConnectSocket, recvbuf, strlen(recvbuf)+1, 0);
        recv(ConnectSocket, recvbuf, BUFSIZE, 0);
        int count = 0, pos = 0, paramPos = 0;
        for (int i = 0; i < strlen(recvbuf); i++) {
            if (recvbuf[i] == ' ') {
                count++;
                pos = 0;
            }
            switch (count) {
            case 2:
                if (pos != 0)
                    param[pos - 1] = recvbuf[i];
                paramPos = pos;
                pos++;
                break;
            case 3:
                if (pos != 0)
                    funName[pos - 1] = recvbuf[i];
                pos++;
            default:
                break;
            }
        }
        param[paramPos] = '\0';
        funName[pos] = '\0';
        if (!strcmp(param, "-func"))
        {
            DynamicTarget = DetourFindFunction("kernel32.dll", funName);
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(&(PVOID&)DynamicTarget, Lab2Hook_x64);

            LONG err = DetourTransactionCommit();
            if (err != NO_ERROR) {
                char sendMsg[BUFSIZE];
                sprintf_s(sendMsg, "ERROR: DetourTransactionCommit() - %d\n", err);
                send(ConnectSocket, sendMsg, strlen(sendMsg) + 1, 0);
                return 1;
            }
        }
        else if (!strcmp(param, "-hide")) {
            std::string hideName(funName);
            HideFile(hideName);
            closesocket(ConnectSocket);
            WSACleanup();
            return 1;
        }
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}