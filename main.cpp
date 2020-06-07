
#include <stdio.h>
#include <winsock2.h>
#include "SSL.h"

#pragma comment(lib, "ws2_32.lib")

char *SendBuf = "GET / HTTP/1.1\r\n"
                "Host: www.baidu.com\r\n"
                "Connection: close\r\n"
                "\r\n";

int main()
{
    DWORD SendBufLen = (DWORD)strlen(SendBuf);
    printf("ToSend(%d):\n%s", SendBufLen, SendBuf);

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    CSsl *ssl = new CSsl;
    if (ssl)
    {
        if (ssl->Connect("www.baidu.com", 443))
        {
            printf("Connected ~\n");
            DWORD SentLen = ssl->Send(SendBuf, SendBufLen);
            if (SentLen == SendBufLen)
            {
                printf("SentLen : %d\n\n", SentLen);

                char RecvBuf[512];
                while (1)
                {
                    DWORD RecvLen = ssl->Recv(RecvBuf, sizeof(RecvBuf)-1);
                    if (RecvLen)
                    {
                        RecvBuf[RecvLen] = '\0';
                        fputs(RecvBuf, stdout);
                    }
                    else
                    {
                        break;
                    }
                }
            }

            closesocket(ssl->s);
        }

        delete ssl;
    }

    WSACleanup();
    getchar();
    return 0;
}
