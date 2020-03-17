
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
    int SendLen = (int)strlen(SendBuf);
    printf("Send(%d):\n%s", SendLen, SendBuf);

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    CSsl *ssl = new CSsl;
    if (ssl)
    {
        if (ssl->Connect("www.baidu.com", 443))
        {
            int len = ssl->Send(SendBuf, SendLen, 0);

            char buf[512];
            while (1)
            {
                len = ssl->Recv(buf, sizeof(buf)-1, 0);
                if (len <= 0)
                    break;

                buf[len] = '\0';
                fputs(buf, stdout);
            }
        }
    }

    WSACleanup();
    return 0;
}
