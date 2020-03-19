#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <schannel.h>
#define SECURITY_WIN32
#include <security.h>

class CSsl
{
public:
    CSsl();
    ~CSsl();

    BOOL Connect(const CHAR *host, USHORT port);
    void Close();
    //
    DWORD Send(const CHAR *pBuf, DWORD BufLen);
    int Recv(      void *pBuf, int nBufLen);

    SECURITY_STATUS ClientCreateCredentials(const CHAR *pszUserName, PCredHandle phCreds);
    BOOL ClientConnect(const CHAR *szHostName);
    LONG ClientDisconnect(PCredHandle phCreds, CtxtHandle *phContext);
    SECURITY_STATUS ClientHandshake(PCredHandle phCreds, const CHAR *pszServerName, CtxtHandle *phContext, SecBuffer *pExtraData);
    SECURITY_STATUS ClientHandshakeLoop(PCredHandle phCreds, CtxtHandle *phContext, BOOL fDoInitialRead, SecBuffer *pExtraData);
    DWORD ClientVerifyCertificate(PCCERT_CONTEXT pServerCert,const CHAR *pszServerName, DWORD dwCertFlags);

    SECURITY_STATUS ServerCreateCredentials(const CHAR *pszUserName, PCredHandle phCreds);
    BOOL ServerConnect(SOCKADDR* lpSockAddr, int* lpSockAddrLen);
    LONG ServerDisconect(PCredHandle phCreds, CtxtHandle *phContext);
    BOOL ServerHandshakeLoop(PCtxtHandle phContext, PCredHandle phCred, BOOL fClientAuth, BOOL fDoInitialRead, BOOL NewContext);
    DWORD ServerVerifyCertificate(PCCERT_CONTEXT  pServerCert, DWORD dwCertFlags);

    SOCKET s;
    BOOL m_bServer;

    CHAR *m_CsCertName;
    BOOL m_bMachineStore;
    DWORD m_dwProtocol;

    PCCERT_CONTEXT  m_pCertContext;
    BOOL m_bAuthClient;

    HCERTSTORE      m_hMyCertStore;
    SCHANNEL_CRED   m_SchannelCred;
    CredHandle m_hCreds;
    CtxtHandle m_hContext;

    BOOL m_bConInit;
    BOOL m_bAllowPlainText;

    BYTE *m_pbReceiveBuf;
    DWORD m_dwReceiveBuf;

    BYTE *m_pbIoBuffer;
    DWORD m_cbIoBuffer;

    bool m_permissive;
};
