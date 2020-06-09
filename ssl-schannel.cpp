
#include "SSL.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Crypt32.lib")

#define IO_BUFFER_SIZE  0x10000
#define isagain(nBytes) (nBytes==SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK)

/////////////////////////////////////////////////////////////////////////////

PSecurityFunctionTableA g_pSecFuncTableA;

void Init_pSecFuncTable()
{
    if (!g_pSecFuncTableA)
    {
        HMODULE hSCHANNEL = LoadLibraryA("SCHANNEL.DLL");
        if (hSCHANNEL)
        {
            INIT_SECURITY_INTERFACE_A pInitSecurityInterfaceA =
                (INIT_SECURITY_INTERFACE_A)GetProcAddress(hSCHANNEL, "InitSecurityInterfaceA");

            if (pInitSecurityInterfaceA)
                g_pSecFuncTableA = pInitSecurityInterfaceA();
        }
    }
}

//------------------------------------------------------------------

SOCKET SocketConnect(const CHAR *host, USHORT port)
{
    SOCKET s = NULL;

    char portstr[10];
    sprintf_s(portstr, sizeof(portstr), "%i", port);

    addrinfo hints;
    memset(&hints, 0, sizeof(addrinfo));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = 0;

    addrinfo *addr = NULL;
    getaddrinfo(host, portstr, &hints, &addr);
    if (addr)
    {
        s = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (s != INVALID_SOCKET)
        {
            timeval timeout;
            timeout.tv_sec  = 4;
            timeout.tv_usec = 0;
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

            if (connect(s, addr->ai_addr, (int)addr->ai_addrlen)!=0)
            {
                closesocket(s);
                s = NULL;
            }
        }
        else
        {
            s = NULL;
        }

        freeaddrinfo(addr);
    }

    return s;
}

int SocketSend(SOCKET s, const char * data, int len, int nFlags)
{
    int toLen = len;

    if (!s || s == -1)
        return -1;

    if (toLen == 0)
        toLen = (int)strlen(data);

    while (toLen)
    {
        int nBytes = send(s, data, toLen, nFlags);
        if (nBytes <= 0)
        {
            if (isagain(nBytes))
            {
                Sleep(100);
                continue;
            }

            return nBytes;
        }

        data  += nBytes;
        toLen -= nBytes;
    }

    return (len - toLen);
}

//----------------------------------------------------------------

CSsl::CSsl() :
    s(NULL),
	m_bServer(FALSE),
	m_dwProtocol(0),
	m_pCertContext(NULL),
	m_bAuthClient(FALSE),
	m_hMyCertStore(NULL),
	m_bAllowPlainText(FALSE),
	
    m_IoBuf(NULL),
    m_IoBufLen(0),
    //
    m_RecvDecBuf(NULL),
    m_RecvDecBufLen(0),
    m_RecvDecBufOffset(0),

    m_CsCertName(NULL)
{
    Init_pSecFuncTable();

	ZeroMemory(&m_SchannelCred, sizeof(m_SchannelCred));

	m_hCreds.dwLower = 0;
	m_hCreds.dwUpper = 0;

	m_hContext.dwLower = 0;
	m_hContext.dwUpper = 0;
}

CSsl::~CSsl()
{
    if (m_hCreds.dwLower && m_hCreds.dwUpper)
		g_pSecFuncTableA->FreeCredentialsHandle(&m_hCreds);

	if (m_hContext.dwLower && m_hContext.dwUpper)
		g_pSecFuncTableA->DeleteSecurityContext(&m_hContext);

    if (m_pCertContext)
        CertFreeCertificateContext(m_pCertContext);

    if (m_hMyCertStore)
        CertCloseStore(m_hMyCertStore, 0);

    if (m_IoBuf)
        HeapFree(GetProcessHeap(), 0, m_IoBuf);

	if (m_RecvDecBuf)
        HeapFree(GetProcessHeap(), 0, m_RecvDecBuf);
}

BOOL CSsl::Connect(const char *host, USHORT port)
{
    CSsl *ssl = this;

    ssl->s = SocketConnect(host, port);
    if (ssl->s)
    {
        if (ssl->ClientConnect(host))
        {
            SECURITY_STATUS scRet = g_pSecFuncTableA->QueryContextAttributesA(&m_hContext,SECPKG_ATTR_STREAM_SIZES,&m_StreamSizes);
            if (scRet == SEC_E_OK)
            {
                m_IoBufLen = m_StreamSizes.cbHeader + 
                             m_StreamSizes.cbMaximumMessage +
                             m_StreamSizes.cbTrailer;

                m_IoBuf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, m_IoBufLen);
                if (m_IoBuf)
                {
                    return TRUE;
                }
            }
        }

        closesocket(ssl->s);
        ssl->s = NULL;
    }

    return FALSE;
}


DWORD CSsl::Send(const CHAR *pBuf, DWORD BufLen) 
{
    DWORD SentLen = 0;

    if (!pBuf || !BufLen || !m_IoBuf)
        return 0;

    PBYTE pbMessage = m_IoBuf + m_StreamSizes.cbHeader;
    do
    {
        DWORD cbMessage = BufLen > m_StreamSizes.cbMaximumMessage ? m_StreamSizes.cbMaximumMessage : BufLen;

        CopyMemory(pbMessage, pBuf + SentLen, cbMessage);

        SentLen += cbMessage;
        BufLen -= cbMessage;

        SecBuffer Buffers[4];
        Buffers[0].pvBuffer   = m_IoBuf;
        Buffers[0].cbBuffer   = m_StreamSizes.cbHeader;
        Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

        Buffers[1].pvBuffer   = pbMessage;
        Buffers[1].cbBuffer   = cbMessage;
        Buffers[1].BufferType = SECBUFFER_DATA;

        Buffers[2].pvBuffer   = pbMessage + cbMessage;
        Buffers[2].cbBuffer   = m_StreamSizes.cbTrailer;
        Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

        Buffers[3].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc Message;
        Message.ulVersion     = SECBUFFER_VERSION;
        Message.cBuffers      = 4;
        Message.pBuffers      = Buffers;

        SECURITY_STATUS scRet = g_pSecFuncTableA->EncryptMessage(&m_hContext, 0, &Message, 0);
        if(scRet != SEC_E_OK)
        {
            SentLen = 0;
            break;
        }

        int nSent = SocketSend(this->s, (char *)m_IoBuf, Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer, 0);
        if (!nSent || (nSent == SOCKET_ERROR))
        {
            SentLen = 0;
            break;
        }

    } while (BufLen != 0);

	return SentLen;
}

DWORD CSsl::Recv(CHAR *pBuf, DWORD BufLen) 
{
	DWORD RecvLen = 0;

    if (m_IoBuf == NULL)
        return 0;

L_Decrypted:
    if (m_RecvDecBufLen)
    {
        DWORD RestLen = m_RecvDecBufLen - m_RecvDecBufOffset;
        if (BufLen < RestLen)
        {
            RecvLen = BufLen;
            CopyMemory(pBuf, m_RecvDecBuf + m_RecvDecBufOffset, RecvLen);
            m_RecvDecBufOffset += RecvLen;
        }
        else
        {
            RecvLen = RestLen;
            CopyMemory(pBuf, m_RecvDecBuf + m_RecvDecBufOffset, RecvLen);
            m_RecvDecBufLen    = 0;
            m_RecvDecBufOffset = 0;
        }

        return RecvLen;
    }

    DWORD RecvSumLen = 0;
L_Recv:
    int tRecvLen = recv(this->s, (char *)m_IoBuf + RecvSumLen, m_IoBufLen - RecvSumLen, 0);
    if(tRecvLen == 0 || tRecvLen == SOCKET_ERROR)
    {
        return 0;
    }
    RecvSumLen += tRecvLen;

L_Decrypt:
    SecBuffer Buffers[4];
    Buffers[0].pvBuffer   = m_IoBuf;
    Buffers[0].cbBuffer   = RecvSumLen;
    Buffers[0].BufferType = SECBUFFER_DATA;

    Buffers[1].BufferType = SECBUFFER_EMPTY;
    Buffers[2].BufferType = SECBUFFER_EMPTY;
    Buffers[3].BufferType = SECBUFFER_EMPTY;

    SecBufferDesc Message;
    Message.ulVersion     = SECBUFFER_VERSION;
    Message.cBuffers      = 4;
    Message.pBuffers      = Buffers;

    SECURITY_STATUS scRet = g_pSecFuncTableA->DecryptMessage(&m_hContext, &Message, 0, NULL);
    if (scRet)
    {
        if (scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            goto L_Recv;
        }
    }

    SecBuffer *pDataBuffer  = NULL;
    SecBuffer *pExtraBuffer = NULL;
    //
    for (int i = 1; i < 4; i++)
    {
        if (pDataBuffer == NULL && Buffers[i].BufferType == SECBUFFER_DATA)
            pDataBuffer = &Buffers[i];

        if (pExtraBuffer == NULL && Buffers[i].BufferType == SECBUFFER_EXTRA)
            pExtraBuffer = &Buffers[i];
    }

    if (pDataBuffer)
    {
        if (!m_RecvDecBuf)
            m_RecvDecBuf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, m_IoBufLen);

        if (m_RecvDecBufLen + pDataBuffer->cbBuffer > m_IoBufLen)
        {
            printf("m_RecvDecBufLen + pDataBuffer->cbBuffer > dwBufDataLen!\n");
            __debugbreak();
        }

        CopyMemory(m_RecvDecBuf + m_RecvDecBufLen, pDataBuffer->pvBuffer, pDataBuffer->cbBuffer);
        m_RecvDecBufLen += pDataBuffer->cbBuffer;
    }

    if (pExtraBuffer)
    {
        MoveMemory(m_IoBuf, pExtraBuffer->pvBuffer, pExtraBuffer->cbBuffer);
        RecvSumLen = pExtraBuffer->cbBuffer;
        goto L_Decrypt;
    }

    if (m_RecvDecBufLen)
        goto L_Decrypted;

	return RecvLen;
}

void CSsl::Close()
{
	if (m_bServer)
    {
		ServerDisconect(&m_hCreds,&m_hContext);
	}
    else
    {
		ClientDisconnect(&m_hCreds,&m_hContext);
	}
}

SECURITY_STATUS CSsl::ClientCreateCredentials(const CHAR *pszUserName, PCredHandle phCreds)
{
    SECURITY_STATUS Status;
	TimeStamp       tsExpiry;
	CERT_RDN        cert_rdn;
	CERT_RDN_ATTR   cert_rdn_attr;

	do {
		if (!m_hMyCertStore)
        {
			m_hMyCertStore = CertOpenSystemStoreA(0, "MY");
			if (!m_hMyCertStore)
            {
				Status = SEC_E_NO_CREDENTIALS;
				break;
			}
		}

		if (pszUserName && strlen(pszUserName) != 0)
        {
			cert_rdn.cRDNAttr = 1;
			cert_rdn.rgRDNAttr = &cert_rdn_attr;

			cert_rdn_attr.pszObjId = (CHAR*)szOID_COMMON_NAME;
			cert_rdn_attr.dwValueType = CERT_RDN_ANY_TYPE;
			cert_rdn_attr.Value.cbData = (DWORD)strlen(pszUserName);

			cert_rdn_attr.Value.pbData = (BYTE *)pszUserName;
			m_pCertContext = CertFindCertificateInStore(m_hMyCertStore, 
													  X509_ASN_ENCODING, 
													  0,
													  CERT_FIND_SUBJECT_ATTR,
													  &cert_rdn,
													  NULL);

			if(m_pCertContext == NULL)
            {
				Status = SEC_E_NO_CREDENTIALS;
				break;
			}
		}

		ZeroMemory(&m_SchannelCred, sizeof(m_SchannelCred));

		m_SchannelCred.dwVersion  = SCHANNEL_CRED_VERSION;

		if(m_pCertContext)
        {
			m_SchannelCred.cCreds = 1;
			m_SchannelCred.paCred = &m_pCertContext;
		}

		m_SchannelCred.grbitEnabledProtocols = m_dwProtocol;

		m_SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
		m_SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SYSTEM_MAPPER | SCH_CRED_REVOCATION_CHECK_CHAIN;

		Status = g_pSecFuncTableA->AcquireCredentialsHandleA(
							NULL,
							UNISP_NAME_A,
							SECPKG_CRED_OUTBOUND,
							NULL,
							&m_SchannelCred,
							NULL,
							NULL,
							phCreds,
							&tsExpiry);

		if(Status != SEC_E_OK)
        {
			Status = Status;
			break;
		}

	} while (FALSE);

	return Status;
}

SECURITY_STATUS CSsl::ServerCreateCredentials(const CHAR * pszUserName, PCredHandle phCreds)
{
	TimeStamp       tsExpiry;
	SECURITY_STATUS Status;
	CERT_RDN cert_rdn;
	CERT_RDN_ATTR cert_rdn_attr;

	do {

		if(pszUserName == NULL || strlen(pszUserName) == 0) {
			SetLastError(ERROR_NO_SUCH_USER);
			Status = SEC_E_NO_CREDENTIALS;
			break;
		}

		if(m_hMyCertStore == NULL) {
				m_hMyCertStore = CertOpenSystemStoreA(0, "MY");

			if(!m_hMyCertStore) {
				SetLastError(::GetLastError());
				Status = SEC_E_NO_CREDENTIALS;
				break;
			}
		}

		cert_rdn.cRDNAttr = 1;
		cert_rdn.rgRDNAttr = &cert_rdn_attr;

		cert_rdn_attr.pszObjId = (CHAR*)szOID_COMMON_NAME;
		cert_rdn_attr.dwValueType = CERT_RDN_ANY_TYPE;
		cert_rdn_attr.Value.cbData = (DWORD)strlen(pszUserName);

			cert_rdn_attr.Value.pbData = (BYTE *)pszUserName;
			m_pCertContext = CertFindCertificateInStore(m_hMyCertStore, 
													  X509_ASN_ENCODING, 
													  0,
													  CERT_FIND_SUBJECT_ATTR,
													  &cert_rdn,
													  NULL);

		if(m_pCertContext == NULL) {
			SetLastError(::GetLastError());
			Status = SEC_E_NO_CREDENTIALS;
			break;
		}

		ZeroMemory(&m_SchannelCred, sizeof(m_SchannelCred));

		m_SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;

		m_SchannelCred.cCreds = 1;
		m_SchannelCred.paCred = &m_pCertContext;
		m_SchannelCred.hRootStore = m_hMyCertStore;
		//m_SchannelCred.dwMinimumCypherStrength = 80;
		m_SchannelCred.grbitEnabledProtocols = m_dwProtocol;
		m_SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SYSTEM_MAPPER | SCH_CRED_REVOCATION_CHECK_CHAIN;
		
		Status = g_pSecFuncTableA->AcquireCredentialsHandleA(
							NULL,
							UNISP_NAME_A,
							SECPKG_CRED_INBOUND,
							NULL,
							&m_SchannelCred,
							NULL,
							NULL,
							phCreds,
							&tsExpiry);

		if(Status != SEC_E_OK) {
			SetLastError(Status);
			Status = Status;
			break;
		}

	} while (FALSE);

    return Status;
}

BOOL CSsl::ClientConnect(const CHAR *szHostName)
{
	BOOL rc = FALSE;

	do
    {
		if (ClientCreateCredentials(m_CsCertName, &m_hCreds))
        {
			break;
		}

        SecBuffer  ExtraData = {0};
		if(FAILED(ClientHandshake(&m_hCreds, szHostName, &m_hContext, &ExtraData)))
        {
			break;
		}

		if (!m_permissive)
		{
			PCCERT_CONTEXT pRemoteCertContext = NULL;
			SECURITY_STATUS Status =
                g_pSecFuncTableA->QueryContextAttributesA(&m_hContext,SECPKG_ATTR_REMOTE_CERT_CONTEXT,(PVOID)&pRemoteCertContext);
			if(Status != SEC_E_OK)
            {
				SetLastError(Status);
				break;
			}

			Status = ClientVerifyCertificate(pRemoteCertContext, szHostName, 0);
			if(Status)
            {
				SetLastError(Status);
				break;
			}

			CertFreeCertificateContext(pRemoteCertContext);
		}

		rc = TRUE;
	} while (FALSE);

	return rc;
}

SECURITY_STATUS CSsl::ClientHandshake(PCredHandle phCreds, const CHAR *pszServerName, CtxtHandle *phContext, SecBuffer *pExtraData)
{
    SECURITY_STATUS scRet;
    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;

    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
                  ISC_REQ_REPLAY_DETECT     |
                  ISC_REQ_CONFIDENTIALITY   |
                  ISC_RET_EXTENDED_ERROR    |
                  ISC_REQ_ALLOCATE_MEMORY   |
                  ISC_REQ_STREAM;
    
    if (m_permissive)
        dwSSPIFlags |= ISC_REQ_MANUAL_CRED_VALIDATION;

    OutBuffers[0].pvBuffer   = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = 0;

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    scRet = g_pSecFuncTableA->InitializeSecurityContextA(
                    phCreds,
                    NULL,
                    (SEC_CHAR *)pszServerName,
                    dwSSPIFlags,
                    0,
                    SECURITY_NATIVE_DREP,
                    NULL,
                    0,
                    phContext,
                    &OutBuffer,
                    &dwSSPIOutFlags,
                    &tsExpiry);

    if (scRet != SEC_I_CONTINUE_NEEDED)
    {
        SetLastError(scRet);
        return scRet;
    }

    if (OutBuffers[0].pvBuffer && OutBuffers[0].cbBuffer)
    {
        DWORD cbData = 
            SocketSend(this->s, (char *)OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
        if (cbData != OutBuffers[0].cbBuffer)
        {
            g_pSecFuncTableA->FreeContextBuffer(OutBuffers[0].pvBuffer);
            g_pSecFuncTableA->DeleteSecurityContext(phContext);
            return SEC_E_INTERNAL_ERROR;
        }

        g_pSecFuncTableA->FreeContextBuffer(OutBuffers[0].pvBuffer);
        OutBuffers[0].pvBuffer = NULL;
        OutBuffers[0].cbBuffer = 0;
    }

    scRet = ClientHandshakeLoop(phCreds, phContext, TRUE, pExtraData);

	if (pExtraData->pvBuffer)
        delete [](BYTE*)pExtraData->pvBuffer;

	return scRet;
}

SECURITY_STATUS CSsl::ClientHandshakeLoop(PCredHandle phCreds, CtxtHandle *phContext, BOOL fDoInitialRead, SecBuffer *pExtraData)
{
    SECURITY_STATUS scRet;
    SecBufferDesc   InBuffer;
    SecBuffer       InBuffers[2];
    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    DWORD           cbData;

    PUCHAR          IoBuffer;
    DWORD           cbIoBuffer;
    BOOL            fDoRead;

    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
                  ISC_REQ_REPLAY_DETECT     |
                  ISC_REQ_CONFIDENTIALITY   |
                  ISC_RET_EXTENDED_ERROR    |
                  ISC_REQ_ALLOCATE_MEMORY   |
                  ISC_REQ_STREAM;

    if (m_permissive)
        dwSSPIFlags |= ISC_REQ_MANUAL_CRED_VALIDATION;

    IoBuffer = new BYTE[IO_BUFFER_SIZE];
    if (IoBuffer == NULL)
    {
		SetLastError(ERROR_OUTOFMEMORY);
        return SEC_E_INTERNAL_ERROR;
    }
    cbIoBuffer = 0;

    fDoRead = fDoInitialRead;

    scRet = SEC_I_CONTINUE_NEEDED;

    while(scRet == SEC_I_CONTINUE_NEEDED        ||
          scRet == SEC_E_INCOMPLETE_MESSAGE     ||
          scRet == SEC_I_INCOMPLETE_CREDENTIALS)
    {
        if (0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            if (fDoRead)
            {
                cbData = recv(this->s, (char *)(IoBuffer + cbIoBuffer), IO_BUFFER_SIZE - cbIoBuffer, 0);
                if (cbData == (DWORD)SOCKET_ERROR)
                {
					scRet = SEC_E_INTERNAL_ERROR;
					break;
                }
                else if (cbData == 0)
                {
                    SetLastError(ERROR_VC_DISCONNECTED);
                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }

                cbIoBuffer += cbData;
            }
            else
            {
                fDoRead = TRUE;
            }
        }

        InBuffers[0].pvBuffer   = IoBuffer;
        InBuffers[0].cbBuffer   = cbIoBuffer;
        InBuffers[0].BufferType = SECBUFFER_TOKEN;

        InBuffers[1].pvBuffer   = NULL;
        InBuffers[1].cbBuffer   = 0;
        InBuffers[1].BufferType = SECBUFFER_EMPTY;

        InBuffer.cBuffers       = 2;
        InBuffer.pBuffers       = InBuffers;
        InBuffer.ulVersion      = SECBUFFER_VERSION;

        OutBuffers[0].pvBuffer  = NULL;
        OutBuffers[0].BufferType= SECBUFFER_TOKEN;
        OutBuffers[0].cbBuffer  = 0;

        OutBuffer.cBuffers      = 1;
        OutBuffer.pBuffers      = OutBuffers;
        OutBuffer.ulVersion     = SECBUFFER_VERSION;

        scRet = g_pSecFuncTableA->InitializeSecurityContextA(phCreds,
                                          phContext,
                                          NULL,
                                          dwSSPIFlags,
                                          0,
                                          SECURITY_NATIVE_DREP,
                                          &InBuffer,
                                          0,
                                          NULL,
                                          &OutBuffer,
                                          &dwSSPIOutFlags,
                                          &tsExpiry);

        if (scRet == SEC_E_OK                ||
            scRet == SEC_I_CONTINUE_NEEDED   ||
            (FAILED(scRet) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR)))
        {

            if (OutBuffers[0].pvBuffer && OutBuffers[0].cbBuffer)
            {
				cbData = SocketSend(this->s, (const char *)(OutBuffers[0].pvBuffer), OutBuffers[0].cbBuffer, 0);
                if(cbData == (DWORD)SOCKET_ERROR || cbData == 0)
                {
                    g_pSecFuncTableA->FreeContextBuffer(OutBuffers[0].pvBuffer);
                    g_pSecFuncTableA->DeleteSecurityContext(phContext);
                    return SEC_E_INTERNAL_ERROR;
                }

                g_pSecFuncTableA->FreeContextBuffer(OutBuffers[0].pvBuffer);
                OutBuffers[0].pvBuffer = NULL;
                OutBuffers[0].cbBuffer = 0;
            }
        }

        if(scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            continue;
        }

        if(scRet == SEC_E_OK)
        {
            if(InBuffers[1].BufferType == SECBUFFER_EXTRA)
            {
                pExtraData->pvBuffer = new BYTE[InBuffers[1].cbBuffer];

                if(pExtraData->pvBuffer == NULL)
                {
                    SetLastError(ERROR_OUTOFMEMORY);
                    return SEC_E_INTERNAL_ERROR;
                }

                MoveMemory(pExtraData->pvBuffer,
                           IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
                           InBuffers[1].cbBuffer);

                pExtraData->cbBuffer   = InBuffers[1].cbBuffer;
                pExtraData->BufferType = SECBUFFER_TOKEN;
            }
            else
            {
                pExtraData->pvBuffer   = NULL;
                pExtraData->cbBuffer   = 0;
                pExtraData->BufferType = SECBUFFER_EMPTY;
            }

            break;
        }

        if(FAILED(scRet))
        {
            SetLastError(scRet);
            break;
        }

        if(scRet == SEC_I_INCOMPLETE_CREDENTIALS)
        {
			SetLastError(scRet);
			break;
        }

        if ( InBuffers[1].BufferType == SECBUFFER_EXTRA )
        {
            MoveMemory(IoBuffer,
                       IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
                       InBuffers[1].cbBuffer);

            cbIoBuffer = InBuffers[1].cbBuffer;
        }
        else
        {
            cbIoBuffer = 0;
        }
    }

    if(FAILED(scRet))
    {
        g_pSecFuncTableA->DeleteSecurityContext(phContext);
    }

	if (IoBuffer)
        delete [] IoBuffer;

    return scRet;
}

DWORD CSsl::ClientVerifyCertificate(PCCERT_CONTEXT pServerCert,const CHAR *pszServerName,DWORD dwCertFlags)
{
    HTTPSPolicyCallbackData		polHttps;
    CERT_CHAIN_POLICY_PARA		PolicyPara;
    CERT_CHAIN_POLICY_STATUS	PolicyStatus;
    CERT_CHAIN_PARA				ChainPara;
    PCCERT_CHAIN_CONTEXT		pChainContext = NULL;

    DWORD   Status;
    PWSTR   pwszServerName = NULL;
    DWORD   cchServerName;

	do {
		if(pServerCert == NULL) {
			Status = SEC_E_WRONG_PRINCIPAL;
			SetLastError(Status);
			break;
		}
		int iRc = CertVerifyTimeValidity(NULL,pServerCert->pCertInfo);
		if (iRc != 0) {
			Status = SEC_E_CERT_EXPIRED;
			SetLastError(Status);
			break;
		}

		if (pszServerName == NULL || strlen(pszServerName) == 0) {
			return SEC_E_WRONG_PRINCIPAL;
		}

		cchServerName = MultiByteToWideChar(CP_ACP, 0, pszServerName, -1, NULL, 0);
		pwszServerName = new WCHAR[cchServerName];
		if (pwszServerName == NULL) {
			return SEC_E_INSUFFICIENT_MEMORY;
		}
		cchServerName = MultiByteToWideChar(CP_ACP, 0, pszServerName, -1, pwszServerName, cchServerName);
		if (cchServerName == 0) {
			return SEC_E_WRONG_PRINCIPAL;
		}

		ZeroMemory(&ChainPara, sizeof(ChainPara));
		ChainPara.cbSize = sizeof(ChainPara);

		if (!CertGetCertificateChain(
								NULL,
								pServerCert,
								NULL,
								NULL,
								&ChainPara,
								0,
								NULL,
								&pChainContext)) {
			Status = ::GetLastError();
			SetLastError(Status);
			break;
		}

		ZeroMemory(&polHttps, sizeof(HTTPSPolicyCallbackData));
		polHttps.cbStruct           = sizeof(HTTPSPolicyCallbackData);
		polHttps.dwAuthType         = AUTHTYPE_SERVER;
		polHttps.fdwChecks          = dwCertFlags;
		polHttps.pwszServerName     = pwszServerName;

		memset(&PolicyPara, 0, sizeof(PolicyPara));
		PolicyPara.cbSize            = sizeof(PolicyPara);
		PolicyPara.pvExtraPolicyPara = &polHttps;

		memset(&PolicyStatus, 0, sizeof(PolicyStatus));
		PolicyStatus.cbSize = sizeof(PolicyStatus);

	    if (!CertVerifyCertificateChainPolicy(
                            CERT_CHAIN_POLICY_SSL,
                            pChainContext,
                            &PolicyPara,
                            &PolicyStatus)) {
			Status = ::GetLastError();
			SetLastError(Status);
			break;
		}

		if (PolicyStatus.dwError) {
			Status = PolicyStatus.dwError;
			SetLastError(Status);
			break;
		}

		PCERT_CONTEXT *pCerts = new PCERT_CONTEXT[pChainContext->cChain];

		for (DWORD i = 0; i < pChainContext->cChain; i++) {
			pCerts[i] = (PCERT_CONTEXT)(pChainContext->rgpChain[i]->rgpElement[0]->pCertContext);
		}
		
		CERT_REVOCATION_STATUS revStat;
		revStat.cbSize = sizeof(CERT_REVOCATION_STATUS);

		BOOL bRc = CertVerifyRevocation(
						X509_ASN_ENCODING,
						CERT_CONTEXT_REVOCATION_TYPE,
						pChainContext->cChain,
						(void **)pCerts,
						CERT_VERIFY_REV_CHAIN_FLAG,
						NULL,
						&revStat);
		if (!bRc) {
			SetLastError(revStat.dwError);
			break;
		}

		delete [] pCerts;

		Status = SEC_E_OK;

		} while (FALSE);

    if (pChainContext) {
        CertFreeCertificateChain(pChainContext);
    }

	if (pwszServerName) delete [] pwszServerName;

    return Status;
}

LONG CSsl::ClientDisconnect(PCredHandle phCreds, CtxtHandle *phContext)
{
    DWORD           dwType;
    PBYTE           pbMessage;
    DWORD           cbMessage;
    DWORD           cbData;

    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    DWORD           Status;

    dwType = SCHANNEL_SHUTDOWN;

    OutBuffers[0].pvBuffer   = &dwType;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = sizeof(dwType);

    OutBuffer.cBuffers  = 1;
    OutBuffer.pBuffers  = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

	do {

		Status = g_pSecFuncTableA->ApplyControlToken(phContext, &OutBuffer);

		if(FAILED(Status)) {
			SetLastError(Status);
			break;
		}

		dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
					  ISC_REQ_REPLAY_DETECT     |
					  ISC_REQ_CONFIDENTIALITY   |
					  ISC_RET_EXTENDED_ERROR    |
					  ISC_REQ_ALLOCATE_MEMORY   |
					  ISC_REQ_STREAM;

		if (m_permissive) dwSSPIFlags |= ISC_REQ_MANUAL_CRED_VALIDATION;

		OutBuffers[0].pvBuffer   = NULL;
		OutBuffers[0].BufferType = SECBUFFER_TOKEN;
		OutBuffers[0].cbBuffer   = 0;

		OutBuffer.cBuffers  = 1;
		OutBuffer.pBuffers  = OutBuffers;
		OutBuffer.ulVersion = SECBUFFER_VERSION;

		Status = g_pSecFuncTableA->InitializeSecurityContextA(
                    phCreds,
                    phContext,
                    NULL,
                    dwSSPIFlags,
                    0,
                    SECURITY_NATIVE_DREP,
                    NULL,
                    0,
                    phContext,
                    &OutBuffer,
                    &dwSSPIOutFlags,
                    &tsExpiry);

		if(FAILED(Status))
        {
			SetLastError(Status);
			break;
		}

		pbMessage = (BYTE *)(OutBuffers[0].pvBuffer);
		cbMessage = OutBuffers[0].cbBuffer;

		if (pbMessage && cbMessage)
        {
			cbData = SocketSend(this->s, (char *)pbMessage, cbMessage, 0);
			if(cbData == (DWORD)SOCKET_ERROR || cbData == 0)
            {
				Status = WSAGetLastError();
				break;
			}

			g_pSecFuncTableA->FreeContextBuffer(pbMessage);
		}
    
	} while (FALSE);

    g_pSecFuncTableA->DeleteSecurityContext(phContext);
    return Status;
}

//-----------------------------------------------------------------------------

LONG CSsl::ServerDisconect(PCredHandle phCreds, CtxtHandle *phContext)
{
    DWORD           dwType;
    PBYTE           pbMessage;
    DWORD           cbMessage;
    DWORD           cbData;

    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    DWORD           Status;

    dwType = SCHANNEL_SHUTDOWN;

    OutBuffers[0].pvBuffer   = &dwType;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = sizeof(dwType);

    OutBuffer.cBuffers  = 1;
    OutBuffer.pBuffers  = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

	do {

		Status = g_pSecFuncTableA->ApplyControlToken(phContext, &OutBuffer);

		if(FAILED(Status)) {
			SetLastError(Status);
			break;
		}

		dwSSPIFlags =   ASC_REQ_SEQUENCE_DETECT     |
						ASC_REQ_REPLAY_DETECT       |
						ASC_REQ_CONFIDENTIALITY     |
						ASC_REQ_EXTENDED_ERROR      |
						ASC_REQ_ALLOCATE_MEMORY     |
						ASC_REQ_STREAM;

		OutBuffers[0].pvBuffer   = NULL;
		OutBuffers[0].BufferType = SECBUFFER_TOKEN;
		OutBuffers[0].cbBuffer   = 0;

		OutBuffer.cBuffers  = 1;
		OutBuffer.pBuffers  = OutBuffers;
		OutBuffer.ulVersion = SECBUFFER_VERSION;

		Status = g_pSecFuncTableA->AcceptSecurityContext(
						phCreds,
						phContext,
						NULL,
						dwSSPIFlags,
						SECURITY_NATIVE_DREP,
						NULL,
						&OutBuffer,
						&dwSSPIOutFlags,
						&tsExpiry);

		if(FAILED(Status))  {
			SetLastError(Status);
			break;
		}

		pbMessage = (BYTE *)(OutBuffers[0].pvBuffer);
		cbMessage = OutBuffers[0].cbBuffer;

		if(pbMessage != NULL && cbMessage != 0)
        {
			m_bAllowPlainText = TRUE;
			cbData = SocketSend(this->s, (char *)pbMessage, cbMessage, 0);

			m_bAllowPlainText = FALSE;
			if(cbData == (DWORD)SOCKET_ERROR || cbData == 0)
            {
				Status = WSAGetLastError();
				SetLastError(Status);
				break;
			}

			g_pSecFuncTableA->FreeContextBuffer(pbMessage);
		}

	} while (FALSE);

    g_pSecFuncTableA->DeleteSecurityContext(phContext);

    return Status;
}

BOOL CSsl::ServerConnect(SOCKADDR* lpSockAddr, int* lpSockAddrLen)
{
	BOOL rc = FALSE;
	SECURITY_STATUS scRet;
	PCCERT_CONTEXT pRemoteCertContext = NULL;
	SecPkgContext_StreamSizes Sizes;

	do {

		if (!ServerHandshakeLoop(&m_hContext,&m_hCreds,m_bAuthClient,TRUE,TRUE)) {
			break;
		}

		if(m_bAuthClient) {
            scRet = g_pSecFuncTableA->QueryContextAttributesA(&m_hContext,
                                            SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                                            (PVOID)&pRemoteCertContext);

            if(scRet != SEC_E_OK) {
                SetLastError(scRet);
				break;
            } else {
                scRet = ServerVerifyCertificate(pRemoteCertContext, 0);
                if(scRet) {
                    SetLastError(scRet);
                    break;
                }
				CertFreeCertificateContext(pRemoteCertContext);
            }
        }

        scRet = g_pSecFuncTableA->QueryContextAttributesA(&m_hContext, SECPKG_ATTR_STREAM_SIZES, &Sizes);

        if(scRet != SEC_E_OK) {
            SetLastError(scRet);
            break;
        }

		rc = TRUE;

	} while (FALSE);

	return rc;
}

BOOL CSsl::ServerHandshakeLoop(PCtxtHandle phContext, PCredHandle phCred, BOOL fClientAuth, BOOL fDoInitialRead, BOOL NewContext)
{
    TimeStamp            tsExpiry;
    SECURITY_STATUS      scRet;
    SecBufferDesc        InBuffer;
    SecBufferDesc        OutBuffer;
    SecBuffer            InBuffers[2];
    SecBuffer            OutBuffers[1];
    DWORD                err;

    BOOL                 fDoRead;
    BOOL                 fInitContext = NewContext;

    DWORD                dwSSPIFlags, dwSSPIOutFlags;

	BYTE IoBuffer[IO_BUFFER_SIZE];
	DWORD cbIoBuffer = 0;

    scRet = SEC_E_SECPKG_NOT_FOUND;
    err = 0;

    fDoRead = fDoInitialRead;

    dwSSPIFlags =   ASC_REQ_SEQUENCE_DETECT        |
                    ASC_REQ_REPLAY_DETECT      |
                    ASC_REQ_CONFIDENTIALITY  |
                    ASC_REQ_EXTENDED_ERROR    |
                    ASC_REQ_ALLOCATE_MEMORY  |
                    ASC_REQ_STREAM;

    if(fClientAuth) {
        dwSSPIFlags |= ASC_REQ_MUTUAL_AUTH;
    }


    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    scRet = SEC_I_CONTINUE_NEEDED;

    while( scRet == SEC_I_CONTINUE_NEEDED ||
            scRet == SEC_E_INCOMPLETE_MESSAGE ||
            scRet == SEC_I_INCOMPLETE_CREDENTIALS)  {

        if(0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE) {

            if(fDoRead)
            {
				m_bAllowPlainText = TRUE;
				err = recv(this->s, (char *)IoBuffer+cbIoBuffer, IO_BUFFER_SIZE, 0);
				m_bAllowPlainText = FALSE;

				if (err == (DWORD)SOCKET_ERROR || err == 0) {
					SetLastError(::WSAGetLastError());
					return FALSE;
				} else {
					cbIoBuffer += err;
				}
            } else {
                fDoRead = TRUE;
            }
        }

        InBuffers[0].pvBuffer = IoBuffer;
        InBuffers[0].cbBuffer = cbIoBuffer;
        InBuffers[0].BufferType = SECBUFFER_TOKEN;

        InBuffers[1].pvBuffer   = NULL;
        InBuffers[1].cbBuffer   = 0;
        InBuffers[1].BufferType = SECBUFFER_EMPTY;

        InBuffer.cBuffers        = 2;
        InBuffer.pBuffers        = InBuffers;
        InBuffer.ulVersion       = SECBUFFER_VERSION;

        OutBuffers[0].pvBuffer   = NULL;
        OutBuffers[0].BufferType = SECBUFFER_TOKEN;
        OutBuffers[0].cbBuffer   = 0;

        scRet = g_pSecFuncTableA->AcceptSecurityContext(
                        phCred,
                        (fInitContext?NULL:phContext),
                        &InBuffer,
                        dwSSPIFlags,
                        SECURITY_NATIVE_DREP,
                        (fInitContext?phContext:NULL),
                        &OutBuffer,
                        &dwSSPIOutFlags,
                        &tsExpiry);

        fInitContext = FALSE;

        if ( scRet == SEC_E_OK ||
             scRet == SEC_I_CONTINUE_NEEDED ||
             (FAILED(scRet) && (0 != (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR)))) {

            if  (OutBuffers[0].cbBuffer != 0    &&
                 OutBuffers[0].pvBuffer != NULL )
            {
				m_bAllowPlainText = TRUE;
                err = SocketSend(this->s, (char *)OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
				m_bAllowPlainText = FALSE;

                g_pSecFuncTableA->FreeContextBuffer( OutBuffers[0].pvBuffer );
                OutBuffers[0].pvBuffer = NULL;
            }
        }

        if ( scRet == SEC_E_OK ) {
            if ( InBuffers[1].BufferType == SECBUFFER_EXTRA ) {
                    memcpy(IoBuffer,
                           (LPBYTE) (IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer)),
                            InBuffers[1].cbBuffer);
                    cbIoBuffer = InBuffers[1].cbBuffer;
            } else {
                cbIoBuffer = 0;
            }

            return TRUE;
        } else if (FAILED(scRet) && (scRet != SEC_E_INCOMPLETE_MESSAGE)) {
            SetLastError(scRet);
            return FALSE;
        }

        if ( scRet != SEC_E_INCOMPLETE_MESSAGE &&
             scRet != SEC_I_INCOMPLETE_CREDENTIALS) {

            if ( InBuffers[1].BufferType == SECBUFFER_EXTRA ) {
                memcpy(IoBuffer,
                       (LPBYTE) (IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer)),
                        InBuffers[1].cbBuffer);
                cbIoBuffer = InBuffers[1].cbBuffer;
            } else {
                cbIoBuffer = 0;
            }
        }
    }

    return FALSE;
}

DWORD CSsl::ServerVerifyCertificate(PCCERT_CONTEXT pServerCert, DWORD dwCertFlags)
{
    HTTPSPolicyCallbackData		polHttps;
    CERT_CHAIN_POLICY_PARA		PolicyPara;
    CERT_CHAIN_POLICY_STATUS	PolicyStatus;
    CERT_CHAIN_PARA				ChainPara;
    PCCERT_CHAIN_CONTEXT		pChainContext = NULL;

    DWORD   Status;

	do {
		if(pServerCert == NULL) {
			Status = SEC_E_WRONG_PRINCIPAL;
			SetLastError(Status);
			break;
		}

		int iRc = CertVerifyTimeValidity(NULL,pServerCert->pCertInfo);
		if (iRc != 0) {
			Status = SEC_E_CERT_EXPIRED;
			SetLastError(Status);
			break;
		}

		ZeroMemory(&ChainPara, sizeof(ChainPara));
		ChainPara.cbSize = sizeof(ChainPara);

		if(!CertGetCertificateChain(
								NULL,
								pServerCert,
								NULL,
								NULL,
								&ChainPara,
								CERT_CHAIN_REVOCATION_CHECK_CHAIN,
								NULL,
								&pChainContext)) {
			Status = ::GetLastError();
			SetLastError(Status);
			break;
		}

		ZeroMemory(&polHttps, sizeof(HTTPSPolicyCallbackData));
		polHttps.cbStruct           = sizeof(HTTPSPolicyCallbackData);
		polHttps.dwAuthType         = AUTHTYPE_CLIENT;
		polHttps.fdwChecks          = dwCertFlags;
		polHttps.pwszServerName     = NULL;

		memset(&PolicyPara, 0, sizeof(PolicyPara));
		PolicyPara.cbSize            = sizeof(PolicyPara);
		PolicyPara.pvExtraPolicyPara = &polHttps;

		memset(&PolicyStatus, 0, sizeof(PolicyStatus));
		PolicyStatus.cbSize = sizeof(PolicyStatus);

		if(!CertVerifyCertificateChainPolicy(
								CERT_CHAIN_POLICY_SSL,
								pChainContext,
								&PolicyPara,
								&PolicyStatus)) {
			Status = ::GetLastError();
			SetLastError(Status);
			break;
		}

		if (PolicyStatus.dwError) {
			Status = PolicyStatus.dwError;
			SetLastError(Status);
			break;
		}

		PCERT_CONTEXT *pCerts = new PCERT_CONTEXT[pChainContext->cChain];

		for (DWORD i = 0; i < pChainContext->cChain; i++) {
			pCerts[i] = (PCERT_CONTEXT)(pChainContext->rgpChain[i]->rgpElement[0]->pCertContext);
		}
		
		CERT_REVOCATION_STATUS revStat;
		revStat.cbSize = sizeof(CERT_REVOCATION_STATUS);

		BOOL bRc = CertVerifyRevocation(
						X509_ASN_ENCODING,
						CERT_CONTEXT_REVOCATION_TYPE,
						pChainContext->cChain,
						(void **)pCerts,
						CERT_VERIFY_REV_CHAIN_FLAG,
						NULL,
						&revStat);
		if (!bRc) {
			SetLastError(revStat.dwError);
			break;
		}

		delete [] pCerts;
		Status = SEC_E_OK;

	} while(FALSE);

    if (pChainContext) {
        CertFreeCertificateChain(pChainContext);
    }

    return Status;
}

