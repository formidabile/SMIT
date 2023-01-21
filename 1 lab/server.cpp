#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <fstream>
#include <windows.h>
#include <stdio.h>
using namespace std;

#include "int_h.h"

#pragma comment (lib, "Rpcrt4.lib")
#pragma warning(disable:4996)

const unsigned int cMaxClient = 10;

struct client
{
	handle_t client_handle;
	FILE* file;
	bool IsClosedFile;
};

client ALL_Clients[cMaxClient];
unsigned int count_clients = 0;
bool IsConnectedClient[cMaxClient] = { false };

int MakeClientOnServer(const unsigned char* login, const unsigned char* password, int* index)
{
	if (count_clients >= cMaxClient)
		return -2;
	int new_index = 0;

	for (; (IsConnectedClient[new_index]) && new_index < cMaxClient; new_index++);
	if (new_index == cMaxClient)
		return -2;
	handle_t handle = 0;

	if (!LogonUserA((LPCSTR)login, NULL, (LPCSTR)password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &handle))
	{
		cout << ">> Token descriptor not received";
		return -1;
	}

	if (!ImpersonateLoggedOnUser(handle))
	{
		cout << ">> Impersonation error";
		return -1;
	}

	ALL_Clients[new_index].client_handle = handle;
	ALL_Clients[new_index].IsClosedFile = true;
	ALL_Clients[new_index].file = NULL;
	IsConnectedClient[new_index] = true;
	count_clients++;
	(*index) = new_index;

	cout << ">> Ñonnected!" << endl;
	return 1;
}

void Output(const unsigned char* szOutput)
{
	std::cout << szOutput << std::endl;
}

int CopyOnClient(const unsigned char* path, int buf[65534], unsigned int* length_buf, int index, int* check_eof)
{
	if (!ImpersonateLoggedOnUser(ALL_Clients[index].client_handle))
	{
		cout << ">> Client " << index << " impersonation error" << endl;
		return -1;
	}

	if (ALL_Clients[index].IsClosedFile)
	{
		cout << ">> Opening file for the first time\n";
		ALL_Clients[index].file = fopen((const char*)path, "rb");
		ALL_Clients[index].IsClosedFile = false;
	}

	if (!ALL_Clients[index].file)
	{
		cout << ">> No access" << endl;
		ALL_Clients[index].IsClosedFile = true;
		return -1;
	}

	int symbol = 0;
	int len = 0;

	while (len < cMaxBuf)
	{
		int check = fread(&symbol, 1, 1, ALL_Clients[index].file);
		if (check == 0)
		{
			*check_eof = 1;
			fclose(ALL_Clients[index].file);
			ALL_Clients[index].IsClosedFile = true;
			break;
		}
		buf[len] = symbol;
		len++;
	}

	(*length_buf) = len;
	return 1;
}

int MakeFileOnServer(const unsigned char* FileName, int buf[65534], int len_buf, int index, int EndOfFile)
{
	if (!ImpersonateLoggedOnUser(ALL_Clients[index].client_handle))
	{
		cout << ">> Impersonation error" << endl;
		return -1;
	}

	if (ALL_Clients[index].IsClosedFile)
	{
		cout << ">> Opening file for the first time\n";
		ALL_Clients[index].file = fopen((const char*)(FileName), "wb");
		ALL_Clients[index].IsClosedFile = false;
	}

	if (!ALL_Clients[index].file)
	{
		cout << ">> No access" << endl;
		ALL_Clients[index].IsClosedFile = true;
		return -1;
	}

	for (unsigned int i = 0; i < len_buf; i++)
		fwrite(&buf[i], 1, 1, ALL_Clients[index].file);

	if (EndOfFile)
	{
		ALL_Clients[index].IsClosedFile = true;
		fclose(ALL_Clients[index].file);
	}

	return 1;
}

int DeleteFileOnServer(const unsigned char* PathToFile, int index)
{
	if (!ImpersonateLoggedOnUser(ALL_Clients[index].client_handle))
	{
		cout << ">> Impersonation error" << endl;
		return -1;
	}

	if (remove((const char*)PathToFile) == -1)
	{
		cout << ">> No access" << endl;
		return -1;
	}

	return 1;
}

int ClientOut(int index)
{
	if (index > cMaxClient || index < 0)
		return -1;

	IsConnectedClient[index] = false;
	ALL_Clients[index].client_handle = 0;
	ALL_Clients[index].IsClosedFile = true;
	ALL_Clients[index].file = NULL;
	count_clients--;

	cout << ">> Client disconnected" << endl;
	return 1;
}

RPC_STATUS CALLBACK SecurityCallback(RPC_IF_HANDLE, void*)
{
	return RPC_S_OK;
}

int main()
{
	setlocale(LC_ALL, "Rus");
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);

	RPC_STATUS status;
	RpcServerRegisterAuthInfoA(nullptr, RPC_C_AUTHN_WINNT, 0, nullptr);

	status = RpcServerUseProtseqEpA(
		(RPC_CSTR)("ncacn_ip_tcp"),
		RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
		(RPC_CSTR)("9000"),
		NULL);

	if (status)
		exit(status);

	status = RpcServerRegisterIf2(
		Example1_v1_0_s_ifspec,              // Interface to register.
		NULL,                                // Use the MIDL generated entry-point vector.
		NULL,                                // Use the MIDL generated entry-point vector.
		RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH, // Forces use of security callback.
		RPC_C_LISTEN_MAX_CALLS_DEFAULT,      // Use default number of concurrent calls.
		(unsigned)-1,                        // Infinite max size of incoming data blocks.
		SecurityCallback);                   // Naive security callback.

	if (status)
		exit(status);
	cout << ">> Server started!" << endl;

	status = RpcServerListen(
		1,                                   // Recommended minimum number of threads.
		RPC_C_LISTEN_MAX_CALLS_DEFAULT,      // Recommended maximum number of threads.
		FALSE);                              // Start listening now.
	cout << ">> Shutdown" << endl;
	if (status)
		exit(status);
}

void* __RPC_USER midl_user_allocate(size_t size)
{
	return malloc(size);
}

void __RPC_USER midl_user_free(void* p)
{
	free(p);
}