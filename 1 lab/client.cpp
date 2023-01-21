#include <windows.h>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <locale.h>
#include <conio.h>

#include "int_h.h"

#pragma comment (lib, "Rpcrt4.lib")
#pragma warning(disable:4996)

#define SIZE 100

using namespace std;

void download_to_server(int index_client)
{
	char PathToFile[SIZE] = { 0 }, FileName[64] = { 0 };
	int DataOfFile[cMaxBuf] = { 0 };
	unsigned int len_buf = 0, len_path = 0, len_FileName = 0;
	int res, EndOfFile = 0, symbol;

	cout << "Enter exist file path on client: ";
	cin >> PathToFile;
	len_path = strlen(PathToFile);

	int i;
	for (i = len_path - 1; PathToFile[i] != '\\'; i--);
	for (i += 1; i < len_path && len_FileName < 63; i++)
	{
		FileName[len_FileName] = PathToFile[i];
		len_FileName++;
	}
	char FileNameOnServer[SIZE] = { 0 };
	cout << "Enter new file path on server: ";
	cin >> FileNameOnServer;

	FILE* file = fopen(PathToFile, "rb");

	while (1)
	{
		while (len_buf < cMaxBuf)
		{
			res = fread(&symbol, 1, 1, file);
			if (res == 0)
			{
				EndOfFile = 1;
				break;
			}
			DataOfFile[len_buf++] = symbol;
		}

		res = MakeFileOnServer((const unsigned char*)FileNameOnServer, DataOfFile, len_buf, index_client, EndOfFile);

		if (res < 0)
		{
			cout << "No access" << endl;
			break;
		}
		memset(DataOfFile, 0, cMaxBuf);
		len_buf = 0;
		if (EndOfFile)
		{
			cout << "Successful" << endl;
			break;
		}
	}
	if (file != NULL)
		fclose(file);
}

void download_from_server(int index_client)
{
	char PathToFile[SIZE] = { 0 }, FileName[64] = { 0 };
	int DataOfFile[cMaxBuf] = { 0 };
	unsigned int len_buf = 0, len_path = 0, len_FileName = 0;
	int res, EndOfFile = 0;

	cout << "Enter exist file path on server: ";
	cin >> PathToFile;
	for (; PathToFile[len_path] != L'\0'; len_path++);

	int i = 0;
	for (i = len_path - 1; PathToFile[i] != '\\'; i--);
	for (i += 1; i < len_path && len_FileName < 63; i++)
	{
		FileName[len_FileName] = PathToFile[i];
		len_FileName++;
	}
	FileName[len_FileName] = '\0';

	bool IsOpenedFile = true;
	FILE* file = NULL;

	while (1)
	{

		res = CopyOnClient((const unsigned char*)PathToFile, DataOfFile, &len_buf, index_client, &EndOfFile);
		if (res < 0)
		{
			cout << "No access" << endl;
			break;
		}
		if (IsOpenedFile)
		{
			file = fopen(FileName, "wb");
			IsOpenedFile = false;
		}
		for (unsigned int i = 0; i < len_buf; i++)
			fwrite(&DataOfFile[i], 1, 1, file);

		memset(DataOfFile, 0, cMaxBuf);
		if (EndOfFile)
			break;
	}
	if (file != NULL)
	{
		cout << "Success" << endl;
		fclose(file);
	}
}

int main()
{

AGAIN_:
	RPC_STATUS status;
	RPC_CSTR szStringBinding = NULL;

	char IPv4[32];
	char ListeningPort[8];

	cout << "Please, enter ip adress: ";
	cin >> IPv4;
	cout << "Please, enter port: ";
	cin >> ListeningPort;


	status = RpcStringBindingComposeA(
		NULL,
		(RPC_CSTR)("ncacn_ip_tcp"),
		(RPC_CSTR)(IPv4),
		(RPC_CSTR)(ListeningPort),
		NULL,
		&szStringBinding);

	if (status)
	{
		cout << "No connection." << endl;
		exit(status);
	}

	status = RpcBindingFromStringBindingA(
		szStringBinding,
		&hExample1Binding);

	if (status)
		exit(status);

	int index_client = 0, size_pass;
	char login[SIZE] = { 0 };
	char password[SIZE] = { 0 };

	cout << "\n";
	cout << "Please, enter login: ";
	cin >> login;
	cout << "Please, enter password: ";


	for (size_pass = 0; size_pass < SIZE && password[size_pass - 1] != L'\r'; size_pass++)
		password[size_pass] = _getch();

	password[size_pass - 1] = '\0';
	system("cls");

	int res = MakeClientOnServer((const unsigned char*)login, (const unsigned char*)password, &index_client);

	printf("Your index is %d\n", index_client);

	switch (res)
	{
	case -2:
		cout << "Exceeded the number of clients";
		_getch();
		return 0;
		break;
	case -1:
		cout << "Authorisation Error";
		_getch();
		return 0;
		break;
	}
	cout << "Registration completed!" << endl;

	RpcTryExcept
	{
		char PathToFile[SIZE] = { 0 };
		int ChoosenAction = 0;

		while (1)
		{
			cout << "1. Download file" << endl
				<< "2. UpLoad file to server" << endl <<
				"3. Delete file" << endl <<
				"4. Exit" << endl <<
				"5. Disconnect" << endl <<
				"Enter action: ";

			cin >> ChoosenAction;
			switch (ChoosenAction)
			{
			case 1:
				download_from_server(index_client);
				break;
			case 2:
				download_to_server(index_client);
				break;
			case 3:
				cout << "Enter exist file path on server: ";
				cin >> PathToFile;
				res = DeleteFileOnServer((const unsigned char*)PathToFile, index_client);
				if (res < 0)
					cout << "No access" << endl;
				else
					cout << "Success!" << endl;
				break;

			case 4:
				ClientOut(index_client);
				goto OUT_;
				break;
			case 5:
				ClientOut(index_client);
				goto AGAIN_;

			default:
				cout << "Incorrect action" << endl;
			}
			memset(PathToFile, 0, SIZE);
			ChoosenAction = 0;
		}
	}
		RpcExcept(1)
	{
		std::cerr << "Runtime reported exception " << RpcExceptionCode()
			<< std::endl;
	}
	RpcEndExcept

		OUT_ :
	status = RpcStringFreeA(
		&szStringBinding);

	if (status)
		exit(status);

	status = RpcBindingFree(
		&hExample1Binding);

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