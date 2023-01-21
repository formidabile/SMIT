#define WIN32_LEAN_AND_MEAN 
#include <windows.h> 
#include <winsock2.h> 
#include <ws2tcpip.h> // ƒиректива линковщику: использовать библиотеку сокетов 
#pragma comment(lib, "ws2_32.lib") 
#include <stdio.h> 
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <io.h>
#include <wincrypt.h>
#include<string.h>
#include <conio.h>
#pragma warning(disable : 4996)

#include <iostream>
#include <string>
#include <vector>

#define MAX_COMMAND_SIZE 500
#define MAX_BUFFER_SIZE 2048
#define KEY_BUF_SIZE 256
#define MIN_PATH_SIZE 5

using namespace std;

typedef struct sock
{
	int s;

	HCRYPTPROV DescCSP;
	HCRYPTKEY DescKey;
	HCRYPTKEY DescKey_imp;
	HCRYPTKEY hPublicKey, hPrivateKey;

}socketExtended;

vector<socketExtended> sockets;

int init()
{
	// ƒл€ Windows следует вызвать WSAStartup перед началом использовани€ сокетов 
	WSADATA wsa_data;
	return (0 == WSAStartup(MAKEWORD(2, 2), &wsa_data));
}

void deinit()
{
	// ƒл€ Windows следует вызвать WSACleanup в конце работы 
	WSACleanup();
}

int sock_err(const char* function, int s)
{
	int err;
	err = WSAGetLastError();
	fprintf(stderr, "%s: socket error: %d\n", function, err);
	return -1;
}

void s_close(int s)
{
	closesocket(s);
}

int connect_100ms(int s, struct sockaddr_in addr)
{
	for (int rec = 0; rec < 10; rec++)
	{
		if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0)
			return 0;
		else
		{
			fprintf(stdout, "%i time failed to connect to server\n", (rec + 1));
			Sleep(100);
		}
	}
	return 1;
}

unsigned int strLength(char* mas, int startPos)
{
	int i = startPos;
	for (int j = startPos - 1; j >= 0; j--)
	{
		if (mas[j] != '\0') break;
		else i--;
	}

	return i;
}

int crytp_send(int choiceSize, char* buffer, unsigned int& bufSize, int s, char* choice)
{
	if (!CryptEncrypt(sockets[s].DescKey_imp, 0, TRUE, 0, (BYTE*)choice, (DWORD*)&choiceSize, MAX_COMMAND_SIZE))
		printf("ERROR, %x", GetLastError());

	if (send(sockets[s].s, choice, choiceSize, 0) < 0)
		return sock_err("send", sockets[s].s);
	if (recv(sockets[s].s, buffer, MAX_BUFFER_SIZE, 0) < 0)
		return sock_err("receive", sockets[s].s);

	bufSize = strLength(buffer, MAX_BUFFER_SIZE);
	if (!CryptDecrypt(sockets[s].DescKey_imp, NULL, TRUE, NULL, (BYTE*)buffer, (DWORD*)&bufSize))
		printf("ERROR, %x", GetLastError());
	return 1;
}

int CryptReal(int s, sockaddr_in addr)
{
	socketExtended result;
	// дл€ создани€ контейнера ключей с определенным CSP
	/*phProv Ц указатель а дескриптор CSP.
	  pszContainer Ц им€ контейнера ключей.
	  pszProvider Ц им€ CSP.
	  dwProvType Ц тип CSP.
	  dwFlags Ц флаги.*/
	  /*
	  —оздает новый контейнер ключей с именем, указанным в pszContainer .\
	  ≈сли pszContainer имеет значение NULL , создаетс€ контейнер ключей \
	  с именем по умолчанию.
	  */
	if (!CryptAcquireContextW(&result.DescCSP, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
	{
		if (!CryptAcquireContextW(&result.DescCSP, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			printf("ERROR, %x", GetLastError());
	}

	/*
	‘ункци€ экспорта ключа дл€ его передачи по каналам информации.
	¬озможны различные варианты передачи ключа, включа€ передачу публичного ключа,
	пары ключей, а также передачу секретного или сеансового ключа
		hProvЦ дескриптор CSP.
		Algid Ц идентификатор алгоритма(указываем, что генерируем пару ключей, а не подпись).
		dwFlags Ц флаги.
		phKey Ц указатель на дескриптор ключа.*/
	if (CryptGenKey(result.DescCSP, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &result.DescKey) == 0)
		printf("ERROR, %i", GetLastError());

	// лиент генерирует асимметричный ключЦпару ключей публичный/приватный
	if (!CryptGetUserKey(result.DescCSP, AT_KEYEXCHANGE, &result.hPublicKey))
		printf("CryptGetUserKey err\n");
	if (!CryptGetUserKey(result.DescCSP, AT_KEYEXCHANGE, &result.hPrivateKey))
		printf("CryptGetUserKey err\n");

	char ExpBuf[KEY_BUF_SIZE] = { 0 };
	DWORD len = KEY_BUF_SIZE;

	// лиент посылает публичный ключ серверу
	//2й аргумент - 0, тк мы не шифруем посылаемый публичный ключ
	/*
	hKey Ц дескриптор экспортируемого ключа.
	hExpKey Ц ключ, с помощью которого будет зашифрован hKey при экспорте.
	dwBlobType Ц тип экспорта.
	dwFlags Ц флаги.
	pbData Ц буфер дл€ экспорта. Ѕудет содержать зашифрованный hKey с помощью
	hExpKey.
	pdwDataLen Ц длина буфера на вход. Ќа выходе Ц количество значащих байт
	*/
	if (!CryptExportKey(result.hPublicKey, 0, PUBLICKEYBLOB, NULL, (BYTE*)ExpBuf, &len))
		printf("ERROR, %x", GetLastError());

	//передаЄм длину ключа
	int expBufSize = strLength(ExpBuf, KEY_BUF_SIZE);
	ExpBuf[expBufSize] = expBufSize;

	//отправка - получение информации
	if (send(s, ExpBuf, (expBufSize + 1), 0) < 0)
		sock_err("send", s);
	char buffer[KEY_BUF_SIZE] = { 0 };
	if (recv(s, buffer, KEY_BUF_SIZE, 0) < 0)
		sock_err("receive", s);

	int bufSize = strLength(buffer, KEY_BUF_SIZE) - 1;
	unsigned int dli = (unsigned char)buffer[bufSize];
	buffer[bufSize] = 0;

	// лиент получает зашифрованное сообщение и расшифровывает его с помощью
	//своего приватного ключа
	//‘ункци€ предназначена дл€ получени€ из каналов информации значени€\
	ключа
	/*
	hProv Ц дескриптор CSP.
	pbData Ц импортируемый ключ представленный в виде массива байт.
	dwDataLen Цдлина данных в pbData.
	hPubKey - дескриптор ключа, который расшифрует ключ содержащийс€ в pbData.
	dwFlags - флаги.
	phKey Ц указатель на дескриптор ключа. Ѕудет указывать на импортированный ключ
	*/
	if (!CryptImportKey(result.DescCSP, (BYTE*)buffer, dli, result.hPrivateKey, 0, &result.DescKey_imp))//получаем сеансовый ключ
		printf("ERROR, %x", GetLastError());
	result.s = s;
	sockets.push_back(result);
	return s;
}

void input_str(char* choiceStr, char* choice)
{
	char temp[MAX_COMMAND_SIZE];
	int i = 0;
	int indexM = -1;
	for (; i < strlen(choiceStr); i++)
	{
		if (choiceStr[i] == ' ')
		{
			indexM = i;
			break;
		}

		temp[i] = choiceStr[i];
		temp[i + 1] = '\0';
	}

	//printf("ѕробел:%d\n", indexM);
	if (strcmp(temp, "help") == 0)
	{
		choice[0] = 'h';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "add_server") == 0)
	{
		choice[0] = 'a';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "info_OS") == 0)
	{
		choice[0] = 'o';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "current_time") == 0)
	{
		choice[0] = 't';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "time_from_start") == 0)
	{
		choice[0] = 'm';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "info_disks") == 0)
	{
		choice[0] = 'f';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "info_memory") == 0)
	{
		choice[0] = 's';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "close_client") == 0)
	{
		choice[0] = 'e';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "end") == 0)
	{
		choice[0] = 'q';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "rights") == 0)
	{
		choice[0] = 'p';
		choice[1] = ' ';
	}
	if (strcmp(temp, "owner") == 0)
	{
		choice[0] = 'r';
		choice[1] = ' ';
	}
	int j = 0;
	for (i = 2, j = indexM + 1; j < strlen(choiceStr); i++, j++)
	{
		choice[i] = choiceStr[j];
		choice[i + 1] = '\0';
	}
	return;
}

int addNewSocket()
{
	cout << "Enter IP:Port : ";

	string ipAddrAndPort = "";

	cin >> ipAddrAndPort;
	//ipAddrAndPort = "192.168.1.126:9000";
	string ipAddress = ipAddrAndPort.substr(0, ipAddrAndPort.find(":"));
	string port = ipAddrAndPort.substr(ipAddrAndPort.find(":") + 1);

	if (port.size() == 0)
		return sock_err("finding the port", 0);

	int s;
	struct sockaddr_in addr;
	short num_port = (short)atoi(port.c_str());

	// »нициалиазаци€ сетевой библиотеки 
	init();

	// —оздание TCP-сокета 
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		return sock_err("socket", s);

	// «аполнение структуры с адресом удаленного узла 
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(num_port);
	addr.sin_addr.s_addr = inet_addr(ipAddress.c_str());

	// ѕопытка установить соединение 
	if (connect_100ms(s, addr) != 0)
	{
		s_close(s);
		return sock_err("connect", s);
	}
	cout << "Connecting to server" << endl;

	//crypt
	s = CryptReal(s, addr);

	cout << "Socket number: " << sockets.size() << endl;

	return s;
}

int io_serv()
{
	char buffer[MAX_BUFFER_SIZE] = { 0 };
	char choice[MAX_COMMAND_SIZE];
	//string choiceStr = "";
	char choiceStr[MAX_COMMAND_SIZE];
	char socketNumStr[MAX_COMMAND_SIZE];
	//string socketNumStr = "";
	unsigned int choiceSize;
	unsigned int bufSize;
	//string bufStrForSize = "";
	bool start = true;
	int s = 0;//current socket


	do
	{
		memset(buffer, 0, MAX_BUFFER_SIZE);
		memset(choice, 0, MAX_COMMAND_SIZE);
		if (!start)
			cout << ">> ";
		else
		{
			addNewSocket();
			start = false;
			//cout << endl << "What information about the system do you want to know(\"h\" for help)? " << endl;
			cout << ">> ";
		}

		//cin.getline(choice, MAX_COMMAND_SIZE);
		scanf("%d", &s);
		char sym;
		scanf("%c", &sym);
		if (s > 0)
		{
			//s = stoi(socketNumStr);
			s--;
			scanf("%[^\n]", choiceStr);
			//printf("%s\n", choiceStr);
			input_str(choiceStr, choice);
			//strcpy(choice, choiceStr.c_str());
			//printf("\'%s\'\n", choice);
			choiceSize = strlen(choice);
			switch (choice[0])
			{
			case 'o':
			{
				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return -1;

				cout << "\n{ \n  \"OSVersion\" : " << buffer << "\n}\n" << endl;
				break;
			}
			case 't':
			{
				crytp_send(choiceSize, buffer, bufSize, s, choice);

				//cout << "Current data - " << buffer << endl;		
				string outStr = string(buffer);
				cout << "\n{\n  \"currentData\" : \"" + outStr.substr(0, outStr.find(" "))
					+ "\",\n  \"currentTime\" : \"" + outStr.substr(outStr.find(" "), outStr.size() - outStr.find(" "))
					+ "\"\n}\n\n";

				break;

			}
			case 'm':
			{
				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return -1;

				int msec = 0;
				memcpy(&msec, buffer, sizeof(int));
				int hour = msec / (1000 * 60 * 60);
				int min = msec / (1000 * 60) - hour * 60;
				int sec = sec = (msec / 1000) - (hour * 60 * 60) - min * 60;

				cout << "\n{\n  \"hours\" : " << hour
					<< ",\n  \"minutes\" : " << min
					<< ",\n  \"seconds\" : " << sec
					<< "\n}\n\n";

				break;
			}
			case 's':
			{
				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return -1;

				cout << endl << buffer << endl;
				break;
			}
			case 'f':
			{
				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return -1;

				cout << endl << buffer << endl;
				break;
			}
			case 'p':
			{
				if (choiceSize < MIN_PATH_SIZE)
				{
					cout << "Incorrect path" << endl;
					break;
				}

				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return -1;

				cout << buffer << endl;

				break;
			}
			case 'r':
			{
				if (choiceSize < MIN_PATH_SIZE)
				{
					cout << "Incorrect path" << endl;
					break;
				}

				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return -1;

				cout << endl << buffer << endl;
				break;
			}
			case 'h':
			{
				printf("info_OS\n\
current_time\n\
time_from_start\n\
info_memory\n\
info_disks\n\
rights \'path\' \n\
owner \'path\' \n\
add_server\n\
close_client\n\
end\n");
				continue;
			}
			case 'a':
			{
				addNewSocket();
				break;
			}
			case 'e':
			{
				if (!CryptEncrypt(sockets[s].DescKey_imp, 0, TRUE, 0, (BYTE*)choice, (DWORD*)&choiceSize, MAX_COMMAND_SIZE))
					printf("ERROR, %x", GetLastError());

				if (send(sockets[s].s, choice, strlen(choice), 0) < 0)
					return sock_err("send", sockets[s].s);

				if (!CryptDecrypt(sockets[s].DescKey_imp, NULL, TRUE, NULL, (BYTE*)choice, (DWORD*)&choiceSize))
					printf("ERROR, %x", GetLastError());

				//sockets.erase(sockets.begin() + s);
				//continue;
				break;
			}
			case 'q':
			{
				goto END;
			}
			default:
			{
				printf("Incorrect command\n");
				continue;
			}
			}
		}

	} while (choice[0] != 'q');
END:
	cout << "Connection closed" << endl;
	s_close(s);
	deinit();
	return 0;
}


int main(void)
{
	setlocale(LC_ALL, "Russian");
	return io_serv();
}
