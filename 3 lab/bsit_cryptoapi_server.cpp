#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <aclapi.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <string>
#include <time.h>
#include <sddl.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")
#pragma warning(disable: 4996)

#define MAX_CLIENTS (100)
#define CLIENT_TIME 180
#define WIN32_LEAN_AND_MEAN

using namespace std;

int g_accepted_socket;
HANDLE g_io_port;

struct client_ctx
{
	int socket;
	CHAR buf_recv[512]; // Буфер приема
	CHAR buf_send[2048]; // Буфер отправки
	unsigned int sz_recv; // Принято данных
	unsigned int sz_send_total; // Данных в буфере отправки
	unsigned int sz_send; // Данных отправлено
	// Структуры OVERLAPPED для уведомлений о завершении
	//позволяет	определить, какая именно операция была завершена
	OVERLAPPED overlap_recv;
	OVERLAPPED overlap_send;
	OVERLAPPED overlap_cancel;
	DWORD flags_recv; // Флаги для WSARecv

	DWORD time;

	HCRYPTPROV DescCSP = 0;
	HCRYPTKEY DescKey = 0;
	HCRYPTKEY DescKey_open = 0;
};

// Прослушивающий сокет и все сокеты подключения хранятся
// в массиве структур (вместе с overlapped и буферами)
struct client_ctx g_ctxs[1 + MAX_CLIENTS];

unsigned int strLength(char* mas)
{
	int i = 0;
	for (int j = 0; j < 2048; j++)
	{
		if (mas[j] == '\0' && mas[j + 1] == '\0') break;
		else i++;
	}

	return i;
}

// Функция стартует операцию чтения из сокета
void schedule_read(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_recv + g_ctxs[idx].sz_recv;
	buf.len = sizeof(g_ctxs[idx].buf_recv) - g_ctxs[idx].sz_recv;
	memset(&g_ctxs[idx].overlap_recv, 0, sizeof(OVERLAPPED));
	g_ctxs[idx].flags_recv = 0;
	WSARecv(g_ctxs[idx].socket, &buf, 1, NULL, &g_ctxs[idx].flags_recv, &g_ctxs[idx].overlap_recv, NULL);
}

// Функция стартует операцию отправки подготовленных данных в сокет
void schedule_write(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_send + g_ctxs[idx].sz_send;
	buf.len = g_ctxs[idx].sz_send_total - g_ctxs[idx].sz_send;
	memset(&g_ctxs[idx].overlap_send, 0, sizeof(OVERLAPPED));
	WSASend(g_ctxs[idx].socket, &buf, 1, NULL, 0, &g_ctxs[idx].overlap_send, NULL);
}

// Функция добавляет новое принятое подключение клиента
void add_accepted_connection()
{
	DWORD i; // Поиск места в массиве g_ctxs для вставки нового подключения
	for (i = 0; i < sizeof(g_ctxs) / sizeof(g_ctxs[0]); i++)
	{
		if (g_ctxs[i].socket == 0)
		{
			g_ctxs[i].time = clock();
			unsigned int ip = 0;
			struct sockaddr_in* local_addr = 0, * remote_addr = 0;
			int local_addr_sz, remote_addr_sz;
			GetAcceptExSockaddrs(g_ctxs[0].buf_recv, g_ctxs[0].sz_recv, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, (struct sockaddr**)&local_addr, &local_addr_sz, (struct sockaddr**)&remote_addr, &remote_addr_sz);
			if (remote_addr) ip = ntohl(remote_addr->sin_addr.s_addr);
			printf(" connection %u created, remote IP: %u.%u.%u.%u\n", i, (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, (ip) & 0xff);
			g_ctxs[i].socket = g_accepted_socket;
			// Связь сокета с портом IOCP, в качестве key используется индекс массива
			if (NULL == CreateIoCompletionPort((HANDLE)g_ctxs[i].socket, g_io_port, i, 0))
			{
				printf("CreateIoCompletionPort error: %x\n", GetLastError());
				return;
			}
			// Ожидание данных от сокета
			schedule_read(i);
			return;
		}
	}
	// Место не найдено => нет ресурсов для принятия соединения
	closesocket(g_accepted_socket);
	g_accepted_socket = 0;
}

// Функция стартует операцию приема соединения
void schedule_accept()
{
	// Создание сокета для принятия подключения (AcceptEx не создает сокетов)
	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	memset(&g_ctxs[0].overlap_recv, 0, sizeof(OVERLAPPED));
	// Принятие подключения.
	// Как только операция будет завершена - порт завершения пришлет уведомление. 
	// Размеры буферов должны быть на 16 байт больше размера адреса согласно документации разработчика ОС
	AcceptEx(g_ctxs[0].socket, g_accepted_socket, g_ctxs[0].buf_recv, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct	sockaddr_in) + 16, NULL, &g_ctxs[0].overlap_recv);
}

//Проверка на то, что строка пришла полностью, длина строки в len
int is_string_received(DWORD idx, int* len)
{
	DWORD i;
	for (i = 0; i < g_ctxs[idx].sz_recv; i++)
	{
		if (g_ctxs[idx].buf_recv[i] == '\n')
		{
			*len = (int)(i + 1);
			return 1;
		}
	}
	if (g_ctxs[idx].sz_recv == sizeof(g_ctxs[idx].buf_recv))
	{
		*len = sizeof(g_ctxs[idx].buf_recv);
		return 1;
	}
	return 1;
}

string defineOSVersion(string code)
{
	if (code == "61") return "7";
	if (code == "62") return "8";
	if (code == "63") return "8.1";
	if (code == "100") return "10.0";
}

void crypt_keys(int idx)
{
	// для создания контейнера ключей с определенным CSP
	/*phProv – указатель а дескриптор CSP.
	  pszContainer – имя контейнера ключей.
	  pszProvider – имя CSP.
	  dwProvType – тип CSP.
	  dwFlags – флаги.*/
	if (!CryptAcquireContextW(&g_ctxs[idx].DescCSP, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, NULL))
	{
		if (!CryptAcquireContextW(&g_ctxs[idx].DescCSP, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, (CRYPT_NEWKEYSET)))
			printf("ERROR, %x", GetLastError());
	}

	//Данная функция предназначена для генерации сеансового ключа, а также для\
	генерации пар ключей для обмена и цифровой подписи
	/*
	hProv– дескриптор CSP.
	Algid – идентификатор алгоритма.
	dwFlags – флаги.
	phKey – указатель на дескриптор ключа.
	*/
	if (CryptGenKey(g_ctxs[idx].DescCSP, CALG_RC4, (CRYPT_EXPORTABLE | CRYPT_ENCRYPT | CRYPT_DECRYPT), &g_ctxs[idx].DescKey) == 0)
		printf("ERROR, %x", GetLastError());

	//Сервер получает публичный ключ клиента
	//сачала достаём длину ключа
	/*
	hProv – дескриптор CSP.
	pbData – импортируемый ключ представленный в виде массива байт.
	dwDataLen –длина данных в pbData.
	hPubKey - дескриптор ключа, который расшифрует ключ содержащийся в pbData.
	dwFlags - флаги.
	phKey – указатель на дескриптор ключа. Будет указывать на импортированный ключ
	*/
	int i = 255;
	for (; i >= 0 && g_ctxs[idx].buf_recv[i] == 0;)	i--;
	unsigned int len = (unsigned char)g_ctxs[idx].buf_recv[i];
	g_ctxs[idx].buf_recv[i] = 0;
	if (!CryptImportKey(g_ctxs[idx].DescCSP, (BYTE*)g_ctxs[idx].buf_recv, len, 0, 0, &g_ctxs[idx].DescKey_open))//получаем открытый ключ
		printf("ERROR, %x", GetLastError());

	//CryptExportKey - Функция экспорта ключа для его передачи по каналам информации.\
	Возможны различные варианты передачи ключа, включая передачу публичного ключа,\
	пары ключей, а также передачу секретного или сеансового ключа.
	//Сервер шифрует сеансовый ключ публичным ключом клиента и отправляет
	//получившееся зашифрованное сообщение клиенту
	/*
	hKey – дескриптор экспортируемого ключа.
	hExpKey – ключ, с помощью которого будет зашифрован hKey при экспорте.
	dwBlobType – тип экспорта.
	dwFlags – флаги.
	pbData – буфер для экспорта. Будет содержать зашифрованный hKey с помощью
	hExpKey.
	pdwDataLen – длина буфера на вход. На выходе – количество значащих байт
	*/
	DWORD lenExp = 256;
	if (!CryptExportKey(g_ctxs[idx].DescKey, g_ctxs[idx].DescKey_open, SIMPLEBLOB, NULL, (BYTE*)g_ctxs[idx].buf_send, &lenExp))//шифруем сеансовый ключ открытым
		printf("ERROR, %x", GetLastError());
	g_ctxs[idx].buf_send[lenExp] = lenExp;
	g_ctxs[idx].sz_send_total = lenExp + 1;
}

string AceType(short t)
{
	//if (t == )
	switch (t)
	{
	case 0: return "ACCESS_ALLOWED_ACE_TYPE ";
	case 1: return "ACCESS_ALLOWED_CALLBACK_ACE_TYPE ";
	case 2: return "ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE ";
	case 3: return "ACCESS_ALLOWED_COMPOUND_ACE_TYPE ";
	case 4: return "ACCESS_ALLOWED_OBJECT_ACE_TYPE ";
	case 5: return "ACCESS_DENIED_ACE_TYPE ";
	case 6: return "ACCESS_DENIED_CALLBACK_ACE_TYPE ";
	case 7: return "ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE ";
	case 8: return "ACCESS_DENIED_OBJECT_ACE_TYPE ";
	case 9: return "ACCESS_MAX_MS_ACE_TYPE ";
	case 10: return "ACCESS_MAX_MS_V2_ACE_TYPE ";
	case 11: return "ACCESS_MAX_MS_V3_ACE_TYPE ";
	case 12: return "ACCESS_MAX_MS_V4_ACE_TYPE ";
	case 13: return "ACCESS_MAX_MS_OBJECT_ACE_TYPE ";
	case 14: return "ACCESS_MIN_MS_ACE_TYPE ";
	case 15: return "ACCESS_MIN_MS_OBJECT_ACE_TYPE ";
	case 16: return "SYSTEM_ALARM_ACE_TYPE ";
	case 17: return "SYSTEM_ALARM_CALLBACK_ACE_TYPE ";
	case 18: return "SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE ";
	case 19: return "SYSTEM_ALARM_OBJECT_ACE_TYPE ";
	case 20: return "SYSTEM_AUDIT_ACE_TYPE ";
	case 21: return "SYSTEM_AUDIT_CALLBACK_ACE_TYPE ";
	case 22: return "SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE ";
	case 23: return "SYSTEM_AUDIT_OBJECT_ACE_TYPE ";
	case 24: return "SYSTEM_MANDATORY_LABEL_ACE_TYPE ";
	default: return "Unknown type of ACE ";
	}
}

string FindRights(unsigned int Mask)
{

	if (Mask & FILE_GENERIC_READ)
		return "FILE_GENERIC_READ ] ";
	if (Mask & FILE_GENERIC_WRITE)
		return "FILE_GENERIC_WRITE ] ";
	if (Mask & FILE_GENERIC_EXECUTE)
		return "FILE_GENERIC_EXECUTE ] ";
	if (Mask & DELETE)
		return "DELETE ] ";
	if (Mask & READ_CONTROL)
		return "READ_CONTROL ] ";
	if (Mask & WRITE_DAC)
		return "WRITE_DAC ] ";
	if (Mask & WRITE_OWNER)
		return "WRITE_OWNER ] ";
	if (Mask & SYNCHRONIZE)
		return "SYNCHRONIZE ] ";


	if (Mask & KEY_ALL_ACCESS)
		return "KEY_ALL_ACCESS ] ";
	if (Mask & KEY_QUERY_VALUE)
		return "KEY_QUERY_VALUE ] ";
	if (Mask & KEY_SET_VALUE)
		return "KEY_SET_VALUE ] ";
	if (Mask & KEY_CREATE_SUB_KEY)
		return "KEY_CREATE_SUB_KEY ] ";
	if (Mask & KEY_ENUMERATE_SUB_KEYS)
		return "KEY_ENUMERATE_SUB_KEYS ] ";
	if (Mask & KEY_NOTIFY)
		return "KEY_NOTIFY ] ";
	if (Mask & KEY_CREATE_LINK)
		return "KEY_CREATE_LINK ] ";
	if (Mask & KEY_READ)
		return "KEY_READ ] ";
	if (Mask & KEY_WRITE)
		return "KEY_WRITE ] ";

	return "BRUH ";
}

HKEY SearchHKey(wchar_t* h)
{
	switch (h[5])
	{
	case L'L': return HKEY_LOCAL_MACHINE;
	case L'U': return HKEY_USERS;
	case L'C':
	{
		switch (h[13])
		{
		case L'R':return HKEY_CLASSES_ROOT;
		case L'C':return HKEY_CURRENT_CONFIG;
		case L'U':return HKEY_CURRENT_USER;
		default: return 0;
		}
	}
	default: return 0;
	}
}

LPCWSTR SearchName(wchar_t* p)
{
	int i = 0;
	while (p[i] != L'\\')
		i++;
	i++;
	return &p[i];
}

void menu(DWORD idx)
{
	DWORD count = 0;

	if (g_ctxs[idx].DescCSP != 0 && g_ctxs[idx].DescKey != 0 && g_ctxs[idx].DescKey_open != 0)
	{
		count = g_ctxs[idx].sz_recv;
		if (!CryptDecrypt(g_ctxs[idx].DescKey, NULL, TRUE, NULL, (BYTE*)g_ctxs[idx].buf_recv, (DWORD*)&count))
			printf("ERROR, %x", GetLastError());
	}

	//cout << "Choice: " << g_ctxs[idx].buf_recv[0] << endl;
	switch (g_ctxs[idx].buf_recv[0])
	{
	case 'o':
	{
		//объект структуры RTL_OSVERSIONINFOEXW, содержащей сведения об операционной системе, в том числе ее версию
		RTL_OSVERSIONINFOEXW* pk_OsVer = new RTL_OSVERSIONINFOEXW;
		typedef LONG(WINAPI* tRtlGetVersion)(RTL_OSVERSIONINFOEXW*);

		//этот объект структуры обнуляется, а поле размера инициализируется
		memset(pk_OsVer, 0, sizeof(RTL_OSVERSIONINFOEXW));
		pk_OsVer->dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);

		//получаем хэндл на системный файл ntdll.dll
		HMODULE h_NtDll = GetModuleHandleW(L"ntdll.dll");
		//для получения заполненной корректными данными структуры RTL_OSVERSIONINFOEXW мы вызываем функцию GetProcAddress
		//которой передаются хэндл файла и имя функции, которую нужно вызвать из системного файла для получения результата
		tRtlGetVersion f_RtlGetVersion = (tRtlGetVersion)GetProcAddress(h_NtDll, "RtlGetVersion");

		//если объект структуры получен, и он не равен 0, 
		//тогда получаем из этого объекта 2 номера, составляющих версию операционки
		if (!f_RtlGetVersion)
			return; // This will never happen (all processes load ntdll.dll)

		LONG Status = f_RtlGetVersion(pk_OsVer);

		string result = "";

		if (Status == 0)
			result = to_string(pk_OsVer->dwMajorVersion)
			+ to_string(pk_OsVer->dwMinorVersion);
		result = defineOSVersion(result);

		delete pk_OsVer;

		strcpy(g_ctxs[idx].buf_send, result.c_str());
		break;
	}
	case 't':
	{
		SYSTEMTIME sm;
		GetSystemTime(&sm);

		string resultTime = "";

		if (sm.wDay < 10) resultTime += "0";
		resultTime += to_string(sm.wDay) + ".";
		if (sm.wMonth < 10) resultTime += "0";
		resultTime += to_string(sm.wMonth) + ".";
		resultTime += to_string(sm.wYear) + " ";
		sm.wHour += 3;
		sm.wHour %= 24;
		if (sm.wHour < 10) resultTime += "0";
		resultTime += to_string(sm.wHour) + ":";
		if (sm.wMinute < 10) resultTime += "0";
		resultTime += to_string(sm.wMinute) + ":";
		if (sm.wSecond < 10) resultTime += "0";
		resultTime += to_string(sm.wSecond);

		strcpy(g_ctxs[idx].buf_send, resultTime.c_str());
		break;
	}
	case 'm':
	{
		int time = GetTickCount64();
		memcpy(g_ctxs[idx].buf_send, &time, sizeof(int));
		g_ctxs[idx].buf_send[sizeof(int)] = '\0';
		break;
	}
	case 's':
	{
		MEMORYSTATUS stat;
		GlobalMemoryStatus(&stat);

		string result = "{\n";
		result += "  \"memoryLoad\" : " + to_string(stat.dwMemoryLoad)
			+ ",\n  \"totalPhysMem\" : " + to_string(stat.dwTotalPhys)
			+ ",\n  \"availPhysMem\" : " + to_string(stat.dwAvailPhys)
			+ ",\n  \"totalMemForProgramm\" : " + to_string(stat.dwTotalPageFile)
			+ ",\n  \"availMemForProgramm\" : " + to_string(stat.dwAvailPageFile)
			+ ",\n  \"totalVirtualMem\" : " + to_string(stat.dwTotalVirtual)
			+ ",\n  \"availVirtualMem\" : " + to_string(stat.dwAvailVirtual)
			+ "\n}\n";

		strcpy(g_ctxs[idx].buf_send, result.c_str());
		break;
	}
	case 'f':
	{
		char disks[26][3] = { 0 };
		DWORD dr = GetLogicalDrives();
		string result = "";
		for (int i = 0, count = 0; i < 26; i++)
		{
			int n = ((dr >> i) & 0x00000001);
			if (n == 1)
			{
				disks[count][0] = char(65 + i);
				disks[count][1] = ':';
				result += "{\n  \"diskName\" : \"";
				result.push_back(disks[count][0]);
				result += ":\",\n  \"type\" : ";
				switch (GetDriveTypeA(disks[count]))
				{
				case DRIVE_UNKNOWN:
					result += "\"unknown\",\n";
					break;
				case DRIVE_NO_ROOT_DIR:
					result += "\"root path is invalid\",\n";
					break;
				case DRIVE_REMOVABLE:
					result += "\"removable\",\n";
					break;
				case DRIVE_FIXED:
					result += "\"fixed\",\n";
					break;
				case DRIVE_REMOTE:
					result += "\"network\",\n";
					break;
				case DRIVE_CDROM:
					result += "\"CD-ROM\",\n";
					break;
				case DRIVE_RAMDISK:
					result += "\"RAM\",\n";
					break;
				default:
					break;
				}

				WCHAR volumeName[MAX_PATH + 1] = { 0 };
				char fileSystemName[MAX_PATH + 1] = { 0 };
				DWORD serialNumber = 0;
				DWORD maxComponentLen = 0;
				DWORD fileSystemFlags = 0;

				result += "  \"fileSystem\" : \"";

				string diskName = string(disks[count]) + "\\";//omg
				if (GetVolumeInformationA((LPCSTR)(diskName.c_str()), (LPSTR)volumeName, sizeof(volumeName),
					&serialNumber, &maxComponentLen, &fileSystemFlags, (LPSTR)fileSystemName, sizeof(fileSystemName)))
				{
					//result += string(fileSystemName) + "\"\n}\n";
					result += string(fileSystemName) + "\"";
				}
				//else result += "Undefined\"\n}\n";
				else result += "Undefined\"";

				//if (GetDriveTypeA(disks[count]) == DRIVE_FIXED)
				//{
				unsigned long long s, b, f, c;
				GetDiskFreeSpaceA(disks[count], (LPDWORD)&s, (LPDWORD)&b, (LPDWORD)&f, (LPDWORD)&c);
				unsigned long long freeSpace = (f * s * b) / 1024 / 1024 / 1024;
				result += ",\n  \"freeSpace\" : " + to_string(freeSpace) + "\n}\n";
				//}
				//else result += "\n}\n";

				count++;
			}
		}
		strcpy(g_ctxs[idx].buf_send, result.c_str());
		break;
	}
	case 'p':
	{
		string result = "";
		wchar_t filePath[500] = { 0 };
		string strPath = string(g_ctxs[idx].buf_recv);
		strPath = strPath.substr(2);
		mbstowcs(filePath, strPath.c_str(), strPath.size());

		PACL a;
		PSECURITY_DESCRIPTOR pSD;
		if (filePath[1] == L':')//file
		{
			if (GetNamedSecurityInfo((LPCWSTR)filePath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &a, NULL, &pSD) != ERROR_SUCCESS)
			{
				result = "Path entered incorrectly";
				sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], result.c_str());
				break;
			}
		}
		else//key
		{
			HKEY desc;
			HKEY type = SearchHKey(filePath);
			LPCWSTR kname = SearchName(filePath);
			//open the key
			if (RegOpenKey(type, kname, &desc) != ERROR_SUCCESS)
			{
				result = "Path entered incorrectly";
				sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], result.c_str());
				break;
			}
			//get info about key
			if (GetSecurityInfo(desc, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &a, NULL, &pSD) != ERROR_SUCCESS)
			{
				result = "Path entered incorrectly";
				sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], result.c_str());
				break;
			}
		}

		if (a == NULL)//dacl
		{
			result = "Security descriptor has no DACL";
			sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], result.c_str());
			break;
		}

		//Пользуемся функцией GetAclInformation(), достаём список
		ACL_REVISION_INFORMATION* buf = (ACL_REVISION_INFORMATION*)malloc(sizeof(ACL_REVISION_INFORMATION));
		GetAclInformation(a, buf, sizeof(ACL_REVISION_INFORMATION), AclRevisionInformation);

		//потом GetAce()
		LPVOID AceInfo;
		for (int i = 0; i < a->AceCount; i++)//cycle for acl list, acecount - amount of ace`s entries
		{
			//get the ace entry
			GetAce(a, i, &AceInfo);
			ACCESS_ALLOWED_ACE* pACE = (ACCESS_ALLOWED_ACE*)AceInfo;
			//get the sid
			PSID pSID;
			pSID = (PSID)(&(pACE->SidStart));

			char name[1024] = "", Domain[1024] = "";
			DWORD LenName = 1024, LenDom = 1024;
			SID_NAME_USE Type;
			LPSTR sid_str;

			if (LookupAccountSidA(NULL, pSID, name, &LenName, Domain, &LenDom, &Type) != 0)
			{
				ConvertSidToStringSidA((PSID)(&(pACE->SidStart)), &sid_str);
				string sidname = sid_str;
				string allowed_denied;
				AceType(pACE->Header.AceType);
				//allowed_denied = 


				result += "\n{";
				//result += "\n  \"SID\" : " + to_string(pACE->SidStart);
				result += "\n  \"SID\" : " + sidname;
				result += ",\n  \"name\" : \"" + string(name);
				result += "\",\n  \"ACEType\" : \"" + AceType(pACE->Header.AceType);
				result += "\",\n  \"rights\" : [ " + FindRights(pACE->Mask);
				result.pop_back();
				result += "\n}\n";
			}
		}
		//cout << result;
		sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], result.c_str());
		free(buf);
		break;
	}
	case 'r':
	{
		string result = "";
		wchar_t filePath[500] = { 0 };
		string strPath = string(g_ctxs[idx].buf_recv);
		strPath = strPath.substr(2);
		mbstowcs(filePath, strPath.c_str(), strPath.size());

		PSID pOwnerSid;
		PSECURITY_DESCRIPTOR pSD;
		if (filePath[1] == L':')//file
		{
			if (GetNamedSecurityInfo((LPCWSTR)filePath, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &pOwnerSid, NULL, NULL, NULL, &pSD) != ERROR_SUCCESS)
			{
				result = "Path entered incorrectly";
				sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], result.c_str());
				break;
			}
		}
		else//key
		{
			HKEY desc;
			HKEY type = SearchHKey(filePath);
			LPCWSTR kname = SearchName(filePath);
			//open the key
			if (RegOpenKey(type, kname, &desc) != ERROR_SUCCESS)
			{
				result = "Path entered incorrectly";
				sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], result.c_str());
				break;
			}
			//get info about key
			if (GetSecurityInfo(desc, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION, &pOwnerSid, NULL, NULL, NULL, &pSD) != ERROR_SUCCESS)
			{
				result = "Path entered incorrectly";
				sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], result.c_str());
				break;
			}
		}

		if (pOwnerSid == NULL)
		{
			result = "Security descriptor has no owner SID";
			sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], result.c_str());
			break;
		}

		char name[500] = "", Domain[500] = "";
		DWORD LenName = 500, LenDom = 500;
		SID_NAME_USE SidName;
		DWORD SID;
		memcpy(&SID, pOwnerSid, sizeof(PSID));

		LookupAccountSidA(NULL, pOwnerSid, name, &LenName, Domain, &LenDom, &SidName);

		result = "{\n  \"SID\" : " + to_string(SID);
		result += ",\n  \"ownerName\" : \"" + string(name) + "\"\n}\n";
		sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], result.c_str());
		break;
	}
	case 'e':
	{
		g_ctxs[idx].DescCSP = 0;
		g_ctxs[idx].DescKey = 0;
		g_ctxs[idx].DescKey_open = 0;
		memset(g_ctxs[idx].buf_send, 0, 2048);
		CancelIo((HANDLE)g_ctxs[idx].socket);
		PostQueuedCompletionStatus(g_io_port, 0, idx, &g_ctxs[idx].overlap_cancel);
		return;
	}
	default:
	{
		crypt_keys(idx);
		return;
	}
	}

	count = strlen(g_ctxs[idx].buf_send);
	if (!CryptEncrypt(g_ctxs[idx].DescKey, NULL, TRUE, NULL, (BYTE*)g_ctxs[idx].buf_send, (DWORD*)&count, 2048))
		printf("ERROR, %x", GetLastError());
	g_ctxs[idx].sz_send_total = count;
}

void io_serv()
{
	//инициализация интерфейса сокетов
	//аргументы: версия интрфейса, структура для записи сведений
	//о конкретной реализации интерфейса Windows Sockets
	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0)
	{
		printf("WSAStartup ok\n");
	}
	else
	{
		printf("WSAStartup error\n");
	}

	struct sockaddr_in addr;

	// Создание сокета прослушивания
	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	// Создание порта завершения
	//INVALID_HANDLE_VALUE означает то, что нам нужен новый порт
	g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (NULL == g_io_port)
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}

	// Обнуление структуры данных для хранения входящих соединений
	memset(g_ctxs, 0, sizeof(g_ctxs));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;		//iPv4
	addr.sin_port = htons(9000);
	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0 || listen(s, 1) < 0)
	{
		printf("error bind() or listen()\n");
		return;
	}
	printf("Listening: %hu\n", ntohs(addr.sin_port));

	// Присоединение существующего сокета s к порту io_port.
	// В качестве ключа для прослушивающего сокета используется 0
	if (NULL == CreateIoCompletionPort((HANDLE)s, g_io_port, 0, 0))
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}
	g_ctxs[0].socket = s;

	// Старт операции принятия подключения.
	schedule_accept();
	// Бесконечный цикл принятия событий о завершенных операциях
	int flag = 0;
	while (1)
	{
		DWORD transferred;		//указатель на переменнную, в которую запишется количество переданных байт в результате завершения операции (фактически это возвращаемое значение recv() и send() в синхронном режиме)
		ULONG_PTR key;			//
		OVERLAPPED* lp_overlap;	//указатель на OVERLAPPED, ассоциированную с этой IO-транзакцией
		// Ожидание событий в течение 1 секунды
		BOOL b = GetQueuedCompletionStatus(g_io_port, &transferred, &key, &lp_overlap, 1000);
		if (b)
		{
			// Поступило уведомление о завершении операции
			if (key == 0) // ключ 0 - для прослушивающего сокета
			{
				g_ctxs[0].sz_recv += transferred;
				// Принятие подключения и начало принятия следующего
				add_accepted_connection();
				schedule_accept();
			}
			else
			{
				// Иначе поступило событие по завершению операции от клиента. // Ключ key - индекс в массиве g_ctxs
				if (&g_ctxs[key].overlap_recv == lp_overlap)
				{
					int len;
					// Данные приняты:
					if (transferred == 0)
					{
						// Соединение разорвано
						CancelIo((HANDLE)g_ctxs[key].socket);
						//Функция помещает в очередь порта сообщение
						PostQueuedCompletionStatus(g_io_port, 0, key, &g_ctxs[key].overlap_cancel);
						continue;
					}
					g_ctxs[key].sz_recv += transferred;
					if (is_string_received(key, &len))
					{
						// Если строка полностью пришла, то сформировать ответ и начать его отправлять
						menu(key);
						g_ctxs[key].time = clock();
						g_ctxs[key].sz_send = 0;
						memset(g_ctxs[key].buf_recv, 0, 512);
						schedule_write(key);
					}
					else
					{
						// Иначе - ждем данные дальше
						schedule_read(key);
					}
				}
				else if (&g_ctxs[key].overlap_send == lp_overlap)
				{
					// Данные отправлены
					g_ctxs[key].sz_send += transferred;
					if (g_ctxs[key].sz_send < g_ctxs[key].sz_send_total && transferred > 0)
					{
						// Если данные отправлены не полностью - продолжить отправлять
						schedule_write(key);
					}
					else
					{
						// Данные отправлены полностью, прервать все коммуникации,
						// добавить в порт событие на завершение работы
						g_ctxs[key].sz_recv = 0;
						memset(g_ctxs[key].buf_send, 0, 2048);
						schedule_read(key);
					}
				}
				else if (&g_ctxs[key].overlap_cancel == lp_overlap)
				{
					// Все коммуникации завершены, сокет может быть закрыт
					closesocket(g_ctxs[key].socket);
					memset(&g_ctxs[key], 0, sizeof(g_ctxs[key]));
					printf("Connection closed\n", key);
				}
			}
		}
		else
		{
			// Если не произошло никаких событий, сервер ищет клиентов
			// от которых не было действий более WAIT_SECONDS секунд
			for (int counter = 1; counter < MAX_CLIENTS; counter++)
			{
				if (g_ctxs[counter].socket != 0 && (clock() - g_ctxs[counter].time) / CLOCKS_PER_SEC >= CLIENT_TIME)
				{
					CancelIo((HANDLE)g_ctxs[counter].socket);
					PostQueuedCompletionStatus(g_io_port, 0, counter, &g_ctxs[counter].overlap_cancel);
				}
			}
		}
	}
}

int main()
{
	setlocale(LC_ALL, "Russian");
	io_serv();
	return 0;
}
