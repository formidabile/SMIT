#define _CRT_SECURE_NO_WARNINGS
#define UNICODE
#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include <wincred.h>
#include <strsafe.h>
#include <iomanip>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")
#define _WIN32_DCOM

int __cdecl main() {
	setlocale(LC_ALL, "Russian");
	HRESULT hres;
	// Шаг1: --------------------------------------------------
	// Инициализация COM. ------------------------------------------
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		std::cout << "Failed to initialize COM library. Error code = 0x" << std::hex << hres << std::endl;
		return 1;
	}

	// Шаг2: --------------------------------------------------
	// Установка уровней безопасности COM--------------------------
	hres = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IDENTIFY,
		NULL,
		EOAC_NONE,
		NULL
	);
	if (FAILED(hres)) {
		std::cout << "Failed to initialize security. Error code = 0x" << std::hex << hres << std::endl;
		CoUninitialize();
		return 1;
	}

	// Шаг3: ---------------------------------------------------
	// Создание локатора WMI -------------------------
	IWbemLocator* pLoc = NULL;
	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)&pLoc);
	if (FAILED(hres)) {
		std::cout << "Failed to create IWbemLocator object." << " Err code = 0x" << std::hex << hres << std::endl;
		CoUninitialize();
		return 1;
	}

	// Шаг4: -----------------------------------------------------
	// Подключение к WMI через IWbemLocator::ConnectServer
	IWbemServices* pSvc = NULL;
	// Получение реквизитов доступа к удаленному компьютеру
	CREDUI_INFO cui;
	bool useToken = false;
	bool useNTLM = true;
	wchar_t pszName[CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };
	wchar_t pszPwd[CREDUI_MAX_PASSWORD_LENGTH + 1] = { 0 };
	wchar_t pszDomain[CREDUI_MAX_USERNAME_LENGTH + 1];
	wchar_t pszUserName[CREDUI_MAX_USERNAME_LENGTH + 1];
	wchar_t pszAuthority[CREDUI_MAX_USERNAME_LENGTH + 1];
	BOOL fSave;
	DWORD dwErr;

	memset(&cui, 0, sizeof(CREDUI_INFO));
	cui.cbSize = sizeof(CREDUI_INFO);
	cui.hwndParent = NULL;
	cui.pszMessageText = TEXT("Press cancel to use process token");
	cui.pszCaptionText = TEXT("Enter Account Information");
	cui.hbmBanner = NULL;
	fSave = FALSE;
	dwErr = CredUIPromptForCredentialsW(
		(PCREDUI_INFOW)&cui,
		(PCWSTR)TEXT(""),
		NULL,
		0,
		pszName,
		CREDUI_MAX_USERNAME_LENGTH + 1,
		pszPwd,
		CREDUI_MAX_PASSWORD_LENGTH + 1,
		&fSave,
		CREDUI_FLAGS_GENERIC_CREDENTIALS |
		CREDUI_FLAGS_ALWAYS_SHOW_UI |
		CREDUI_FLAGS_DO_NOT_PERSIST);
	if (dwErr == ERROR_CANCELLED) useToken = true;
	else if (dwErr) {
		std::cout << "Did not get credentials " << dwErr << std::endl;
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	// change the computerName strings below to the full computer name
	// of the remote computer
	if (!useNTLM) StringCchPrintfW(pszAuthority, CREDUI_MAX_USERNAME_LENGTH + 1, L"kERBEROS:%s", L"DESKTOP-1QC168N");
	// Подключение к пространству имен root\cimv2
	//---------------------------------------------------------
	COAUTHIDENTITY* userAcct = NULL;
	COAUTHIDENTITY authIdent;

	hres = pLoc->ConnectServer(
		_bstr_t(L"\\\\DESKTOP-1QC168N\\root\\cimv2"),
		_bstr_t(useToken ? NULL : pszName),
		_bstr_t(useToken ? NULL : pszPwd),
		NULL,
		NULL,
		_bstr_t(useNTLM ? NULL : pszAuthority),
		NULL,
		&pSvc);
	if (FAILED(hres)) {
		std::cout << "Could not connect. Error code = 0x" << std::hex << hres << std::endl;
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	std::cout << "Connected to ROOT\\CIMV2 WMI namespace" << std::endl;

	// Шаг5: --------------------------------------------------
	// Создание структуры COAUTHIDENTITY 
	if (!useToken) {
		memset(&authIdent, 0, sizeof(COAUTHIDENTITY));
		authIdent.PasswordLength = wcslen(pszPwd);
		authIdent.Password = (USHORT*)pszPwd;
		LPWSTR slash = wcschr(pszName, L'\\');
		if (slash == NULL) {
			std::cout << "Could not create Auth identity. No domain specified\n";
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			return 1;
		}

		StringCchCopyW(pszUserName, CREDUI_MAX_USERNAME_LENGTH + 1, slash + 1);
		authIdent.User = (USHORT*)pszUserName;
		authIdent.UserLength = wcslen(pszUserName);

		StringCchCopyNW(pszDomain, CREDUI_MAX_USERNAME_LENGTH + 1, pszName, slash - pszName);
		authIdent.Domain = (USHORT*)pszDomain;
		authIdent.DomainLength = slash - pszName;
		authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
		userAcct = &authIdent;
	}

	// Шаг6: --------------------------------------------------
	// Установка защиты прокси сервера------------------

	hres = CoSetProxyBlanket(
		pSvc,								// Indicates the proxy to set
		RPC_C_AUTHN_DEFAULT,				// RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_DEFAULT,				// RPC_C_AUTHZ_xxx
		COLE_DEFAULT_PRINCIPAL,				// Server principal name
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,		// RPC_C_AUTHN_LEVEL_xxx
		RPC_C_IMP_LEVEL_IMPERSONATE,		// RPC_C_IMP_LEVEL_xxx
		userAcct,							// client identity
		EOAC_NONE);
	if (FAILED(hres)) {
		std::cout << "Could not set proxy blanket. Error code = 0x" << std::hex << hres << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}

	IWbemClassObject* pclsObj = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	ULONG uReturn = 0;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("Select * from Win32_OperatingSystem"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres)) {
		std::cout << "Query for operating system name failed." << " Error code = 0x" << std::hex << hres << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	hres = CoSetProxyBlanket(
		pEnumerator,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE);
	if (FAILED(hres)) {
		std::cout << "Could not set proxy blanket on enumenator. Error code = 0x" << std::hex << hres << std::endl; // Без on enumenator?
		pEnumerator->Release();
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}

	std::cout << "System Information:" << std::endl;

	while (pEnumerator) {
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn) break;
		VARIANT vtProp;
		pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
		*(vtProp.bstrVal + 32) = '\0';
		std::wcout << "Name: " << vtProp.bstrVal << std::endl;

		pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);
		std::wcout << "Organization: " << vtProp.bstrVal << std::endl;

		pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
		std::wcout << "SerialNumber: " << vtProp.bstrVal << std::endl;

		pclsObj->Get(L"SystemDirectory", 0, &vtProp, 0, 0);
		std::wcout << "SystemDirectory: " << vtProp.bstrVal << std::endl;

		pclsObj->Get(L"Version", 0, &vtProp, 0, 0);
		std::wcout << "Version: " << vtProp.bstrVal << std::endl;

		pclsObj->Get(L"BuildNumber", 0, &vtProp, 0, 0);
		std::wcout << "BuildNumber: " << vtProp.bstrVal << std::endl;

		pclsObj->Get(L"RegisteredUser", 0, &vtProp, 0, 0);
		std::wcout << "RegisteredUser: " << vtProp.bstrVal << std::endl;

		pclsObj->Release();
		pclsObj = NULL;
	}

	pEnumerator = NULL;
	pclsObj = NULL;
	uReturn = 0;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("Select * from Win32_Product"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres)) {
		std::cout << "Query for operating system name failed." << " Error code = 0x" << std::hex << hres << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	hres = CoSetProxyBlanket(
		pEnumerator,                    // Indicates the proxy to set
		RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
		COLE_DEFAULT_PRINCIPAL,         // Server principal name 
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
		userAcct,                       // client identity
		EOAC_NONE                       // proxy capabilities 
	);

	if (FAILED(hres)) {
		std::cout << "Could not set proxy blanket on enumerator. Error code = 0x" << std::hex << hres << std::endl;
		pEnumerator->Release();
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}

	std::cout << "\nApplications:" << std::endl;
	while (pEnumerator) {
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

		if (0 == uReturn) break;
		VARIANT vtProp;

		hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
		std::wcout << vtProp.bstrVal << std::endl;

		VariantClear(&vtProp);

		pclsObj->Release();
		pclsObj = NULL;
	}

	pEnumerator = NULL;
	pclsObj = NULL;
	uReturn = 0;
	if (!useNTLM) StringCchPrintfW(pszAuthority, CREDUI_MAX_USERNAME_LENGTH + 1, L"kERBEROS:%s", L"DESKTOP-1QC168N");
	hres = pLoc->ConnectServer(
		_bstr_t(L"\\\\DESKTOP-1QC168N\\root\\SecurityCenter2"),
		_bstr_t(useToken ? NULL : pszName),
		_bstr_t(useToken ? NULL : pszPwd),
		NULL,
		NULL,
		_bstr_t(useNTLM ? NULL : pszAuthority),
		NULL,
		&pSvc
	);

	if (FAILED(hres)) {
		std::cout << "Could not connect. Error code = 0x" << std::hex << hres << std::endl;
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	std::cout << "\n\nConnected to ROOT\\SecurityCenter2 WMI namespace" << std::endl;

	userAcct = NULL;

	if (!useToken) {
		memset(&authIdent, 0, sizeof(COAUTHIDENTITY));
		authIdent.PasswordLength = wcslen(pszPwd);
		authIdent.Password = (USHORT*)pszPwd;
		LPWSTR slash = wcschr(pszName, L'\\');
		if (slash == NULL) {
			std::cout << "Could not create Auth identity. No domain specified\n";
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			return 1;
		}
		StringCchCopyW(pszUserName, CREDUI_MAX_USERNAME_LENGTH + 1, slash + 1);
		authIdent.User = (USHORT*)pszUserName;
		authIdent.UserLength = wcslen(pszUserName);
		StringCchCopyNW(pszDomain, CREDUI_MAX_USERNAME_LENGTH + 1, pszName, slash - pszName);
		authIdent.Domain = (USHORT*)pszDomain;
		authIdent.DomainLength = slash - pszName;
		authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
		userAcct = &authIdent;
	}
	hres = CoSetProxyBlanket(
		pSvc,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE
	);
	if (FAILED(hres))
	{
		std::cout << "Could not set proxy blanket. Error code = 0x"
			<< std::hex << hres << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	pEnumerator = NULL;
	pclsObj = NULL;
	uReturn = 0;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("Select * from AntiSpywareProduct"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);
	if (FAILED(hres)) {
		std::cout << "Query for AntiSpywareProduct failed." << " Error code = 0x" << std::hex << hres << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	hres = CoSetProxyBlanket(
		pEnumerator,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE
	);
	if (FAILED(hres)) {
		std::cout << "Could not set proxy blanket on enumerator. Error code = 0x" << std::hex << hres << std::endl;
		pEnumerator->Release();
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}

	std::cout << "\nAntiSpyware Programs:" << std::endl;
	bool key = false;
	while (pEnumerator) {
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn) {
			if (key == false) std::cout << "Not install" << std::endl;
			break;
		}
		key = true;
		VARIANT vtProp;
		hr = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);
		std::wcout << "Name: " << vtProp.bstrVal << std::endl;
		hr = pclsObj->Get(L"instanceGuid", 0, &vtProp, 0, 0);
		std::wcout << "GUID: " << vtProp.bstrVal << std::endl;
		hr = pclsObj->Get(L"pathToSignedProductExe", 0, &vtProp, 0, 0);
		std::wcout << "File path: " << vtProp.bstrVal << std::endl << std::endl;
		VariantClear(&vtProp);
		pclsObj->Release();
		pclsObj = NULL;
	}

	pEnumerator = NULL;
	pclsObj = NULL;
	uReturn = 0;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("Select * from AntiVirusProduct"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);
	if (FAILED(hres)) {
		std::cout << "Query for AntiVirusProduct failed." << " Error code = 0x" << std::hex << hres << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	hres = CoSetProxyBlanket(
		pEnumerator,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE
	);
	if (FAILED(hres)) {
		std::cout << "Could not set proxy blanket on enumerator. Error code = 0x" << std::hex << hres << std::endl;
		pEnumerator->Release();
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	std::cout << "\nAntiVirus Programs:" << std::endl;
	key = false;
	while (pEnumerator) {
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn) {
			if (key == false) std::cout << "Not install" << std::endl;
			break;
		}
		key = true;
		VARIANT vtProp;
		hr = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);
		std::wcout << "Name: " << vtProp.bstrVal << std::endl;
		hr = pclsObj->Get(L"instanceGuid", 0, &vtProp, 0, 0);
		std::wcout << "GUID: " << vtProp.bstrVal << std::endl;
		hr = pclsObj->Get(L"pathToSignedProductExe", 0, &vtProp, 0, 0);
		std::wcout << "File path: " << vtProp.bstrVal << std::endl << std::endl;
		VariantClear(&vtProp);
		pclsObj->Release();
		pclsObj = NULL;
	}

	pEnumerator = NULL;
	pclsObj = NULL;
	uReturn = 0;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("Select * from FirewallProduct"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);
	if (FAILED(hres)) {
		std::cout << "Query for FirewallProduct failed." << " Error code = 0x" << std::hex << hres << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	hres = CoSetProxyBlanket(
		pEnumerator,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE
	);
	if (FAILED(hres)) {
		std::cout << "Could not set proxy blanket on enumerator. Error code = 0x" << std::hex << hres << std::endl;
		pEnumerator->Release();
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	std::cout << "\nFirewalls:" << std::endl;
	key = false;
	while (pEnumerator) {
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn) {
			if (key == false) std::cout << "Not install" << std::endl;
			break;
		}
		key = true;
		VARIANT vtProp;
		hr = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);
		std::wcout << "Name: " << vtProp.bstrVal << std::endl;
		hr = pclsObj->Get(L"instanceGuid", 0, &vtProp, 0, 0);
		std::wcout << "GUID: " << vtProp.bstrVal << std::endl;
		hr = pclsObj->Get(L"pathToSignedProductExe", 0, &vtProp, 0, 0);
		std::wcout << "File path: " << vtProp.bstrVal << std::endl << std::endl;
		VariantClear(&vtProp);
		pclsObj->Release();
		pclsObj = NULL;
	}

	SecureZeroMemory(pszName, sizeof(pszName));
	SecureZeroMemory(pszPwd, sizeof(pszPwd));
	SecureZeroMemory(pszUserName, sizeof(pszUserName));
	SecureZeroMemory(pszDomain, sizeof(pszDomain));
	pSvc->Release();
	pEnumerator->Release();
	if (pclsObj) pclsObj->Release();
	CoUninitialize();

	system("pause");
	return 0;
}
