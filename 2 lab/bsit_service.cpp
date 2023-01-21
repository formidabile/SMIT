#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <stdlib.h>
#include <fstream>
#include <string>
#include <zip.h>
#include <filesystem>
#include <iostream>
#include <conio.h>

#define servicePath (L"D:\\programming\\bsit_service\\bsit_service\\Debug\\bsit_service.exe")
#define serviceName (L"BSITService")

LPWSTR serviceNameENTRY = (LPWSTR)"BSITService";

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE hStatus;

zip_t* back_up_archive;

int addLogMessage(const char* str) {
	errno_t err;
	FILE* log;
	if ((err = fopen_s(&log, "D:\\programming\\bsit_service\\bsit_service\\log.txt", "a+")) != 0)
	{
		return -1;
	}
	fprintf(log, "%s\n", str);
	fclose(log);
	return 0;
}

int wildcmp(const char* wild, const char* string) {
	const char* cp = NULL, * mp = NULL;

	while ((*string) && (*wild != '*')) {
		if ((*wild != *string) && (*wild != '?')) {
			return 0;
		}
		wild++;
		string++;
	}

	while (*string) {
		if (*wild == '*') {
			if (!*++wild) {
				return 1;
			}
			mp = wild;
			cp = string + 1;
		}
		else if ((*wild == *string) || (*wild == '?')) {
			wild++;
			string++;
		}
		else {
			wild = mp;
			string = cp++;
		}
	}

	while (*wild == '*') {
		wild++;
	}
	return !*wild;
}

void BackUp()
{
	std::string buffer;
	std::vector<std::string> files;
	std::vector<std::string> masks;
	std::vector<std::string> files_for_backup;
	std::string source;//получаем из конфига
	std::string destination;
	int zip_error;

	std::ifstream file_in("D:\\programming\\bsit_service\\bsit_service\\config.txt"); // окрываем файл для чтения

	if (file_in.is_open())
	{
		getline(file_in, source);
		getline(file_in, destination);;
		while (getline(file_in, buffer))
			masks.push_back(buffer);
	}
	else
	{
		exit(-1);
	}
	file_in.close();

	back_up_archive = zip_open(destination.c_str(), ZIP_CREATE | ZIP_TRUNCATE, &zip_error);

	for (const auto& p : std::filesystem::recursive_directory_iterator(source)) {
		if (!std::filesystem::is_directory(p)) {
			files.push_back(p.path().string());;
		}
	}

	for (int i = 0; i < masks.size(); i++)
	{
		for (int j = 0; j < files.size();)
		{
			if (wildcmp(masks[i].c_str(), files[j].c_str()))
			{
				files_for_backup.push_back(files[j]);
				files.erase(files.begin() + j);
			}
			else if (files[j].find(masks[i].c_str()) != -1)
			{
				files_for_backup.push_back(files[j]);
				files.erase(files.begin() + j);
			}
			else {
				j++;
			}
		}
	}
	files.clear();
	for (int i = 0; i < files_for_backup.size(); i++)
	{
		files.push_back(files_for_backup[i].substr(source.size() + 1));
	}
	for (int i = 0; i < files_for_backup.size(); i++)
	{
		zip_source_t* source = zip_source_file(back_up_archive, files_for_backup[i].c_str(), 0, 0);
		if (source == nullptr) {
			throw std::runtime_error("Failed to add file to zip: " + std::string(zip_strerror(back_up_archive)));
		}
		else
			zip_file_add(back_up_archive, files[i].c_str(), source, ZIP_FL_ENC_UTF_8);

	}
	zip_close(back_up_archive);
	return;
}

void ControlHandler(DWORD request) {
	switch (request)
	{
	case SERVICE_CONTROL_STOP:
		addLogMessage("Stopped.");
		serviceStatus.dwWin32ExitCode = 0;
		serviceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(hStatus, &serviceStatus);
		zip_unchange_all(back_up_archive);
		zip_close(back_up_archive);
		return;
	case SERVICE_CONTROL_SHUTDOWN:
		addLogMessage("Shutdown.");
		serviceStatus.dwWin32ExitCode = 0;
		serviceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(hStatus, &serviceStatus);
		return;
	default:
		break;
	}
	SetServiceStatus(hStatus, &serviceStatus);
	return;
}

void ServiceMain(int argc, char** argv) {
	int i = 0;
	hStatus = RegisterServiceCtrlHandler(serviceName, (LPHANDLER_FUNCTION)ControlHandler);
	if (!hStatus)
	{
		addLogMessage("Error: Registering ServiceControl");
		return;
	}
	serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	serviceStatus.dwCurrentState = SERVICE_START_PENDING;
	serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	serviceStatus.dwWin32ExitCode = 0;
	serviceStatus.dwServiceSpecificExitCode = 0;
	serviceStatus.dwCheckPoint = 0;
	serviceStatus.dwWaitHint = 0;
	serviceStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(hStatus, &serviceStatus);
	while (serviceStatus.dwCurrentState == SERVICE_RUNNING)
	{
		BackUp();
		Sleep(1000);
	}
	addLogMessage("Success!");
	return;
}

int InstallService() {
	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hSCManager) {
		addLogMessage("Error: Can't open Service Control Manager");
		return -1;
	}
	SC_HANDLE hService = CreateService(hSCManager, serviceName, serviceName, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
		SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, servicePath, NULL, NULL, NULL, NULL, NULL);
	if (!hService) {
		int err = GetLastError();
		switch (err) {
		case ERROR_ACCESS_DENIED:
			addLogMessage("Error: ERROR_ACCESS_DENIED");
			break;
		case ERROR_CIRCULAR_DEPENDENCY:
			addLogMessage("Error: ERROR_CIRCULAR_DEPENDENCY");
			break;
		case ERROR_DUPLICATE_SERVICE_NAME:
			addLogMessage("Error: ERROR_DUPLICATE_SERVICE_NAME");
			break;
		case ERROR_INVALID_HANDLE:
			addLogMessage("Error: ERROR_INVALID_HANDLE");
			break;
		case ERROR_INVALID_NAME:
			addLogMessage("Error: ERROR_INVALID_NAME");
			break;
		case ERROR_INVALID_PARAMETER:
			addLogMessage("Error: ERROR_INVALID_PARAMETER");
			break;
		case ERROR_INVALID_SERVICE_ACCOUNT:
			addLogMessage("Error: ERROR_INVALID_SERVICE_ACCOUNT");
			break;
		case ERROR_SERVICE_EXISTS:
			addLogMessage("Error: ERROR_SERVICE_EXISTS");
			break;
		default:
			addLogMessage("Error: Undefined");
		}
		CloseServiceHandle(hSCManager);
		return -1;
	}
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	addLogMessage("Success install service!");
	return 0;
}

int RemoveService() {
	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hSCManager) {
		addLogMessage("Error: Can't open Service Control Manager");
		return -1;
	}
	SC_HANDLE hService = OpenService(hSCManager, serviceName, SERVICE_STOP | DELETE);
	if (!hService) {
		addLogMessage("Error: Can't remove service");
		CloseServiceHandle(hSCManager);
		return -1;
	}
	DeleteService(hService);
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	addLogMessage("Success remove service!");
	return 0;
}

int StartSService()
{
	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	SC_HANDLE hService = OpenService(hSCManager, serviceName, SERVICE_START);
	if (hService == NULL)
	{
		CloseServiceHandle(hSCManager);
		addLogMessage("Error: bad handle");
		return -1;
	}
	if (!StartService(hService, 0, NULL))
	{
		int err = GetLastError();
		switch (err) {
		case ERROR_ACCESS_DENIED:
			addLogMessage("Error: ERROR_ACCESS_DENIED");
			break;
		case ERROR_INVALID_HANDLE:
			addLogMessage("Error: ERROR_INVALID_HANDLE");
			break;
		case ERROR_PATH_NOT_FOUND:
			addLogMessage("Error: ERROR_PATH_NOT_FOUND");
			break;
		case ERROR_SERVICE_ALREADY_RUNNING:
			addLogMessage("Error: ERROR_SERVICE_ALREADY_RUNNING");
			break;
		case ERROR_SERVICE_DATABASE_LOCKED:
			addLogMessage("ERROR_SERVICE_DATABASE_LOCKED");
			break;
		case ERROR_SERVICE_DEPENDENCY_DELETED:
			addLogMessage("Error: ERROR_SERVICE_DEPENDENCY_DELETED");
			break;
		case ERROR_SERVICE_DEPENDENCY_FAIL:
			addLogMessage("Error: ERROR_SERVICE_DEPENDENCY_FAIL");
			break;
		case ERROR_SERVICE_DISABLED:
			addLogMessage("Error: ERROR_SERVICE_DISABLED");
			break;
		case ERROR_SERVICE_LOGON_FAILED:
			addLogMessage("Error: ERROR_SERVICE_LOGON_FAILED");
			break;
		case ERROR_SERVICE_MARKED_FOR_DELETE:
			addLogMessage("Error: ERROR_SERVICE_MARKED_FOR_DELETE");
			break;
		case ERROR_SERVICE_NO_THREAD:
			addLogMessage("Error: ERROR_SERVICE_NO_THREAD");
			break;
		case ERROR_SERVICE_REQUEST_TIMEOUT:
			addLogMessage("Error: ERROR_SERVICE_REQUEST_TIMEOUT");
			break;
		default: addLogMessage("Error: Undefined");
		}
		CloseServiceHandle(hSCManager);
		return -1;
	}
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	return 0;
}

void main(int argc, char* argv[])
{
	if (argc - 1 == 0)
	{
		SERVICE_TABLE_ENTRY ServiceTable[] =
		{ {  serviceNameENTRY,                        //имя сервиса
			(LPSERVICE_MAIN_FUNCTION)ServiceMain }, //главная функция сервиса
			{ NULL, NULL }
		};
		if (!StartServiceCtrlDispatcher(ServiceTable))
		{
			addLogMessage("Error: StartServiceCtrlDispatcher");
		}
	}
	else if (strcmp(argv[argc - 1], "install") == 0)
	{
		InstallService();
	}
	else if (strcmp(argv[argc - 1], "remove") == 0)
	{
		RemoveService();
	}
	else if (strcmp(argv[argc - 1], "start") == 0)
	{
		StartSService();
	}
}


