#include "stdafx.h"
#include "Policy.h"



Policy::Policy()
{
}


Policy::~Policy()
{
}


BOOL Policy::ParsePolicyFile(__in PWCHAR PolicyFileName) {
	using namespace std;
	wifstream policyFile(PolicyFileName);
	wstring line;

	while (std::getline(policyFile, line)) {
		if (!ParseLine(line, allows, deny)) {
			allows.clear();
			deny.clear();
			return FALSE;
		}
	}
	return TRUE;
}


DWORD Policy::GetFlag(std::wstring Flag) {
	DWORD flagValue = 0;
	if (Flag.find(L"GENERIC_READ") != std::string::npos) {
		flagValue |= GENERIC_READ;
	}
	if (Flag.find(L"GENERIC_WRITE") != std::string::npos) {
		flagValue |= GENERIC_WRITE;
	}
	return flagValue;
}

VOID Policy::FreeAll(std::vector<PolicyEntry*> allows, std::vector<PolicyEntry*> deny){
	for (unsigned int i = 0; i < allows.size(); i++) {
		GlobalFree(allows[i]);
	}
	for (unsigned int i = 0; i < deny.size(); i++) {
		GlobalFree(deny[i]);
	}
	allows.clear();
	deny.clear();
}

BOOL Policy::ParseLine(std::wstring line, std::vector<PolicyEntry*> allows, std::vector<PolicyEntry*> deny) {
	if (line.size() < 2 || line.at(1) != L':'){
		SetLastError(ERROR_EMPTY);
		return FALSE;
	}
	WCHAR entryClass = line.at(0);
	line = line.substr(2);
	size_t nextIndex = line.find(L':');
	PolicyEntry* entry = (PolicyEntry*)GlobalAlloc(GPTR, sizeof(PolicyEntry));
	entry->path = line.substr(0, nextIndex);
	DWORD flag = GetFlag(line.substr(nextIndex));
	if (flag == ~0) {
		FreeAll(allows, deny);
		SetLastError(ERROR_INVALID_ACCESS);
		return FALSE;
	}
	entry->flags = flag; 
	if (entryClass == L'A') {	
		allows.push_back(entry);
		return TRUE;
	}
	else if (entryClass == L'D') {
		deny.push_back(entry);
		return TRUE;
	}
	else {
		SetLastError(ERROR_INVALID_ACCESS);
		return FALSE;
	}
}

BOOL Policy::HaveAccessToFile(PWCHAR file, DWORD dwDesiredAccess, DWORD dwShareMode, DWORD dwFlagsAndAttributes)
{
	using namespace std;
	for (unsigned int i = 0; i < deny.size(); i++) {
		wsmatch match;
		wregex wrx(deny.at(i)->path);
		if (std::regex_match(file,wrx, std::regex_constants::match_default)) {
			if (deny.at(i)->flags == dwDesiredAccess) {
				SetLastError(ERROR_ACCESS_DENIED);
				return FALSE;
			}
		}
	}
	for (unsigned int i = 0; i < allows.size(); i++) {
		wsmatch match;
		wregex wrx(allows.at(i)->path);
		if (std::regex_match(file, wrx, std::regex_constants::match_default)) {
			if (allows.at(i)->flags == dwDesiredAccess) {
				return TRUE;
			}
		}
	}
	return TRUE;
}

BOOL Policy::HaveAccessToDirectory(PWCHAR dirrectory) {
	using namespace std;
	for (unsigned int i = 0; i < deny.size(); i++) {
		wsmatch match;
		wregex wrx(deny.at(i)->path);
		if (std::regex_match(dirrectory, wrx, std::regex_constants::match_default)) {
			SetLastError(ERROR_ACCESS_DENIED);
			return FALSE;
		}
	}
	for (unsigned int i = 0; i < allows.size(); i++) {
		wsmatch match;
		wregex wrx(allows.at(i)->path);
		if (std::regex_match(dirrectory, wrx, std::regex_constants::match_default)) {
			return TRUE;
		}
	}
	return TRUE;
}
