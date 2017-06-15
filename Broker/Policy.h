#pragma once
#include <Windows.h>
#include <vector>
#include <stdio.h>
#include <string>
#include <fstream>
#include <iostream>
#include <regex> 


typedef struct {
	std::wstring path;
	DWORD flags;
} PolicyEntry;

class Policy
{
private:
	std::vector<PolicyEntry*> deny;
	std::vector<PolicyEntry*> allows;

	DWORD GetFlag(std::wstring Flag);
	BOOL ParseLine(std::wstring line, std::vector<PolicyEntry*> allows, std::vector<PolicyEntry*> deny);
	VOID FreeAll(std::vector<PolicyEntry*> allows, std::vector<PolicyEntry*> deny);

public:
	Policy();
	~Policy();
	
	BOOL ParsePolicyFile(__in PWCHAR PolicyFileName);
	BOOL HaveAccessToFile(PWCHAR file, DWORD dwDesiredAccess, DWORD dwShareMode, DWORD dwFlagsAndAttributes);
	BOOL HaveAccessToDirectory(PWCHAR dirrectory);
};

