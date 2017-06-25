#pragma once
#include <windows.h>
#include <vector>


using namespace std;

struct CmdlineArg
{
	int argId;
	wstring shortName;
	wstring longName;
	wstring description;
	wstring valueName;
	BOOL isFlag;
	BOOL mandatory;
	BOOL lastArg;
	PWCHAR value;
	int index;
}; 

class cmdline
{
	LPWSTR progDescription;
	vector<CmdlineArg*>* args;
	int numOfMandatory;
	BOOL lastArgDefined;
	PWCHAR programName;

public:
	cmdline(PWCHAR program, LPWSTR description);
	~cmdline();

	BOOL AddOption(int id, wstring shortName, wstring longName, wstring valueName, wstring description, BOOL mandatory, BOOL isFlag, BOOL lastArg);
	VOID parse(int argc, PWCHAR argv[]) const;
	VOID printUsage() const;
	LPWSTR GetArg(int id) const;
	DWORD GetArgIndex(int id) const;
};
