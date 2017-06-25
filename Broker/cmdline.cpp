#include "stdafx.h"
#include "cmdline.h"
#include <string>


cmdline::cmdline(PWCHAR program, LPWSTR description)
{
	programName = program;
	args = new vector<CmdlineArg*>();
	progDescription = description;
	numOfMandatory = 0;
	lastArgDefined = FALSE;
}


cmdline::~cmdline()
{
	for(size_t i =0; i < args->size(); i++){
		CmdlineArg* arg = args->at(i);
		delete arg;
	}
	args->clear();
	delete args;
}


BOOL cmdline::AddOption(int id, wstring shortName, wstring longName, wstring valueName, wstring description, BOOL mandatory, BOOL isFlag, BOOL lastArg)
{

	if (!(lastArg && lastArgDefined))
	{
		CmdlineArg* arg = new CmdlineArg();
		arg->argId = id;
		arg->index = -1;
		arg->shortName = shortName;
		arg->longName = longName;
		arg->valueName = valueName;
		arg->description = description;
		arg->isFlag = isFlag;
		arg->mandatory = mandatory;
		arg->lastArg = lastArg;
		arg->value = nullptr;
		args->push_back(arg);
		if (mandatory)
		{
			numOfMandatory++;
		}
		if (lastArg) {
			lastArgDefined = TRUE;
		}
		return TRUE;
	}
	return FALSE;
}

VOID cmdline::parse(int argc, PWCHAR argv[]) const
{
	int givenMandatory = 0;
	BOOL error = FALSE;
	for(int i=1; i < argc; i++)
	{
		for (size_t j = 0; j < args->size(); j++) {
			if (wcscmp(argv[i],args->at(j)->shortName.c_str()) == 0 || 
				wcscmp(argv[i], args->at(j)->longName.c_str()) == 0)
			{
				args->at(j)->index = i;
				if (args->at(j)->isFlag)
				{
					args->at(j)->value = argv[i];
					if (args->at(j)->mandatory)
					{
						givenMandatory++;
					}
					if (args->at(j)->lastArg)
					{
						goto end_loop;
					}
				}
				else {
					if (i + 1 < argc)
					{
						args->at(j)->value = argv[i + 1];
						if (args->at(j)->mandatory)
						{
							givenMandatory++;
						}
						if (args->at(j)->lastArg)
						{
							goto end_loop;
						}
					}
					else
					{
						error = TRUE;
						goto end_loop;
					}
				}
				break;
			}
		}
	}
end_loop:
	if(error || givenMandatory != numOfMandatory)
	{
		printUsage();
		system("pause");
		ExitProcess(EXIT_FAILURE);
	}
}


VOID cmdline::printUsage() const
{
	int lastArg = -1;
	wprintf(L"Usage: %s", programName);
	for (size_t i = 0; i < args->size(); i++) {
		WCHAR startSytle = L'[';
		WCHAR endStyle = L']';
		if(args->at(i)->lastArg)
		{
			lastArg = i;
		}
		else if(args->at(i)->mandatory)
		{
			startSytle = L'<';
			endStyle = '>';
		}
		if (args->at(i)->isFlag) {
			wprintf(L" %c%s|%s%c %s", startSytle, args->at(i)->shortName.c_str(), args->at(i)->longName.c_str(), endStyle, L"");
		}
		else {
			wprintf(L" %c%s|%s%c %s", startSytle, args->at(i)->shortName.c_str(), args->at(i)->longName.c_str(), endStyle, args->at(i)->valueName.c_str());
		}
	}
	if (lastArg != -1) {
		WCHAR startSytle = L'[';
		WCHAR endStyle = L']';
		if (args->at(lastArg)->mandatory)
		{
			startSytle = L'<';
			endStyle = '>';
		}
		if (args->at(lastArg)->isFlag) {
			wprintf(L" %c%s|%s%c %s", startSytle, args->at(lastArg)->shortName.c_str(), args->at(lastArg)->longName.c_str(), endStyle, L"");
		}
		else {
			wprintf(L" %c%s|%s%c %s", startSytle, args->at(lastArg)->shortName.c_str(), args->at(lastArg)->longName.c_str(), endStyle, args->at(lastArg)->valueName.c_str());
		}
	}
	wprintf(L"\n\n");
	for (size_t i = 0; i < args->size(); i++) {
		if (args->at(i)->lastArg)
		{
		}
		else if (args->at(i)->mandatory)
		{
			wprintf(L"\t%s | %s - %s\n",
				args->at(i)->shortName.c_str(),
				args->at(i)->longName.c_str(),
				args->at(i)->description.c_str());
		}
		else
		{
			wprintf(L"\t[opt] %s | %s - %s\n",
				args->at(i)->shortName.c_str(),
				args->at(i)->longName.c_str(),
				args->at(i)->description.c_str());
		}
	}
	if (lastArg != -1) {
		if (args->at(lastArg)->mandatory)
		{
			wprintf(L"\t%s | %s - %s\n",
				args->at(lastArg)->shortName.c_str(),
				args->at(lastArg)->longName.c_str(),
				args->at(lastArg)->description.c_str());
		}
		else
		{
			wprintf(L"\t[opt]%s | %s - %s\n",
				args->at(lastArg)->shortName.c_str(),
				args->at(lastArg)->longName.c_str(),
				args->at(lastArg)->description.c_str());
		}
	}
}


LPWSTR cmdline::GetArg(int id) const
{
	for (size_t i = 0; i < args->size(); i++) {
		if (args->at(i)->argId == id)
		{
			return args->at(i)->value;
		}
	}
	return nullptr;
}

DWORD cmdline::GetArgIndex(int id) const
{
	for (size_t i = 0; i < args->size(); i++) {
		if (args->at(i)->argId == id)
		{
			return args->at(i)->index;
		}
	}
	return ~0;
}
