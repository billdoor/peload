#include "pefile.h"

#include <iostream>

using namespace std;

int main(int argc, char **argv)
{
	cout << "PELoad test" << endl;

	if(argc == 2)
	{
		cout << "Loading file " << argv[1] << endl;
		PEFile pe(argv[1]);
		cout << "Entry point bytes:" << endl;
		vector<BYTE> buf = pe.getBuffer(pe.getEntryPointVA(), 0x100);
		for(size_t i = 0; i < buf.size(); ++i)
		{
			if(i % 0x10 == 0)
				cout << endl;
			cout << hex << (size_t)buf[i] << " ";
		}
		cout << endl;
	}
	return 0;
}
