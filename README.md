# PE Service
This is a replacement for the original PEFile service of AssemblyLine

# Dependencies
This service uses the LIEF library.
It also downloads the latest version of the Rich Header compiler information from https://github.com/dishather/richprint/blob/master/comp_id.txt
And the latest version of MalwareBazaar's Code Signing Certificate Blocklist from https://bazaar.abuse.ch/export/csv/cscb/
When building the docker container

It also incorporate the ordlookup files from https://github.com/erocarrera/pefile/tree/master/ordlookup
And the statically built c release of https://github.com/NextronSystems/gimphash
Those last two are statically built in the module and may need to be updated once in a while.
