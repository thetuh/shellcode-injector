#pragma once

typedef HMODULE( __stdcall* pLoadLibraryA )( LPCSTR );
typedef FARPROC( __stdcall* pGetProcAddress )( HMODULE, LPCSTR );
typedef INT( __stdcall* dllmain )( HMODULE, DWORD, LPVOID );

struct loaderdata
{
	LPVOID ImageBase;

	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseReloc;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;

	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;
};

static DWORD __stdcall LibraryLoader( LPVOID Memory )
{
	loaderdata* LoaderParams = ( loaderdata* ) Memory;

	PIMAGE_BASE_RELOCATION pIBR = LoaderParams->BaseReloc;

	DWORD delta = ( DWORD ) ( ( LPBYTE ) LoaderParams->ImageBase - LoaderParams->NtHeaders->OptionalHeader.ImageBase ); // Calculate the delta

	while ( pIBR->VirtualAddress )
	{
		if ( pIBR->SizeOfBlock >= sizeof( IMAGE_BASE_RELOCATION ) )
		{
			int count = ( pIBR->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD );
			PWORD list = ( PWORD ) ( pIBR + 1 );

			for ( int i = 0; i < count; i++ )
			{
				if ( list[ i ] )
				{
					PDWORD ptr = ( PDWORD ) ( ( LPBYTE ) LoaderParams->ImageBase + ( pIBR->VirtualAddress + ( list[ i ] & 0xFFF ) ) );
					*ptr += delta;
				}
			}
		}

		pIBR = ( PIMAGE_BASE_RELOCATION ) ( ( LPBYTE ) pIBR + pIBR->SizeOfBlock );
	}

	PIMAGE_IMPORT_DESCRIPTOR pIID = LoaderParams->ImportDirectory;

	// Resolve DLL imports
	while ( pIID->Characteristics )
	{
		PIMAGE_THUNK_DATA OrigFirstThunk = ( PIMAGE_THUNK_DATA ) ( ( LPBYTE ) LoaderParams->ImageBase + pIID->OriginalFirstThunk );
		PIMAGE_THUNK_DATA FirstThunk = ( PIMAGE_THUNK_DATA ) ( ( LPBYTE ) LoaderParams->ImageBase + pIID->FirstThunk );

		HMODULE hModule = LoaderParams->fnLoadLibraryA( ( LPCSTR ) LoaderParams->ImageBase + pIID->Name );

		if ( !hModule )
			return FALSE;

		while ( OrigFirstThunk->u1.AddressOfData )
		{
			if ( OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )
			{
				// Import by ordinal
				DWORD Function = ( DWORD ) LoaderParams->fnGetProcAddress( hModule,
					( LPCSTR ) ( OrigFirstThunk->u1.Ordinal & 0xFFFF ) );

				if ( !Function )
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME pIBN = ( PIMAGE_IMPORT_BY_NAME ) ( ( LPBYTE ) LoaderParams->ImageBase + OrigFirstThunk->u1.AddressOfData );
				DWORD Function = ( DWORD ) LoaderParams->fnGetProcAddress( hModule, ( LPCSTR ) pIBN->Name );
				if ( !Function )
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			OrigFirstThunk++;
			FirstThunk++;
		}
		pIID++;
	}

	if ( LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint )
	{
		dllmain EntryPoint = ( dllmain ) ( ( LPBYTE ) LoaderParams->ImageBase + LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint );

		return EntryPoint( ( HMODULE ) LoaderParams->ImageBase, DLL_PROCESS_ATTACH, NULL ); // Call the entry point
	}
	return TRUE;
}

static DWORD __stdcall stub( )
{
	return 0;
}

static DWORD remote_get_module_handle( const HANDLE process, std::string& module_name )
{
    HMODULE module_handles[ 1024 ];
    DWORD bytes_needed;

	if ( EnumProcessModules( process, module_handles, sizeof( module_handles ), &bytes_needed ) )
	{
		for ( int i = 0; i < ( bytes_needed / sizeof( HMODULE ) ); i++ )
		{
			char szModName[ MAX_PATH ];
			if ( GetModuleBaseName( process, module_handles[ i ], szModName, sizeof( szModName ) / sizeof( char ) ) )
			{
				std::string mod_string{ szModName };

				std::transform( module_name.begin( ), module_name.end( ), module_name.begin( ), ::tolower );
				std::transform( mod_string.begin( ), mod_string.end( ), mod_string.begin( ), ::tolower );

				if ( module_name.compare( mod_string ) == 0 )
					return ( DWORD ) module_handles[ i ];
			}
		}
	}

	return 0;
}

static DWORD GetRemoteFuncAddress( const HANDLE process, std::string& module_name, const char* func ) {
	HMODULE hRemote = ( HMODULE ) remote_get_module_handle( process, module_name );
	if ( !hRemote )
		return NULL;

	IMAGE_DOS_HEADER DosHeader;
	if ( !ReadProcessMemory( process, ( void* ) hRemote, &DosHeader, sizeof( IMAGE_DOS_HEADER ), NULL ) || DosHeader.e_magic != IMAGE_DOS_SIGNATURE )
		return NULL;

	IMAGE_NT_HEADERS NtHeaders;
	PDWORD dwNTHeaders = ( PDWORD ) ( ( DWORD ) hRemote + DosHeader.e_lfanew );
	if ( !ReadProcessMemory( process, dwNTHeaders, &NtHeaders, sizeof( IMAGE_NT_HEADERS ), NULL ) || NtHeaders.Signature != IMAGE_NT_SIGNATURE )
		return NULL;

	auto const export_data = NtHeaders.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
	if ( export_data.Size <= 0 )
		return false;

	auto const export_buffer = std::make_unique<uint8_t[ ]>( export_data.Size );
	ReadProcessMemory( process, ( uint8_t* ) hRemote + export_data.VirtualAddress, export_buffer.get( ), export_data.Size, nullptr );
	auto const EATDirPtr = ( PIMAGE_EXPORT_DIRECTORY ) export_buffer.get( );
	IMAGE_EXPORT_DIRECTORY EATDirectory{ *EATDirPtr };

	PDWORD* AddressOfFunctions = ( PDWORD* ) malloc( EATDirectory.NumberOfFunctions * sizeof( PDWORD ) );
	PDWORD* AddressOfNames = ( PDWORD* ) malloc( EATDirectory.NumberOfNames * sizeof( PDWORD ) );
	WORD* AddressOfOrdinals = ( WORD* ) malloc( EATDirectory.NumberOfNames * sizeof( WORD ) );

	if ( !ReadProcessMemory( process, ( void* ) ( ( DWORD ) hRemote + ( DWORD ) EATDirectory.AddressOfFunctions ), AddressOfFunctions, EATDirectory.NumberOfFunctions * sizeof( PDWORD ), NULL ) ) {
		free( AddressOfFunctions );
		free( AddressOfNames );
		free( AddressOfOrdinals );
		return NULL;
	}

	if ( !ReadProcessMemory( process, ( void* ) ( ( DWORD ) hRemote + ( DWORD ) EATDirectory.AddressOfNames ), AddressOfNames, EATDirectory.NumberOfNames * sizeof( PDWORD ), NULL ) ) {
		free( AddressOfFunctions );
		free( AddressOfNames );
		free( AddressOfOrdinals );
		return NULL;
	}

	if ( !ReadProcessMemory( process, ( void* ) ( ( DWORD ) hRemote + ( DWORD ) EATDirectory.AddressOfNameOrdinals ), AddressOfOrdinals, EATDirectory.NumberOfNames * sizeof( WORD ), NULL ) ) {
		free( AddressOfFunctions );
		free( AddressOfNames );
		free( AddressOfOrdinals );
		return NULL;
	}

	DWORD dwExportBase = ( ( DWORD ) hRemote + NtHeaders.OptionalHeader.DataDirectory[ 0 ].VirtualAddress );
	DWORD dwExportSize = ( dwExportBase + NtHeaders.OptionalHeader.DataDirectory[ 0 ].Size );

	for ( int i = 0; i < EATDirectory.NumberOfNames; ++i ) {
		DWORD dwAddressOfFunction = ( ( DWORD ) hRemote + ( DWORD ) AddressOfFunctions[ i ] );
		DWORD dwAddressOfName = ( ( DWORD ) hRemote + ( DWORD ) AddressOfNames[ i ] );

		char pszFunctionName[ 256 ] = { 0 };

		if ( !ReadProcessMemory( process, ( void* ) dwAddressOfName, pszFunctionName, 256, NULL ) )
			continue;

		if ( strcmp( pszFunctionName, func ) != 0 )
			continue;

		if ( dwAddressOfFunction >= dwExportBase && dwAddressOfFunction <= dwExportSize ) {
			char pszRedirectName[ 256 ] = { 0 };

			if ( !ReadProcessMemory( process, ( void* ) dwAddressOfFunction, pszRedirectName, 256, NULL ) )
				continue;

			char pszModuleName[ 256 ] = { 0 };
			char pszFunctionRedi[ 256 ] = { 0 };

			int a = 0;
			for ( ; pszRedirectName[ a ] != '.'; a++ )
				pszModuleName[ a ] = pszRedirectName[ a ];
			a++;
			pszModuleName[ a ] = '\0';

			int b = 0;
			for ( ; pszRedirectName[ a ] != '\0'; a++, b++ )
				pszFunctionRedi[ b ] = pszRedirectName[ a ];
			b++;
			pszFunctionRedi[ b ] = '\0';

			strcat( pszModuleName, ".dll" );

			free( AddressOfFunctions );
			free( AddressOfNames );
			free( AddressOfOrdinals );

			std::string modName{ pszModuleName };

			return GetRemoteFuncAddress( process, modName, pszFunctionRedi );
		}

		WORD OrdinalValue = AddressOfOrdinals[ i ];

		if ( OrdinalValue != i ) {
			DWORD dwAddressOfRedirectedFunction = ( ( DWORD ) hRemote + ( DWORD ) AddressOfFunctions[ OrdinalValue ] );
			DWORD dwAddressOfRedirectedName = ( ( DWORD ) hRemote + ( DWORD ) AddressOfNames[ OrdinalValue ] );

			char pszRedirectedFunctionName[ 256 ] = { 0 };

			free( AddressOfFunctions );
			free( AddressOfNames );
			free( AddressOfOrdinals );

			if ( !ReadProcessMemory( process, ( void* ) dwAddressOfRedirectedName, pszRedirectedFunctionName, 256, NULL ) )
				return NULL;
			else
				return dwAddressOfRedirectedFunction;
		}
		else {
			free( AddressOfFunctions );
			free( AddressOfNames );
			free( AddressOfOrdinals );

			return dwAddressOfFunction;
		}
	}

	free( AddressOfFunctions );
	free( AddressOfNames );
	free( AddressOfOrdinals );

	return NULL;
}

static DWORD get_pid_by_name( const std::string_view process_name )
{
    HANDLE snapshot{ CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 ) };
    if ( snapshot == INVALID_HANDLE_VALUE )
        return 0;

    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof( PROCESSENTRY32 );

    if ( Process32First( snapshot, &process_entry ) )
    {
        do
        {
            if ( !process_name.compare( process_entry.szExeFile ) )
            {
                CloseHandle( snapshot );
                return process_entry.th32ProcessID;
            }
        } while ( Process32Next( snapshot, &process_entry ) );
    }

    CloseHandle( snapshot );
    return 0;
}