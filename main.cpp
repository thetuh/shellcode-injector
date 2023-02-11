
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <bcrypt.h>
#include <fstream>
#include <filesystem>
#include <string>
#include <Psapi.h>
#include <tchar.h>
#include <intrin.h>

#include "pe.h"
#include "syscall/syscalls.h"
#include "utilities.h"

#define DLL_PATH "example_dll.dll"
#define PROCESS "ac_client.exe"

extern "C" void* internal_cleancall_wow64_gate{ nullptr };

unsigned char shellcode[ ] = "\x6a\x00\x68\xbb\xbb\xbb\xbb\x68\xcc\xcc\xcc\xcc\x6a\x00\xb8\xff\xff\xff\xff\xff\xd0\x68\xdd\xdd\xdd\xdd\xb8\xff\xff\xff\xff\xff\xd0\xc3";

bool resolve_module_functions( )
{
    printf( "testing module resolves...\n" );

    /* this is not ideal */
    std::string user32string{ "user32.dll" };

    /* ensure that the library is loaded before we attempt to resolve its exports */
    LoadLibrary( user32string.c_str() );

    const auto my_handle{ OpenProcess( PROCESS_ALL_ACCESS, false, GetCurrentProcessId( ) ) };
    if ( !my_handle || my_handle == INVALID_HANDLE_VALUE )
        printf( "could not open handle to own process\n" );

    const DWORD user32_mod_remote{ remote_get_module_handle( my_handle, user32string ) };
    const DWORD user32_mod{ ( DWORD ) GetModuleHandle( user32string.c_str( ) ) };
    if ( user32_mod_remote != user32_mod )
    {
        printf( "incorrect module address\n" );
        CloseHandle( my_handle );
        return false;
    }

    const DWORD call_next_hook_remote{ GetRemoteFuncAddress( my_handle, user32string, "CallNextHookEx" ) };
    const DWORD call_next_hook{ ( DWORD ) GetProcAddress( GetModuleHandle( user32string.c_str( ) ), "CallNextHookEx" ) };
    if ( call_next_hook_remote != call_next_hook )
    {
        printf( "incorrect export address\n" );
        CloseHandle( my_handle );
        return false;
    }

    printf( "succeded tests!\n" );

    CloseHandle( my_handle );

    return true;
}

int main( )
{
    try
    {
        /* no point in continuing if we can't even correctly evaluate our own modules */
        if ( !resolve_module_functions( ) )
            throw std::exception( "failed export resolve test" );

        /* initialize WoW64 transition call (heaven's gate) */
        internal_cleancall_wow64_gate = ( void* ) __readfsdword( 0xC0 );

        printf( "looking for process id...\n" );

        const DWORD pid{ get_pid_by_name( PROCESS ) };
        if ( !pid )
            throw std::exception( "could not find target process id" );

        printf( "pid found: %u\n", pid );

        /* read the raw data of our dll and store it in in a byte vector */
        if ( !std::filesystem::exists( DLL_PATH ) )
            throw std::exception( "file does not exist" );

        std::basic_ifstream<std::byte> file( DLL_PATH, std::ios::binary );
        if ( !file )
            throw std::exception( "could not read file" );

        file.exceptions( std::ifstream::failbit | std::ifstream::badbit );
        if ( std::filesystem::file_size( DLL_PATH ) < 0x1000 )
        {
            file.close( );
            throw std::exception( "invalid file size" );
        }

        std::vector<std::byte> binary_data = { std::istreambuf_iterator<std::byte>( file ), std::istreambuf_iterator<std::byte>( ) };
        file.close( );

        printf( "performing PE sanity checks...\n" );

        const IMAGE_DOS_HEADER* old_dos{ reinterpret_cast< IMAGE_DOS_HEADER* >( binary_data.data() ) };
        if ( !old_dos || old_dos->e_magic != IMAGE_DOS_SIGNATURE )
            throw std::exception( "invalid dos signature" );

        const IMAGE_NT_HEADERS* old_nt{ reinterpret_cast< IMAGE_NT_HEADERS* >( ( uintptr_t ) old_dos + old_dos->e_lfanew ) };
        if ( !old_nt || old_nt->Signature != IMAGE_NT_SIGNATURE )
            throw std::exception( "invalid nt signature" );

        printf( "opening handle to process...\n" );

        OBJECT_ATTRIBUTES attr;
        memset( &attr, 0, sizeof( OBJECT_ATTRIBUTES ) );
        InitializeObjectAttributes( &attr, NULL, 0, 0, NULL );

        CLIENT_ID cid;
        cid.UniqueProcess = ( HANDLE ) pid;
        cid.UniqueThread = NULL;

        HANDLE process_handle{ nullptr };
        if ( NT_ERROR( NtOpenProcess( &process_handle, PROCESS_ALL_ACCESS, &attr, &cid ) ) )
        {
            binary_data.~vector( );
            throw std::exception( "could not open process handle" );
        }

        /* allocate dll memory */
        void* target_base{ reinterpret_cast< void* >( old_nt->OptionalHeader.ImageBase ) };
        SIZE_T region_size{ old_nt->OptionalHeader.SizeOfImage };
        if ( NT_ERROR( NtAllocateVirtualMemory( process_handle, &target_base, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) ) )
        {
            printf( "could not allocate virtual memory at preferred image base, reattemping to allocate at arbitrary location\n" );

            target_base = nullptr;
            region_size = old_nt->OptionalHeader.SizeOfImage;

            if ( NT_ERROR( NtAllocateVirtualMemory( process_handle, &target_base, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) ) )
            {
                binary_data.~vector( );
                NtClose( process_handle );
                throw std::exception( "could not allocate dll virtual memory" );
            }
        }

        /* map our dll headers */
        if ( NT_ERROR( NtWriteVirtualMemory( process_handle, target_base, binary_data.data( ), old_nt->OptionalHeader.SizeOfHeaders, NULL ) ) )
        {
            NtFreeVirtualMemory( process_handle, &target_base, &region_size, MEM_RELEASE );
            NtClose( process_handle );
            throw std::exception( "could not write image headers" );
        }

        /* map our dll sections */
        PIMAGE_SECTION_HEADER section_header = ( PIMAGE_SECTION_HEADER ) ( old_nt + 1 );
        for ( int i = 0; i < old_nt->FileHeader.NumberOfSections; i++ )
        {
            if ( NT_ERROR( NtWriteVirtualMemory( process_handle, ( PVOID ) ( ( LPBYTE ) target_base + section_header[ i ].VirtualAddress ),
                ( PVOID ) ( ( LPBYTE ) binary_data.data( ) + section_header[ i ].PointerToRawData ), section_header[ i ].SizeOfRawData, NULL ) ) )
            {
                NtFreeVirtualMemory( process_handle, &target_base, &region_size, MEM_RELEASE );
                NtClose( process_handle );
                throw std::exception( "could not write image sections" );
            }
        }

        /* prepare our loader data */
        loaderdata LoaderParams{ };
        LoaderParams.ImageBase = target_base;
        LoaderParams.NtHeaders = ( PIMAGE_NT_HEADERS ) ( ( LPBYTE ) target_base + old_dos->e_lfanew );

        LoaderParams.BaseReloc = ( PIMAGE_BASE_RELOCATION ) ( ( LPBYTE ) target_base
            + old_nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress );
        LoaderParams.ImportDirectory = ( PIMAGE_IMPORT_DESCRIPTOR ) ( ( LPBYTE ) target_base
            + old_nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress );

        LoaderParams.fnLoadLibraryA = LoadLibraryA;
        LoaderParams.fnGetProcAddress = GetProcAddress;

        /* we don't need this anymore, free it */
        binary_data.~vector( );

        /* allocate the loader memory for our dll */
        void* loader_address{ nullptr };
        if ( NT_ERROR( NtAllocateVirtualMemory( process_handle, &loader_address, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE  ) ) )
        {
            NtClose( process_handle );
            throw std::exception( "could not allocate loader memory" );
        }

        if ( NT_ERROR( NtWriteVirtualMemory( process_handle, loader_address, &LoaderParams, sizeof( loaderdata ), nullptr ) ) )
        {
            NtClose( process_handle );
            throw std::exception( "could not write loader info" );
        }

        if ( NT_ERROR( NtWriteVirtualMemory( process_handle, ( PVOID ) ( ( loaderdata* ) loader_address + 1 ), LibraryLoader, ( DWORD ) stub - ( DWORD ) LibraryLoader, nullptr ) ) )
        {
            NtClose( process_handle );
            throw std::exception( "could not write loader function" );
        }

        /* allocate shellcode memory that will call our loader stub */
        region_size = sizeof( shellcode );
        void* shellcode_address{ nullptr };
        if ( NT_ERROR( NtAllocateVirtualMemory( process_handle, &shellcode_address, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) ) )
        {
            NtClose( process_handle );
            throw std::exception( "could not allocate shellcode memory" );
        }

        constexpr char title[ ] = "title";
        constexpr char msg[ ] = "caption";
        std::string user32_string{ "user32.dll" };
        
        region_size = ( strlen( title ) + 1 );
        void* title_address{ nullptr };
        if ( NT_ERROR( NtAllocateVirtualMemory( process_handle, &title_address, 0, &region_size, MEM_COMMIT, PAGE_READWRITE ) ) )
        {
            NtClose( process_handle );
            throw std::exception( "could not allocate messagebox title virtual memory" );
        }

        if ( NT_ERROR( NtWriteVirtualMemory( process_handle, title_address, ( LPVOID ) title, region_size, nullptr ) ) )
        {
            NtClose( process_handle );
            throw std::exception( "could not write messagebox title" );
        }

        region_size = ( strlen( msg ) + 1 );
        void* msg_address{ nullptr };
        if ( NT_ERROR( NtAllocateVirtualMemory( process_handle, &msg_address, 0, &region_size, MEM_COMMIT, PAGE_READWRITE ) ) )
        {
            NtClose( process_handle );
            throw std::exception( "could not allocate messagebox msg virtual memory" );
        }

        if ( NT_ERROR( NtWriteVirtualMemory( process_handle, msg_address, ( LPVOID ) msg, region_size, nullptr ) ) )
        {
            NtClose( process_handle );
            throw std::exception( "could not write messagebox caption" );
        }

        /* patch the addresses into the shellcode */
        *( LPVOID* ) ( shellcode + 3 ) = title_address;
        *( LPVOID* ) ( shellcode + 8 ) = msg_address;
        *( DWORD* ) ( shellcode + 15 ) = GetRemoteFuncAddress( process_handle, user32_string, "MessageBoxA" );
        *( LPVOID* ) ( shellcode + 0x16 ) = loader_address;
        *( LPVOID* ) ( shellcode + 0x1b ) = ( ( loaderdata* ) loader_address + 1 );

        /* write the shellcode to the allocated memory */
        NtWriteVirtualMemory( process_handle, shellcode_address, shellcode, region_size, nullptr );

        /* 'safe' module that we will pass */
        const HMODULE dll{ LoadLibraryA( "ntdll.dll" ) };
        
        /* retrieve thread id using window name */
        const HWND hwnd = FindWindowA( NULL, PROCESS );
        const DWORD tid{ GetWindowThreadProcessId( hwnd, NULL ) };

        /* use our shellcode as a hook procedure */
        const HHOOK handle{ SetWindowsHookExA( WH_KEYBOARD, ( HOOKPROC ) shellcode_address, dll, tid ) };
        if ( !handle )
            throw std::exception( "could not set hook procedure" );

        PostThreadMessageA( tid, WM_NULL, NULL, NULL );
        printf( "successfully set hook procedure! unhooking in 5 seconds...\n" );

        Sleep( 2500 );

        UnhookWindowsHookEx( handle );
        printf( "unhooked, exiting program...\n" );
        system( "pause > nul" );

        return EXIT_SUCCESS;
    }
    catch ( std::exception& e )
    {
        printf( "error: %s\n", e.what( ) );

        system( "pause" );

        return EXIT_FAILURE;
    }
}
