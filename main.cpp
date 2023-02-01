
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

#define DLL_PATH "C:\\Users\\Minh3\\source\\repos\\anticheat_poc\\build\\Release\\example_dll.dll"
#define PROCESS "ac_client.exe"

extern "C" void* internal_cleancall_wow64_gate{ nullptr };

unsigned char shellcode[ ] = "\x6a\x00\x68\xbb\xbb\xbb\xbb\x68\xcc\xcc\xcc\xcc\x6a\x00\xb8\xff\xff\xff\xff\xff\xd0\xc3";
using shellcode_t = void( __stdcall* )( );

bool resolve_module_functions( )
{
    /* ensure that the library is loaded before we attempt to resolve its exports */
    LoadLibrary( "user32.dll" );

    /* this sucks */
    std::string ntstring{ "NTDLL.dll" };
    std::string user32string{ "user32.dll" };
    std::string kernel32string{ "kernel32.dll" };

    const auto my_handle{ OpenProcess( PROCESS_ALL_ACCESS, false, GetCurrentProcessId( ) ) };
    if ( my_handle == INVALID_HANDLE_VALUE )
        printf( "could not open handle to own process\n" );

    const DWORD user32_mod_remote{ remote_get_module_handle( my_handle, user32string ) };
    const DWORD user32_mod{ ( DWORD ) GetModuleHandle( "user32.dll" ) };
    if ( user32_mod_remote == user32_mod )
        printf( "module address match!\n" );
    else
    {
        printf( "incorrect module address\n" );
        CloseHandle( my_handle );
        return false;
    }

    const DWORD call_next_hook_remote{ GetRemoteFuncAddress( my_handle, user32string, "CallNextHookEx" ) };
    const DWORD call_next_hook{ ( DWORD ) GetProcAddress( GetModuleHandle( "user32.dll" ), "CallNextHookEx" ) };
    if ( call_next_hook_remote == call_next_hook )
        printf( "export address match!\n" );
    else
    {
        printf( "incorrect export address\n" );
        CloseHandle( my_handle );
        return false;
    }

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

        /* find the target process id */

        printf( "[noir] looking for process id...\n" );

        const DWORD pid{ get_pid_by_name( PROCESS ) };
        if ( !pid )
            throw std::exception( "could not find target process id" );

        printf( "[noir] pid found: %u\n", pid );

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

        /* PE sanity checks */

        printf( "[noir] verifying file signatures...\n" );

        const IMAGE_DOS_HEADER* old_dos{ reinterpret_cast< IMAGE_DOS_HEADER* >( binary_data.data() ) };
        if ( !old_dos || old_dos->e_magic != IMAGE_DOS_SIGNATURE )
            throw std::exception( "invalid dos signature" );

        const IMAGE_NT_HEADERS* old_nt{ reinterpret_cast< IMAGE_NT_HEADERS* >( ( uintptr_t ) old_dos + old_dos->e_lfanew ) };
        if ( !old_nt || old_nt->Signature != IMAGE_NT_SIGNATURE )
            throw std::exception( "invalid nt signature" );

        /* open a handle to the target process */

        printf( "[noir] opening handle to process...\n" );

        HANDLE process_handle{ nullptr };

        OBJECT_ATTRIBUTES attr;
        memset( &attr, 0, sizeof( OBJECT_ATTRIBUTES ) );
        InitializeObjectAttributes( &attr, NULL, 0, 0, NULL );

        CLIENT_ID cid;
        cid.UniqueProcess = ( HANDLE ) pid;
        cid.UniqueThread = NULL;

        if ( NT_ERROR( NtOpenProcess( &process_handle, PROCESS_ALL_ACCESS, &attr, &cid ) ) )
        {
            binary_data.~vector( );
            throw std::exception( "could not open process handle" );
        }

        /* allocate memory in target process for our dll */

        void* target_base{ reinterpret_cast< void* >( old_nt->OptionalHeader.ImageBase ) };
        SIZE_T region_size{ old_nt->OptionalHeader.SizeOfImage };
        if ( NT_ERROR( NtAllocateVirtualMemory( process_handle, &target_base, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) ) )
        {
            printf( "[noir] could not allocate virtual memory at preferred image base, reattemping to allocate at arbitrary location\n" );

            target_base = nullptr;
            region_size = old_nt->OptionalHeader.SizeOfImage;

            if ( NT_ERROR( NtAllocateVirtualMemory( process_handle, &target_base, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) ) )
            {
                binary_data.~vector( );
                NtClose( process_handle );
                throw std::exception( "could not allocate dll virtual memory" );
            }
        }

        /* map the sections to the newly allocated memory */
        
        printf( "[noir] mapping sections...\n" );

        // Copy the headers to target process
        NtWriteVirtualMemory( process_handle, target_base, binary_data.data(),
            old_nt->OptionalHeader.SizeOfHeaders, NULL );

        // Target Dll's Section Header
        PIMAGE_SECTION_HEADER pSectHeader = ( PIMAGE_SECTION_HEADER ) ( old_nt + 1 );
        // Copying sections of the dll to the target process
        for ( int i = 0; i < old_nt->FileHeader.NumberOfSections; i++ )
        {
            NtWriteVirtualMemory( process_handle, ( PVOID ) ( ( LPBYTE ) target_base + pSectHeader[ i ].VirtualAddress ),
                ( PVOID ) ( ( LPBYTE ) binary_data.data() + pSectHeader[ i ].PointerToRawData ), pSectHeader[ i ].SizeOfRawData, NULL );
        }

        region_size = { sizeof ( shellcode ) };
        void* loader_address{ nullptr };
        if ( NT_ERROR( NtAllocateVirtualMemory( process_handle, &loader_address, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) ) )
        {
            NtFreeVirtualMemory( process_handle, &target_base, &region_size, MEM_RELEASE );
            NtClose( process_handle );
            throw std::exception( "could not allocate loader virtual memory" );
        }

        void* address{ VirtualAlloc( nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) };
        if ( !address )
            throw std::exception( "could not allocate shellcode memory" );

        SIZE_T wrote = 0;
        char title[ ] = "title";
        char msg[ ] = "caption";
        
        LPVOID TitleAddress = VirtualAllocEx( process_handle, NULL, strlen( title ) + 1, MEM_COMMIT, PAGE_READWRITE );
        
        if ( !WriteProcessMemory( process_handle, TitleAddress, ( LPVOID ) title, strlen( title ) + 1, &wrote ) )
            printf( "Couldn't write \"title\" at %p\n", TitleAddress );

        LPVOID MsgAddress = VirtualAllocEx( process_handle, NULL, strlen( msg ) + 1, MEM_COMMIT, PAGE_READWRITE );
        
        if ( !WriteProcessMemory( process_handle, MsgAddress, ( LPVOID ) msg, strlen( msg ) + 1, &wrote ) )
            printf( "Couldn't write \"msg\" at %p\n", MsgAddress );

        std::string user32string{ "user32.dll" };

        *( LPVOID* ) ( shellcode + 3 ) = TitleAddress;
        *( LPVOID* ) ( shellcode + 8 ) = MsgAddress;
        *( DWORD* ) ( shellcode + 15 ) = GetRemoteFuncAddress( process_handle, user32string, "MessageBoxA" );

        NtWriteVirtualMemory( process_handle, loader_address, shellcode, region_size, nullptr );

        const HMODULE dll{ LoadLibraryA( "ntdll.dll" ) };
        const HWND hwnd = FindWindowA( NULL, "ac_client.exe" );
        const DWORD tid{ GetWindowThreadProcessId( hwnd, NULL ) };
        const HHOOK handle{ SetWindowsHookExA( WH_KEYBOARD, ( HOOKPROC ) loader_address, dll, tid ) };
        if ( !handle )
        {
            printf( "couldn't set hook\n" );
            system( "pause" );
            return EXIT_FAILURE;
        }

        PostThreadMessageA( tid, WM_NULL, NULL, NULL );
        system( "pause > nul" );
        return EXIT_SUCCESS;
    }
    catch ( std::exception& e )
    {
        printf( "[noir] error - %s\n", e.what( ) );

        system( "pause" );

        return 1;
    }
}
