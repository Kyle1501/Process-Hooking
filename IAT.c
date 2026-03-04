/******************************** 
 * 
 * IAT.c - demonstration of how porcess hooking via the IAT table
 * 
 * Resolves the address of MessageBoxA in the IAT table and replace it with
 * the address of hooked_MessageBoxA, which prints a different message.
 * 
 * compile: gcc IAT.c -o IAT.exe
 * 
 * 
 * Author: Kyle Anderson
 * Date: 2026-03-04
 * 
***********************************/

//include directives
#include <windows.h>
#include <stdio.h>

// function pointer type for MessageBoxA
typedef int (WINAPI *MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);

// global variable to store the original MessageBoxA in
MessageBoxA_t original_MessageBoxA = NULL;

// hooked_MessageBoxA - replaces MessageBoxA and prints the text of MessageBoxA in terminal then displays a different message
int WINAPI hooked_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    printf("[Hooked] MessageBoxA called with text: %s\n", lpText); // prints original message to terminal
    return original_MessageBoxA(hWnd, "Hello from Hooked!", lpCaption, uType); //what will be displayed in the message box
}

int main() {
    MessageBoxA(NULL, "Hello, World!", "Victim", MB_OK);

    HMODULE base = GetModuleHandleA(NULL); // get the base address of the current process
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base; // get the DOS header
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)base + dos->e_lfanew); // get the NT header
    IMAGE_IMPORT_DESCRIPTOR *imports = (IMAGE_IMPORT_DESCRIPTOR *)((BYTE *)base + 
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress); //get the import directory

    for (IMAGE_IMPORT_DESCRIPTOR *desc = imports; desc->Name != 0; desc++) {
        char *dll_name = (char *)((BYTE *)base + desc->Name);
        if (_stricmp(dll_name, "user32.dll") == 0) { // check if user32.dll is imported - necessary for MessageBoxA
            printf("Found user32.dll imports\n");

            IMAGE_THUNK_DATA *orig = (IMAGE_THUNK_DATA *)((BYTE *)base + desc->OriginalFirstThunk);
            IMAGE_THUNK_DATA *iat  = (IMAGE_THUNK_DATA *)((BYTE *)base + desc->FirstThunk);

            while (orig->u1.AddressOfData != 0) {
                IMAGE_IMPORT_BY_NAME *import_name = (IMAGE_IMPORT_BY_NAME *)((BYTE *)base + orig->u1.AddressOfData);
                if (strcmp(import_name->Name, "MessageBoxA") == 0) {
                    DWORD old;
                    original_MessageBoxA = (MessageBoxA_t)iat->u1.Function;
                    VirtualProtect(&iat->u1.Function, sizeof(ULONG_PTR), PAGE_READWRITE, &old); // change the protection of the page to allow writing
                    iat->u1.Function = (ULONG_PTR)hooked_MessageBoxA; // replace the pointer 
                    VirtualProtect(&iat->u1.Function, sizeof(ULONG_PTR), old, &old); // restore original protection
                    printf("[IAT] Pointer swapped!\n"); // logging
                }               
                orig++;
                iat++;
            }                   
            break;              
        }                       
    }                           

    MessageBoxA(NULL, "Hello, World!", "Victim", MB_OK);
    return 0;
}
