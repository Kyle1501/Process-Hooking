#include <windows.h>
#include <stdio.h>

typedef int (WINAPI *MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);

MessageBoxA_t original_MessageBoxA = NULL;

int WINAPI hooked_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    printf("[Hooked] MessageBoxA called with text: %s\n", lpText);
    return original_MessageBoxA(hWnd, "Hello from Hooked!", lpCaption, uType);
}

int main() {
    MessageBoxA(NULL, "Hello, World!", "Victim", MB_OK);

    HMODULE base = GetModuleHandleA(NULL);
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)base + dos->e_lfanew);
    IMAGE_IMPORT_DESCRIPTOR *imports = (IMAGE_IMPORT_DESCRIPTOR *)((BYTE *)base + 
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (IMAGE_IMPORT_DESCRIPTOR *desc = imports; desc->Name != 0; desc++) {
        char *dll_name = (char *)((BYTE *)base + desc->Name);
        if (_stricmp(dll_name, "user32.dll") == 0) {
            printf("Found user32.dll imports\n");

            IMAGE_THUNK_DATA *orig = (IMAGE_THUNK_DATA *)((BYTE *)base + desc->OriginalFirstThunk);
            IMAGE_THUNK_DATA *iat  = (IMAGE_THUNK_DATA *)((BYTE *)base + desc->FirstThunk);

            while (orig->u1.AddressOfData != 0) {
                IMAGE_IMPORT_BY_NAME *import_name = (IMAGE_IMPORT_BY_NAME *)((BYTE *)base + orig->u1.AddressOfData);
                if (strcmp(import_name->Name, "MessageBoxA") == 0) {
                    DWORD old;
                    original_MessageBoxA = (MessageBoxA_t)iat->u1.Function;
                    VirtualProtect(&iat->u1.Function, sizeof(ULONG_PTR), PAGE_READWRITE, &old);
                    iat->u1.Function = (ULONG_PTR)hooked_MessageBoxA;
                    VirtualProtect(&iat->u1.Function, sizeof(ULONG_PTR), old, &old);
                    printf("[IAT] Pointer swapped!\n");
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