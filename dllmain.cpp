#include "pch.h"
#include <windows.h>
#include <cstdio>
#include <stdio.h>
#include <string>
#include <vector>
#include "MinHook.h"


HMODULE g_hMod = 0;
typedef long long(__fastcall* tPACFind)(void* pacBase, long long* outEntry, void* cmpCtx);
tPACFind oPACFind = nullptr;

std::vector<const char*> Filetypes = { "BML", "btx", "mad", "ANHD"};

long long __fastcall hkPACFind(void* pacBase, long long* outEntry, void* cmpCtx)
{
    long long ret = oPACFind(pacBase, outEntry, cmpCtx);
    if (!ret) return 0;

    __try {
        const char* wanted_name = (const char*)outEntry[2];     // out + 0x10
        const char* type = (const char*)outEntry[0];

        /* FILE* log;
        fopen_s(&log, "outEntry.txt", "a");
        if (log) {
            fprintf(log, "data pointer: %p\n", (void*)outEntry[0]);
            fprintf(log, "size: %d\n", *(int*)((uintptr_t)outEntry + 8));
            fprintf(log, "name: %s\n", (const char*)outEntry[2]);
            fprintf(log, "type word: %04X\n", *(unsigned short*)((uintptr_t)outEntry + 0x18));
            fprintf(log, "flag byte: %02X\n", *((unsigned char*)outEntry + 0x1A));
            fprintf(log, "--------------------\n");
            fclose(log);
        } */

        char tag[5] = { 0 };
        memcpy(tag, type, 4);

        bool type_found = false;
        for (auto t : Filetypes) if (strcmp(t, tag) == 0) { type_found = true; break; }

        if (wanted_name && type_found) {
            const char* suffix = "";

            if (strcmp(tag, "btx") == 0)
                suffix = "_tex";

            else if (strcmp(tag, "BML") == 0)
                suffix = "_BML";

            else if (strcmp(tag, "mad") == 0)
                suffix = "_BMD";

            else if (strcmp(tag, "ANHD") == 0)
                suffix = "_BMA";

            char exePath[MAX_PATH];
            GetModuleFileNameA(NULL, exePath, MAX_PATH);
            *strrchr(exePath, '\\') = 0;

            const char* fn = strrchr(wanted_name, '/');
            fn = fn ? fn + 1 : wanted_name;

            char fnNoExt[MAX_PATH];
            strcpy_s(fnNoExt, fn);
            char* d = strrchr(fnNoExt, '.');
            if (d) *d = 0;

            char modPath[MAX_PATH];
            sprintf_s(modPath, "%s\\mods\\%s%s", exePath, fnNoExt, suffix);

            FILE* mf; fopen_s(&mf, modPath, "rb");
            if (mf) {
                fseek(mf, 0, SEEK_END); long sz = ftell(mf); fseek(mf, 0, SEEK_SET);
                void* buf = malloc(sz);
                fread(buf, 1, sz, mf); fclose(mf);
                outEntry[0] = (long long)buf;
                *(int*)((uintptr_t)outEntry + 8) = sz;
                return ret; // not buf
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return ret;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_hMod = hModule;
        DisableThreadLibraryCalls(hModule);

        MH_Initialize();
        uintptr_t base = (uintptr_t)GetModuleHandleA(nullptr);
        void* target = (void*)(base + 0x2E9C30);

        MH_CreateHook(target, &hkPACFind, (void**)&oPACFind);
        MH_EnableHook(target);
    }
    return TRUE;
}
