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

std::vector<const char*> Filetypes = { "BML", "btx" };

long long __fastcall hkPACFind(void* pacBase, long long* outEntry, void* cmpCtx)
{
    long long ret = oPACFind(pacBase, outEntry, cmpCtx);
    if (!ret) return 0;

    __try {
        const char* wanted = *(const char**)((uintptr_t)cmpCtx + 8);
        const char* type = (const char*)outEntry[0];

        char tag[5] = { 0 };
        memcpy(tag, type, 4);

        bool type_found = false;
        for (auto t : Filetypes) if (strcmp(t, tag) == 0) { type_found = true; break; }

        if (wanted && type_found) {
            char exePath[MAX_PATH];
            GetModuleFileNameA(NULL, exePath, MAX_PATH);
            *strrchr(exePath, '\\') = 0;

            const char* fn = strrchr(wanted, '/');
            fn = fn ? fn + 1 : wanted;

            char fnNoExt[MAX_PATH];
            strcpy_s(fnNoExt, fn);
            char* d = strrchr(fnNoExt, '.');
            if (d) *d = 0;

            char modPath[MAX_PATH];
            sprintf_s(modPath, "%s\\mods\\%s", exePath, fnNoExt);

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