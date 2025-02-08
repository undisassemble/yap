#include "vm.hpp"
#include "vm_types.hpp"

// Globals
Vector<DWORD> RelocRVAs;
Vector<Vector<VirtInst_t>> Virtualized;

// Util funcs
DWORD GetExportRVA(Asm* pPE, char* name);

bool Virtualize(_In_ Asm* pPE) {
	LOG(Info_Extended, MODULE_VM, "Beginning virtualization (%d functions)\n", Options.VM.VMFuncs.Size() + Options.VM.bVirtEntry);

	uint64_t Total, Virted;
	DWORD dwRVA;
	for (int i = 0; i < Options.VM.VMFuncs.Size(); i++) {
		Total = Virted = 0;
		LOG(Info, MODULE_VM, "Virtualizing \'%s\'\n", Options.VM.VMFuncs[i].Name);
		
		// Get RVA
		dwRVA = GetExportRVA(pPE, Options.VM.VMFuncs[i].Name);
		if (!dwRVA) {
			LOG(Failed, MODULE_VM, "Failed to located function \'%s\'\n", Options.VM.VMFuncs[i].Name);
			continue;
		}
		LOG(Info_Extended, MODULE_VM, "Function address: 0x%p\n", pPE->GetBaseAddress() + dwRVA);

		// Output results
		if (Total) {
			LOG(Success, MODULE_VM, "Virtualized function \'%s\' (%d%%)\n", Options.VM.VMFuncs[i].Name, 100 * Virted / Total);
		} else {
			LOG(Failed, MODULE_VM, "No instructions were found for function \'%s\'\n", Options.VM.VMFuncs[i].Name);
		}
	}

	LOG(Success, MODULE_VM, "Finished virtualization\n");
	return true;
}


DWORD GetExportRVA(Asm* pPE, char* name) {
	Vector<char*> ExportNames = pPE->GetExportedFunctionNames();
	Vector<DWORD> ExportRVAs = pPE->GetExportedFunctionRVAs();
	DWORD RVA = 0;

	for (int i = 0; i < ExportNames.Size(); i++) {
		if (i >= ExportRVAs.Size()) break;
		if (!lstrcmpA(name, ExportNames.At(i))) {
			RVA = ExportRVAs.At(i);
			break;
		}
	}

	ExportNames.Release();
	ExportRVAs.Release();
	return RVA;
}