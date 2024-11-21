#include "vm.hpp"
#include "vm_types.hpp"

// Globals
Vector<DWORD> RelocRVAs;
Vector<Vector<VirtInst_t>> Virtualized;

bool Virtualize(_In_ Asm* pPE) {
	LOG(Info_Extended, MODULE_VM, "Beginning virtualization (%d functions)\n", Options.VM.VMFuncs.Size() + Options.VM.bVirtEntry);

	uint64_t Total;
	uint64_t Virted;
	for (int i = 0; i < Options.VM.VMFuncs.Size(); i++) {
		Total = Virted = 0;
		LOG(Info, MODULE_VM, "Virtualizing \'%s\'\n", Options.VM.VMFuncs[i].Name);

		LOG(Success, MODULE_VM, "Virtualized function \'%s\' (%d%%)\n", Options.VM.VMFuncs[i].Name, 100 * Virted / Total);
	}

	LOG(Success, MODULE_VM, "Finished virtualization\n");
	return true;
}