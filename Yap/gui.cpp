#include "gui.hpp"
#include <d3d11.h>
#include <dxgi.h>
#include <stdlib.h>
#include <ctime>
#include "imgui_internal.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#pragma comment(lib, "d3d11.lib")
#include "util.h"
#include "asm.hpp"

static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
IDXGIOutput* g_pOutput = NULL;
bool bMinimized = false, bOpen = true, bInitialized = false;;
const int width = 850;
const int height = 560;
ImGuiWindow* pWindow = NULL;
Asm* _pAssembly = NULL;

LRESULT WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
DWORD WINAPI WindowThread(void* args);
void CleanupRenderTarget();
void CreateRenderTarget();
void CleanupDeviceD3D();
bool CreateDeviceD3D(HWND hWnd);
void EndGUI();
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

DWORD WINAPI ParsePE(void* args) {
	Data.PEFunctions = _pAssembly->FindFunctions();
	return 0;
}

// Opens file dialogue
bool OpenFileDialogue(_Out_ char* pOut, _In_ size_t szOut, _In_ char* pFilter, _Out_opt_ WORD* pFileNameOffset, _In_ bool bSaveTo) {
	// Initialize struct
	OPENFILENAME FileName = { 0 };
	FileName.lStructSize = sizeof(OPENFILENAME);
	FileName.hwndOwner = Data.hWnd;
	FileName.lpstrFilter = pFilter;
	FileName.nFilterIndex = 1;
	FileName.lpstrFile = pOut;
	FileName.nMaxFile = szOut;
	FileName.Flags = OFN_EXPLORER;
	if (!bSaveTo)
		FileName.Flags |= OFN_FILEMUSTEXIST;

	// Open dialogue
	bool bRet = false;
	if (bSaveTo) {
		bRet = GetSaveFileName(&FileName);
	}
	else {
		bRet = GetOpenFileName(&FileName);
	}

	// Return
	if (pFileNameOffset && bRet) {
		*pFileNameOffset = FileName.nFileOffset;
	}
	return bRet;
}

void DrawGUI() {
	// End if window is closed
	if (!bOpen) {
		EndGUI();
		_exit(0);
	}
	
	ImGui::Begin("Yap (Yet Another Packer)", &bOpen, ImGuiWindowFlags_NoResize);

	// Drag-n-drop menu
	if (!Data.PEFunctions.raw.pBytes && !Data.PEFunctions.raw.u64Size) {
		// Handle dropped file
		if (Data.hDropFile) {
			char File[MAX_PATH];
			if (DragQueryFileA(Data.hDropFile, 0, File, MAX_PATH)) {
				_pAssembly = new Asm(File);
				if (_pAssembly->GetStatus()) {
					MessageBoxA(Data.hWnd, "Could not parse binary!", NULL, MB_OK | MB_ICONERROR);
				} else {
					Data.bParsing = true;
					CreateThread(0, 0, ParsePE, 0, 0, 0);
				}
			}
			DragFinish(Data.hDropFile);
			Data.hDropFile = NULL;
		}

		ImGui::SetCursorPos(ImVec2((ImGui::GetWindowSize().x - ImGui::CalcTextSize(Data.bParsing ? "Analyzing..." : "Drop file here").x) / 2, (ImGui::GetWindowSize().y - ImGui::GetTextLineHeight()) / 2));
		ImGui::Text(Data.bParsing ? "Analyzing..." : "Drop file here");
	}

	// Configuration menu
	else if (!Data.bRunning) {
		ImGui::BeginTabBar("#Tabs");

		if (ImGui::BeginTabItem("Packing")) {
			IMGUI_TOGGLE("Enable Packer", Options.Packing.bEnabled);
			ImGui::SetItemTooltip("Wraps the original binary with a custom loader.");
			ImGui::SameLine();
			IMGUI_TOGGLE("Don't Pack Resources", Options.Packing.bDontCompressRsrc);
			ImGui::SetItemTooltip("Preserves everything in the resource directory, keeping details such as icons and privileges.");
			ImGui::SliderInt("Depth", &Options.Packing.EncodingCounts, 1, 10);
			ImGui::SetItemTooltip("Number of times the application should be packed.\n1: packed app\n2: packed packed app\n3: packed packed packed app\netc.");
			ImGui::SliderInt("Compression Level", &Options.Packing.CompressionLevel, 1, 9);
			ImGui::SetItemTooltip("How compressed the binary should be.");
			ImGui::SliderInt("Mutation Level", &Options.Packing.MutationLevel, 1, 15);
			ImGui::SetItemTooltip("The amount of garbage that should be generated (more -> slower).");
			//DEBUG_ONLY(IMGUI_TOGGLE("Evade Dumpers", Options.Packing.bEvadeDumpers));
			DEBUG_ONLY(ImGui::SetItemTooltip("Attempts to throw off PE dumpers."));
			IMGUI_TOGGLE("Hide IAT", Options.Packing.bHideIAT);
			ImGui::SetItemTooltip("Attempts to hide the packed binaries IAT.");
			IMGUI_TOGGLE("Generate False Info", Options.Packing.bFalseSymbols);
			ImGui::SetItemTooltip("Creates fake data directories and tables (doesn\'t affect size)");
			IMGUI_TOGGLE("Delayed Entry Point", Options.Packing.bDelayedEntry);
			ImGui::SetItemTooltip("Changes the entry point of the application during runtime.");
			IMGUI_TOGGLE("DLL Sideloading Mitigations", Options.Packing.bMitigateSideloading);
			ImGui::SetItemTooltip("Prioritizes DLLs in Windows directories, loading those first instead of DLLs placed in the local directory.");
			ImGui::SameLine();
			IMGUI_TOGGLE("Only Load Microsoft Signed DLLs", Options.Packing.bOnlyLoadMicrosoft);
			ImGui::SetItemTooltip("Only allows DLLs that have been signed by Microsoft to be loaded.");
			IMGUI_TOGGLE("Anti-Debug", Options.Packing.bAntiDebug);
			ImGui::SetItemTooltip("Prevent debuggers from attaching to process.");
			IMGUI_TOGGLE("Anti-VM", Options.Packing.bAntiVM);
			ImGui::SetItemTooltip("Prevent app from running in a virtual machine.");
			ImGui::SameLine();
			IMGUI_TOGGLE("Allow Hyper-V", Options.Packing.bAllowHyperV);
			ImGui::SetItemTooltip("Still run if the detected VM is only MS Hyper-V.");
			IMGUI_TOGGLE("Anti-Sandbox", Options.Packing.bAntiSandbox);
			ImGui::SetItemTooltip("Prevent app from running in a sandboxed environment.");
			ImGui::Combo("Immitate Packer", (int*)&Options.Packing.Immitate, "None\0Themida\0WinLicense\0UPX\0MPRESS\0ExeStealth\0Enigma\0");
			ImGui::SetItemTooltip("Changes some details about the packed binary to make it look like another packer.");
			if (ImGui::TreeNode("Extended Options")) {
				IMGUI_TOGGLE("Enable Process Masquerading", Options.Packing.bEnableMasquerade);
				ImGui::SetItemTooltip("Makes the packed executable appear as a different process (NOT process hollowing).\nPlease note that the smaller the path the easier it is to use.");
				ImGui::SameLine();
				ImGui::InputText(" ", Options.Packing.Masquerade, MAX_PATH);
				IMGUI_TOGGLE("Mark Critical (Requires Admin)", Options.Packing.bMarkCritical);
				ImGui::SetItemTooltip("Marks the process as critical, causing the system to bluescreen when the process exits or is killed.\nRequires the packed process to be run with administrator privileges.");
				ImGui::InputText("Leave a Message", Options.Packing.Message, 64);
				ImGui::SetItemTooltip("Leave a little message for any possible reverse engineers.");
				ImGui::TreePop();
			}
			ImGui::EndTabItem();
		}

		if (ImGui::BeginTabItem("VM")) {
			IMGUI_TOGGLE("Enable VM", Options.VM.bEnabled);
			if (ImGui::Button("Add Function (Max 256)")) {
				if (Options.VM.VMFuncs.Size() >= 256) {
					MessageBoxA(Data.hWnd, "Maximum number of functions selected!", NULL, MB_ICONINFORMATION | MB_OK);
				}
				else {
					Options.VM.VMFuncs.Push(0);
				}
			}

			for (int i = 0, n = Options.VM.VMFuncs.Size(); i < n; i++) {
				// Label
				char buf[512];
				ImGui::Text("Function %d", i + 1);

				// Dropdown
				wsprintfA(buf, "BtnFn%d", i);
				ImGui::PushID(buf);
				if (Options.VM.VMFuncs.At(i)) {
					if (Data.PEFunctions.At(Options.VM.VMFuncs.At(i) - 1).pName) {
						strcpy_s(buf, Data.PEFunctions.At(Options.VM.VMFuncs.At(i) - 1).pName);
					}
					else {
						wsprintfA(buf, "sub_%p", Data.PEFunctions.At(Options.VM.VMFuncs.At(i) - 1).u64Address);
					}
				}
				else {
					memcpy(buf, "Select Function", 16);
				}
				ImGui::SameLine();
				if (ImGui::BeginCombo("Function", buf)) {
					for (int j = 0, m = Data.PEFunctions.Size(); j < m; j++) {
						if (!Data.PEFunctions.At(j).pName) wsprintfA(buf, "sub_%p", Data.PEFunctions.At(j).u64Address);
						else strcpy_s(buf, Data.PEFunctions.At(j).pName);
						if (ImGui::Selectable(buf)) {
							Options.VM.VMFuncs.Replace(i, j + 1);
						}
						if (j == Options.VM.VMFuncs.At(i) - 1) {
							ImGui::SetItemDefaultFocus();
						}
					}
					ImGui::EndCombo();
				}
				ImGui::PopID();

				// Remove button
				ImGui::SameLine();
				wsprintfA(buf, "BtnRemove%d", i);
				ImGui::PushID(buf);
				if (ImGui::Button("Remove")) {
					uint64_t holder = 0;
					for (int j = i; j < n - 1; j++) Options.VM.VMFuncs.Replace(j, Options.VM.VMFuncs.At(j + 1));
					Options.VM.VMFuncs.Pop();
					n--;
					i--;
				}
				ImGui::PopID();
			}
			ImGui::EndTabItem();
		}

		if (ImGui::BeginTabItem("Reassembler")) {
			IMGUI_TOGGLE("Enabled", Options.Reassembly.bEnabled);
			ImGui::SetItemTooltip("");
			IMGUI_TOGGLE("Test", Options.Reassembly.bTest);
			IMGUI_TOGGLE("Strip Debug Symbols", Options.Reassembly.bStrip);
			ImGui::SetItemTooltip("Remove debugging information from the PE.");
			ImGui::EndTabItem();
		}

#ifdef _DEBUG
		if (ImGui::BeginTabItem("Debug")) {
			IMGUI_TOGGLE("Create Breakpoints", Options.Debug.bGenerateBreakpoints);
			IMGUI_TOGGLE("Wrap Real Instructions in NOPs", Options.Debug.bGenerateMarks);
			IMGUI_TOGGLE("Dump Disassembly", Options.Debug.bDumpAsm);
			IMGUI_TOGGLE("Dump Individual Sections", Options.Debug.bDumpSections);
			IMGUI_TOGGLE("Disable Mutation", Options.Debug.bDisableMutations);
			IMGUI_TOGGLE("Disable Relocations", Options.Debug.bDisableRelocations);
			ImGui::EndTabItem();
		}
#endif

		if (ImGui::BeginTabItem("Version")) {
			ImGui::Text("Yap Version: " __YAP_VERSION__);
			ImGui::Text("ImGui Version: " IMGUI_VERSION);
			ImGui::Text("Zydis Version: %d.%d.%d", ZYDIS_VERSION_MAJOR(ZYDIS_VERSION), ZYDIS_VERSION_MINOR(ZYDIS_VERSION), ZYDIS_VERSION_PATCH(ZYDIS_VERSION));
			ImGui::Text("AsmJit Version: %d.%d.%d", ASMJIT_LIBRARY_VERSION_MAJOR(ASMJIT_LIBRARY_VERSION), ASMJIT_LIBRARY_VERSION_MINOR(ASMJIT_LIBRARY_VERSION), ASMJIT_LIBRARY_VERSION_PATCH(ASMJIT_LIBRARY_VERSION));
			ImGui::Text("Build: " __YAP_BUILD__);
			ImGui::Text("Build Time: " __DATE__ " " __TIME__);
			ImGui::EndTabItem();
		}

		ImGui::EndTabBar();
		ImGui::SetCursorPos(ImVec2(800 - ImGui::GetWindowScrollbarRect(ImGui::GetCurrentWindow(), ImGuiAxis_Y).GetWidth(), 532 + ImGui::GetScrollY()));
		if (ImGui::Button("Begin")) {
			CreateThread(0, 0, Begin, 0, 0, 0);
		}
	}

	// Data
	else {
		ImGui::SetCursorPos(ImVec2((ImGui::GetWindowSize().x - ImGui::CalcTextSize("Doing Magical Things...").x) / 2, (ImGui::GetWindowSize().y - ImGui::GetTextLineHeight()) / 2));
		ImGui::Text("Doing Magical Things...");
	}

	ImGui::End();

	// Save file dialogue
	if (Data.bWaitingOnFile && !Data.bUserCancelled) {
		while (!OpenFileDialogue(Data.SaveFileName, MAX_PATH, "Binaries\0*.exe;*.dll;*.sys\0All Files\0*.*\0", NULL, true)) {
			if (MessageBoxA(Data.hWnd, "Failed to get save file name!", NULL, MB_ICONERROR | MB_RETRYCANCEL) == IDCANCEL) {
				Data.bUserCancelled = true;
				break;
			}
		}
		Data.bWaitingOnFile = false;
	}
	if (!pWindow) pWindow = ImGui::FindWindowByName("Yap (Yet Another Packer)");
}

bool BeginGUI() {
	if (bInitialized)
		return false;
	bInitialized = true;

	// Register class
	WNDCLASSEXA WindowClass = { 0 };
	WindowClass.cbSize = sizeof(WNDCLASSEXA);
	WindowClass.lpfnWndProc = (WNDPROC)WndProc;
	WindowClass.hInstance = GetModuleHandle(NULL);
	WindowClass.style = CS_CLASSDC;
	WindowClass.lpszClassName = "Yap (Yet Another Packer)";
	if (!RegisterClassExA(&WindowClass)) {
		return (bInitialized = false);
	}

	// Create window
	if (!(Data.hWnd = CreateWindowExA(
		WS_EX_ACCEPTFILES,
		"Yap (Yet Another Packer)",
		"Yap (Yet Another Packer)",
		0,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		width,
		height,
		NULL,
		NULL,
		GetModuleHandleA(NULL),
		NULL
	))) {
		UnregisterClassA("Yap (Yet Another Packer)", GetModuleHandleA(NULL));
		return (bInitialized = false);
	}
	SetWindowLongA(Data.hWnd, GWL_STYLE, 0);
	ShowWindow(Data.hWnd, SW_SHOW);

	// Setup ImGui
	CreateDeviceD3D(Data.hWnd);
	ImGui_ImplWin32_Init(Data.hWnd);
	ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);
	CleanupRenderTarget();
	g_pSwapChain->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, 0);
	g_pSwapChain->GetContainingOutput(&g_pOutput);
	CreateRenderTarget();

	// Create rendering thread
	if (!CreateThread(0, 0, WindowThread, 0, 0, 0)) {
		EndGUI();
		UnregisterClassA("Yap (Yet Another Packer)", GetModuleHandleA(NULL));
		return false;
	}

	// Handle message queue
	MSG msg;
	while (bInitialized) {
		while (bInitialized && PeekMessage(&msg, Data.hWnd, 0, 0, 1)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
		if (!ImGui::IsMouseDown(0)) {
			g_pOutput->WaitForVBlank();
		}
	}
	return true;
}

void MoveWindow(int x, int y, bool bRelative) {
	if (bRelative) {
		RECT WindowRect;
		GetWindowRect(Data.hWnd, &WindowRect);
		x += WindowRect.left;
		y += WindowRect.top;
	}
	SetWindowPos(Data.hWnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

void EndGUI() {
	if (!bInitialized)
		return;
	bInitialized = false;
	pWindow = (ImGuiWindow*)1;
	ImGui_ImplDX11_Shutdown();
	ImGui_ImplWin32_Shutdown();
	CleanupDeviceD3D();
}

// Window thread
DWORD WINAPI WindowThread(void* args) {
	while (bInitialized) {
		// Setup frame
		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();

		if (pWindow) {
			// Minimize window
			if (pWindow->Collapsed) {
				if (!bMinimized) {
					ShowWindow(Data.hWnd, SW_MINIMIZE);
				}
				ImGui::SetWindowCollapsed(pWindow, false);
			}

			// Move window
			if (pWindow->Pos.x != 0 || pWindow->Pos.y != 0) {
				MoveWindow((int)pWindow->Pos.x, (int)pWindow->Pos.y, true);
			}
		}

		// Render
		ImGui::SetNextWindowPos(ImVec2(0, 0));
		ImGui::SetNextWindowSize(ImVec2(width, height));
		DrawGUI();

		// Finish frame
		ImGui::Render();
		g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
		g_pSwapChain->Present(1, 0);
	}
	EndGUI();
	return 0;
}

// Message handler
LRESULT WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_QUIT:
	case WM_DESTROY:
	case WM_CLOSE:
		EndGUI();
		break;
	case WM_SHOWWINDOW:
		bMinimized = wParam == FALSE;
		break;
	case WM_DROPFILES:
		Data.hDropFile = (HDROP)wParam;
	}
	return ImGui_ImplWin32_WndProcHandler(hWnd, uMsg, wParam, lParam) ? TRUE : DefWindowProc(hWnd, uMsg, wParam, lParam);
}

void ApplyImGuiTheme() {

}


/***** IMGUI PROVIDED DX11 FUNCTIONS *****/

bool CreateDeviceD3D(HWND hWnd)
{
	// Setup swap chain
	DXGI_SWAP_CHAIN_DESC sd;
	ZeroMemory(&sd, sizeof(sd));
	sd.BufferCount = 2;
	sd.BufferDesc.Width = 0;
	sd.BufferDesc.Height = 0;
	sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	sd.BufferDesc.RefreshRate.Numerator = 60;
	sd.BufferDesc.RefreshRate.Denominator = 1;
	sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
	sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	sd.OutputWindow = hWnd;
	sd.SampleDesc.Count = 1;
	sd.SampleDesc.Quality = 0;
	sd.Windowed = TRUE;
	sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

	UINT createDeviceFlags = 0;
	//createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
	D3D_FEATURE_LEVEL featureLevel;
	const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
	HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
	if (res == DXGI_ERROR_UNSUPPORTED) // Try high-performance WARP software driver if hardware is not available.
		res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
	if (res != S_OK)
		return false;

	CreateRenderTarget();
	return true;
}

void CleanupDeviceD3D()
{
	CleanupRenderTarget();
	if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
	if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
	if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

void CreateRenderTarget()
{
	ID3D11Texture2D* pBackBuffer;
	g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
	g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
	pBackBuffer->Release();
}

void CleanupRenderTarget()
{
	if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}