#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#pragma comment(lib, "advapi32")

#include <windows.h>
#include <wincrypt.h>

TCHAR szClassName[] = TEXT("Window");
#define MAX_BUFFER 1024

BOOL Crypt3Des(BOOL bEnCryptOrDeCrypt, LPBYTE lpszText, DWORD dwTextSize, const LPBYTE lpszPassword, DWORD dwPasswordSize)
{
	HCRYPTKEY hKey = NULL;
	HCRYPTPROV hProv = NULL;
	HCRYPTHASH hHash = NULL;
	BOOL bResult = FALSE;
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_SCHANNEL, CRYPT_VERIFYCONTEXT)) goto END;
	if (!CryptCreateHash(hProv, CALG_SHA, NULL, NULL, &hHash)) goto END;
	if (!CryptHashData(hHash, lpszPassword, dwPasswordSize, 0)) goto END;
	if (!CryptDeriveKey(hProv, CALG_3DES, hHash, 0, &hKey)) goto END;
	if (bEnCryptOrDeCrypt) {
		if (!CryptEncrypt(hKey, NULL, TRUE, 0, lpszText, &dwTextSize, MAX_BUFFER)) goto END;
		CHAR hex_table[16] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
		LPSTR pszTemp = (LPSTR)GlobalAlloc(0, dwTextSize * 2);
		for (DWORD i = 0; i < dwTextSize; ++i) {
			pszTemp[2 * i] = hex_table[(lpszText[i] >> 4) & 0x0F];
			pszTemp[2 * i + 1] = hex_table[lpszText[i] & 0x0F];
		}
		CopyMemory(lpszText, pszTemp, dwTextSize * 2);
		lpszText[dwTextSize * 2] = 0;
		GlobalFree(pszTemp);
	}
	else {
		dwTextSize /= 2;
		LPSTR pszTemp = (LPSTR)GlobalAlloc(0, dwTextSize);
		for (DWORD i = 0; i < dwTextSize; ++i) {
			BYTE szTemp[2] = { lpszText[i * 2], lpszText[i * 2 + 1] };
			*(pszTemp + i) = (CHAR)strtoul((LPCSTR)szTemp, NULL, 16);
		}
		CopyMemory(lpszText, pszTemp, dwTextSize);
		GlobalFree(pszTemp);
		if (!CryptDecrypt(hKey, NULL, TRUE, 0, (BYTE*)lpszText, &dwTextSize)) goto END;
		lpszText[dwTextSize] = 0;
	}
	bResult = TRUE;
END:
	if (hKey) {
		CryptDestroyKey(hKey);
		hKey = NULL;
	}
	if (hHash) {
		CryptDestroyHash(hHash);
		hHash = NULL;
	}
	if (hProv) {
		CryptReleaseContext(hProv, 0);
		hProv = NULL;
	}
	return bResult;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static HWND hButton1;
	static HWND hButton2;
	static HWND hEdit1;
	static HWND hEdit2;
	static HWND hEdit3;
	switch (msg)
	{
	case WM_CREATE:
		hButton1 = CreateWindow(TEXT("BUTTON"), TEXT("暗号化"), WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hWnd, (HMENU)1000, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hButton2 = CreateWindow(TEXT("BUTTON"), TEXT("複合化"), WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hWnd, (HMENU)1001, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hEdit1 = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT("0123456789012345"), WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, (HMENU)1002, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hEdit2 = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT("ABCDEFGEFGHIJKLM"), WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, (HMENU)1003, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hEdit3 = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT(""), WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, (HMENU)1004, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		break;
	case WM_SIZE:
		MoveWindow(hButton1, 10, 10, 256, 32, TRUE);
		MoveWindow(hButton2, 10, 50, 256, 32, TRUE);
		MoveWindow(hEdit1, 10, 90, LOWORD(lParam) - 20, 32, TRUE);
		MoveWindow(hEdit2, 10, 130, LOWORD(lParam) - 20, 32, TRUE);
		MoveWindow(hEdit3, 10, 170, LOWORD(lParam) - 20, 32, TRUE);
		break;
	case WM_COMMAND:
		if (LOWORD(wParam) == 1000) {
			const int nSize1 = GetWindowTextLengthA(hEdit1);
			LPSTR lpszPassword = (LPSTR)GlobalAlloc(0, nSize1 + 1);
			GetWindowTextA(hEdit1, lpszPassword, nSize1 + 1);
			const int nSize2 = GetWindowTextLengthA(hEdit2);
			LPSTR lpszText = (LPSTR)GlobalAlloc(0, MAX_BUFFER);
			GetWindowTextA(hEdit2, lpszText, nSize2 + 1);
			if (Crypt3Des(TRUE, (LPBYTE)lpszText, nSize2, (LPBYTE)lpszPassword, nSize1)) {
				SetWindowTextA(hEdit3, lpszText);
			}
			GlobalFree(lpszPassword);
			GlobalFree(lpszText);
		}
		else if (LOWORD(wParam) == 1001) {
			const int nSize1 = GetWindowTextLengthA(hEdit1);
			LPSTR lpszPassword = (LPSTR)GlobalAlloc(0, nSize1 + 1);
			GetWindowTextA(hEdit1, lpszPassword, nSize1 + 1);
			const int nSize3 = GetWindowTextLengthA(hEdit3);
			LPSTR lpszText = (LPSTR)GlobalAlloc(0, MAX_BUFFER);
			GetWindowTextA(hEdit3, lpszText, nSize3 + 1);
			if (Crypt3Des(FALSE, (LPBYTE)lpszText, nSize3, (LPBYTE)lpszPassword, nSize1)) {
				SetWindowTextA(hEdit2, lpszText);
			}
			GlobalFree(lpszPassword);
			GlobalFree(lpszText);
		}
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, msg, wParam, lParam);
	}
	return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPreInst, LPSTR pCmdLine, int nCmdShow)
{
	MSG msg;
	WNDCLASS wndclass = {
		CS_HREDRAW | CS_VREDRAW,
		WndProc,
		0,
		0,
		hInstance,
		0,
		LoadCursor(0,IDC_ARROW),
		(HBRUSH)(COLOR_WINDOW + 1),
		0,
		szClassName
	};
	RegisterClass(&wndclass);
	HWND hWnd = CreateWindow(
		szClassName,
		TEXT("TripleDes"),
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT,
		0,
		CW_USEDEFAULT,
		0,
		0,
		0,
		hInstance,
		0
	);
	ShowWindow(hWnd, SW_SHOWDEFAULT);
	UpdateWindow(hWnd);
	while (GetMessage(&msg, 0, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return (int)msg.wParam;
}