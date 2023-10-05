using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Injector
{
    internal class Injector
    {
        public static string Userchoice { get; private set; }

        // Define constants and methods for manual map injection.
        private const uint PROCESS_CREATE_THREAD = 0x0002;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_OPERATION = 0x0008;
        private const uint PROCESS_VM_WRITE = 0x0020;
        private const uint PROCESS_VM_READ = 0x0010;

        private const uint MEM_COMMIT = 0x00001000;
        private const uint MEM_RESERVE = 0x00002000;
        private const uint MEM_RELEASE = 0x00008000;
        private const uint PAGE_READWRITE = 0x04;

        // Import necessary functions from kernel32.dll for DLL injection.
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        // Import necessary functions from user32.dll for SetWindowsHookEx.
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        // Import necessary functions from kernel32.dll for QueueUserAPC injection.
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, UIntPtr dwData);

        // Define a delegate type for the hook procedure.
        private delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);

        // Define a delegate for the APC function.
        private delegate void APCProc();

        // Define thread access rights.
        [Flags]
        private enum ThreadAccess : uint
        {
            THREAD_TERMINATE = 0x0001,
            THREAD_SUSPEND_RESUME = 0x0002,
            THREAD_GET_CONTEXT = 0x0008,
            THREAD_SET_CONTEXT = 0x0010,
            THREAD_SET_INFORMATION = 0x0020,
            THREAD_QUERY_INFORMATION = 0x0040,
            THREAD_SET_THREAD_TOKEN = 0x0080,
            THREAD_IMPERSONATE = 0x0100,
            THREAD_DIRECT_IMPERSONATION = 0x0200,
            THREAD_SET_LIMITED_INFORMATION = 0x0400,
            THREAD_QUERY_LIMITED_INFORMATION = 0x0800,
            THREAD_ALL_ACCESS = 0x1F03FF
        }

        // Define a simple function to perform manual map injection into a process by name.
        private static bool ManualMapInjectByName(string processName, string dllPath)
        {
            Process[] processes = Process.GetProcessesByName(processName);

            if (processes.Length == 0)
            {
                Console.WriteLine($"No process with the name '{processName}' found.");
                return false;
            }

            foreach (Process process in processes)
            {
                IntPtr processHandle = IntPtr.Zero;
                IntPtr loadLibraryAddr = IntPtr.Zero;

                try
                {
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.WriteLine($"Injecting into process with ID: {process.Id}");
                    Console.ResetColor();

                    // Open the target process with appropriate permissions.
                    processHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, process.Id);
                    if (processHandle == IntPtr.Zero)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"Failed to open process with ID {process.Id}");
                        Console.ResetColor();
                        return false;
                    }

                    // Allocate memory for the DLL path in the target process.
                    IntPtr remoteMem = VirtualAllocEx(processHandle, IntPtr.Zero, (uint)dllPath.Length + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (remoteMem == IntPtr.Zero)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to allocate memory in the target process.");
                        Console.ResetColor();
                        return false;
                    }

                    // Write the DLL path to the allocated memory.
                    byte[] dllPathBytes = Encoding.ASCII.GetBytes(dllPath);
                    int bytesWritten;
                    if (!WriteProcessMemory(processHandle, remoteMem, dllPathBytes, (uint)dllPathBytes.Length, out bytesWritten))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to write DLL path to target process.");
                        Console.ResetColor();
                        return false;
                    }

                    // Get the address of the LoadLibrary function in the target process.
                    loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

                    if (loadLibraryAddr == IntPtr.Zero)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to get the address of LoadLibrary.");
                        Console.ResetColor();
                        return false;
                    }

                    // Create a remote thread to call LoadLibrary with the path to the injected DLL.
                    IntPtr threadId;
                    IntPtr hThread = CreateRemoteThread(processHandle, IntPtr.Zero, 0, loadLibraryAddr, remoteMem, 0, out threadId);

                    if (hThread == IntPtr.Zero)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to create remote thread.");
                        Console.ResetColor();
                        return false;
                    }

                    // Wait for the remote thread to finish.
                    WaitForSingleObject(hThread, 0xFFFFFFFF);

                    // Cleanup and close the handles.
                    CloseHandle(hThread);
                    VirtualFreeEx(processHandle, remoteMem, 0, MEM_RELEASE);
                    CloseHandle(processHandle);

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("Injection completed.");
                    Console.ResetColor();
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Error injecting into process with ID {process.Id}: {ex.Message}");
                    Console.ResetColor();
                }
            }

            return true;
        }

        // Define a function to perform LoadLibrary injection into a process by name.
        private static bool LoadLibraryInjectByName(string processName, string dllPath)
        {
            Process[] processes = Process.GetProcessesByName(processName);

            if (processes.Length == 0)
            {
                Console.WriteLine($"No process with the name '{processName}' found.");
                return false;
            }

            foreach (Process process in processes)
            {
                IntPtr processHandle = IntPtr.Zero;
                IntPtr loadLibraryAddr = IntPtr.Zero;

                try
                {
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.WriteLine($"Injecting into process with ID: {process.Id}");
                    Console.ResetColor();

                    // Open the target process with appropriate permissions.
                    processHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, process.Id);
                    if (processHandle == IntPtr.Zero)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"Failed to open process with ID {process.Id}");
                        Console.ResetColor();
                        return false;
                    }

                    // Get the address of the LoadLibrary function in the target process.
                    loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

                    if (loadLibraryAddr == IntPtr.Zero)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to get the address of LoadLibrary.");
                        Console.ResetColor();
                        return false;
                    }

                    // Allocate memory for the DLL path in the target process.
                    IntPtr remoteMem = VirtualAllocEx(processHandle, IntPtr.Zero, (uint)dllPath.Length + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (remoteMem == IntPtr.Zero)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to allocate memory in the target process.");
                        Console.ResetColor();
                        return false;
                    }

                    // Write the DLL path to the allocated memory.
                    byte[] dllPathBytes = Encoding.ASCII.GetBytes(dllPath);
                    int bytesWritten;
                    if (!WriteProcessMemory(processHandle, remoteMem, dllPathBytes, (uint)dllPathBytes.Length, out bytesWritten))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to write DLL path to target process.");
                        Console.ResetColor();
                        return false;
                    }

                    // Create a remote thread to call LoadLibrary with the path to the injected DLL.
                    IntPtr threadId;
                    IntPtr hThread = CreateRemoteThread(processHandle, IntPtr.Zero, 0, loadLibraryAddr, remoteMem, 0, out threadId);

                    if (hThread == IntPtr.Zero)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to create remote thread.");
                        Console.ResetColor();
                        return false;
                    }

                    // Wait for the remote thread to finish.
                    WaitForSingleObject(hThread, 0xFFFFFFFF);

                    // Cleanup and close the handles.
                    CloseHandle(hThread);
                    VirtualFreeEx(processHandle, remoteMem, 0, MEM_RELEASE);
                    CloseHandle(processHandle);

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("Injection completed.");
                    Console.ResetColor();
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Error injecting into process with ID {process.Id}: {ex.Message}");
                    Console.ResetColor();
                }
            }

            return true;
        }

        // Define a function to perform SetWindowsHookEx injection into a process by name.
        private static bool SetWindowsHookExInjectByName(string processName, string dllPath)
        {
            Process[] processes = Process.GetProcessesByName(processName);

            if (processes.Length == 0)
            {
                Console.WriteLine($"No process with the name '{processName}' found.");
                return false;
            }

            foreach (Process process in processes)
            {
                IntPtr processHandle = IntPtr.Zero;
                IntPtr remoteMem = IntPtr.Zero;
                IntPtr hHook = IntPtr.Zero;

                try
                {
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.WriteLine($"Injecting into process with ID: {process.Id}");
                    Console.ResetColor();

                    // Open the target process with appropriate permissions.
                    processHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, process.Id);
                    if (processHandle == IntPtr.Zero)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"Failed to open process with ID {process.Id}");
                        Console.ResetColor();
                        return false;
                    }

                    // Allocate memory for the DLL path in the target process.
                    remoteMem = VirtualAllocEx(processHandle, IntPtr.Zero, (uint)dllPath.Length + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (remoteMem == IntPtr.Zero)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to allocate memory in the target process.");
                        Console.ResetColor();
                        return false;
                    }

                    // Write the DLL path to the allocated memory.
                    byte[] dllPathBytes = Encoding.ASCII.GetBytes(dllPath);
                    int bytesWritten;
                    if (!WriteProcessMemory(processHandle, remoteMem, dllPathBytes, (uint)dllPathBytes.Length, out bytesWritten))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to write DLL path to target process.");
                        Console.ResetColor();
                        return false;
                    }

                    // Load the user32.dll module in the target process.
                    IntPtr user32Module = GetModuleHandle("user32.dll");
                    if (user32Module == IntPtr.Zero)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to get the user32.dll module handle.");
                        Console.ResetColor();
                        return false;
                    }

                    // Get the address of the SetWindowsHookEx function.
                    IntPtr setHookAddr = GetProcAddress(user32Module, "SetWindowsHookExA");
                    if (setHookAddr == IntPtr.Zero)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to get the address of SetWindowsHookEx.");
                        Console.ResetColor();
                        return false;
                    }

                    // Create a remote thread to call SetWindowsHookEx with the path to the injected DLL.
                    IntPtr threadId;
                    IntPtr hThread = CreateRemoteThread(processHandle, IntPtr.Zero, 0, setHookAddr, remoteMem, 0, out threadId);

                    if (hThread == IntPtr.Zero)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to create remote thread.");
                        Console.ResetColor();
                        return false;
                    }

                    // Wait for the remote thread to finish.
                    WaitForSingleObject(hThread, 0xFFFFFFFF);

                    // Get the hook handle returned by SetWindowsHookEx.
                    IntPtr hookHandle = Marshal.ReadIntPtr(remoteMem);

                    // Cleanup and close the handles.
                    CloseHandle(hThread);
                    VirtualFreeEx(processHandle, remoteMem, 0, MEM_RELEASE);
                    CloseHandle(processHandle);

                    if (hookHandle == IntPtr.Zero)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("SetWindowsHookEx failed to create the hook.");
                        Console.ResetColor();
                        return false;
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("Injection completed.");
                        Console.ResetColor();
                    }
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Error injecting into process with ID {process.Id}: {ex.Message}");
                    Console.ResetColor();
                }
            }

            return true;
        }

        // Define a function to perform QueueUserAPC injection into a process by name.
        private static bool QueueUserAPCInjectByName(string processName, string dllPath)
        {
            Process[] processes = Process.GetProcessesByName(processName);

            if (processes.Length == 0)
            {
                Console.WriteLine($"No process with the name '{processName}' found.");
                return false;
            }

            foreach (Process process in processes)
            {
                IntPtr processHandle = IntPtr.Zero;
                IntPtr loadLibraryAddr = IntPtr.Zero;

                try
                {
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.WriteLine($"Injecting into process with ID: {process.Id}");
                    Console.ResetColor();

                    // Open the target process with appropriate permissions.
                    processHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, process.Id);
                    if (processHandle == IntPtr.Zero)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"Failed to open process with ID {process.Id}");
                        Console.ResetColor();
                        return false;
                    }

                    // Get the address of the LoadLibrary function in the target process.
                    loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

                    if (loadLibraryAddr == IntPtr.Zero)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to get the address of LoadLibrary.");
                        Console.ResetColor();
                        return false;
                    }

                    // Allocate memory for the DLL path in the target process.
                    IntPtr remoteMem = VirtualAllocEx(processHandle, IntPtr.Zero, (uint)dllPath.Length + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (remoteMem == IntPtr.Zero)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to allocate memory in the target process.");
                        Console.ResetColor();
                        return false;
                    }

                    // Write the DLL path to the allocated memory.
                    byte[] dllPathBytes = Encoding.ASCII.GetBytes(dllPath);
                    int bytesWritten;
                    if (!WriteProcessMemory(processHandle, remoteMem, dllPathBytes, (uint)dllPathBytes.Length, out bytesWritten))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to write DLL path to target process.");
                        Console.ResetColor();
                        return false;
                    }

                    // Create a remote thread to call LoadLibrary with the path to the injected DLL.
                    IntPtr threadId;
                    IntPtr hThread = CreateRemoteThread(processHandle, IntPtr.Zero, 0, loadLibraryAddr, remoteMem, 0, out threadId);

                    if (hThread == IntPtr.Zero)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to create remote thread.");
                        Console.ResetColor();
                        return false;
                    }

                    // Wait for the remote thread to finish.
                    WaitForSingleObject(hThread, 0xFFFFFFFF);

                    // Cleanup and close the handles.
                    CloseHandle(hThread);
                    VirtualFreeEx(processHandle, remoteMem, 0, MEM_RELEASE);
                    CloseHandle(processHandle);

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("Injection completed.");
                    Console.ResetColor();
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Error injecting into process with ID {process.Id}: {ex.Message}");
                    Console.ResetColor();
                }
            }

            return true;
        }

        static void Main(string[] args)
        {
            Console.Title = "Light Injector v1.0.0 | ";
            // Set console colors for the interface.
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("Welcome USER, you are using Light Injector v1\n");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Please select an option from the menu below\n");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Gray;

            // Display the menu options to the user.
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("Select an injection method:\n");
            Console.ResetColor();
            Console.WriteLine("1 - | - Manual Map\n");
            Console.WriteLine("2 - | - LoadLibrary\n");
            Console.WriteLine("3 - | - SetWindowsHookEx (may give errors)\n");
            Console.WriteLine("4 - | - QueueUserAPC\n");

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Enter your choice: ");
            Console.ResetColor();

            // Read the user's choice.
            Userchoice = Console.ReadLine();

            // Check if the user's choice is valid and proceed with injection.
            if (Userchoice == "1" || Userchoice == "2" || Userchoice == "3" || Userchoice == "4")
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"\nYou chose option: {Userchoice}\n");
                Console.ResetColor();

                // Initialize target process name and DLL path.
                string targetProcessName = string.Empty;
                string targetdllPath = string.Empty;

                // Ask the user for the target process name until a valid name is provided.
                while (string.IsNullOrEmpty(targetProcessName))
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write("Enter the name of the target process: ");
                    Console.ResetColor();
                    targetProcessName = Console.ReadLine();
                }

                // Ask the user for the DLL path until a valid path is provided.
                while (string.IsNullOrEmpty(targetdllPath))
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write("Enter the path to the DLL to inject: ");
                    Console.ResetColor();
                    targetdllPath = Console.ReadLine();
                    Console.Title = "Light Injector v1.0.0 | " + targetProcessName + " | ";
                }

                // Perform injection into the specified process by name based on the user's choice.
                switch (Userchoice)
                {
                    case "1":
                        ManualMapInjectByName(targetProcessName, targetdllPath);
                        break;
                    case "2":
                        LoadLibraryInjectByName(targetProcessName, targetdllPath);
                        break;
                    case "3":
                        SetWindowsHookExInjectByName(targetProcessName, targetdllPath);
                        break;
                    case "4":
                        QueueUserAPCInjectByName(targetProcessName, targetdllPath);
                        break;
                    default:
                        Console.WriteLine("Invalid choice.");
                        break;
                }
            }
            else
            {
                Console.WriteLine("\nInvalid choice.");
            }

            Console.ReadLine();
        }
    }
}
