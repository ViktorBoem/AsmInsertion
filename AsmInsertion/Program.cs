using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;

namespace AsmInsertion
{
    internal class Program
    {
        [SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int AssemblyAddFunction(int x, int y);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        static void Main(string[] args)
        {
            var process = System.Diagnostics.Process.GetCurrentProcess();
            int returnValue;

            byte[] assembledCode =
            {
                0x55,               // push ebp            
                0x89, 0xE5,         // mov ebp, esp         
                0x8B, 0x45, 0x0C,   // mov eax, [ebp+12]    
                0x8B, 0x55, 0x08,   // mov edx, [ebp+8]     
                0x01, 0xD0,         // add eax, edx         
                0x89, 0xEC,         // mov esp, ebp         
                0x5D,               // pop ebp              
                0xC3                // ret                  
            };

            unsafe
            {
                fixed (byte* ptr = assembledCode)
                {
                    var memoryAddress = (IntPtr)ptr;

                    if (!VirtualProtectEx(process.Handle, memoryAddress, (UIntPtr)assembledCode.Length, 0x40, out uint _))
                    {
                        throw new Win32Exception();
                    }

                    var myAssemblyFunction = Marshal.GetDelegateForFunctionPointer<AssemblyAddFunction>(memoryAddress);
                    returnValue = myAssemblyFunction(2, 1);

                }
            }

            Console.WriteLine($"мій бал з АККМ: {returnValue}");
        }
    }
}
