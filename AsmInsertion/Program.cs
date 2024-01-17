using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;

namespace AsmInsertion
{
    internal class Program
    {
        // Відключення перевірки безпеки пам'яті CLR при виклику некерованого коду
        [SuppressUnmanagedCodeSecurity]
        // Атрибут для делегатів, які вказують на некеровані функції, прописує "C" декларацію
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        // Делегат для виклику функції з некерованим асемблерним кодом
        private delegate int AssemblyAddFunction(int x, int y);

        // Вказує, що функція "VirtualProtectEx" імпортується з "kernel32.dll"
        // та змінює параметри доступу до віртуальної пам'яті певного процесу
        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        static void Main(string[] args)
        {
            // отримуємо об'єкт, що представляє поточний процес
            var process = System.Diagnostics.Process.GetCurrentProcess();
            // зміння для збереження результату асемблерної функції
            int returnValue;


            // масиву байтів, що містить асемблерний код
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


            // дозволяє використовувати "небезпечний" код, вказівники як у C/С++
            unsafe
            {
                // фіксація байт масиву у пам'яті, щоб збирач сміття його не перемістив
                fixed (byte* ptr = assembledCode)
                {
                    // приведення до керованого вказівника
                    var memoryAddress = (IntPtr)ptr;

                    // зміна атрибуту ділянки пам'яті, яка виділені під "memoryAddress" на читання та запис
                    if (!VirtualProtectEx(process.Handle, memoryAddress, (UIntPtr)assembledCode.Length, 0x40, out uint _))
                    {
                        // в разі не успішної зміни атрибутів генерується вийняток
                        throw new Win32Exception();
                    }

                    //сторюється кероване прдеставлення асемблерної функції, отриманням делегату який на неї вказує
                    var myAssemblyFunction = Marshal.GetDelegateForFunctionPointer<AssemblyAddFunction>(memoryAddress);
                    //виклик асемблерної функції
                    returnValue = myAssemblyFunction(2, 1);

                }
            }

            //вивід результату виконання асемблерної функції
            Console.WriteLine($"мій бал з АККМ: {returnValue}");
        }
    }
}
