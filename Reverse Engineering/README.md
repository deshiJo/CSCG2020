
# Reverse Engineering Challenges

## Intro to Reversing 1 

**Challenge**

This is the first reversing Challenge with the difficulty baby. We obtain the Flag from the server if we pass the right password. We also have the binary, running on the server.

**Solution**

As always try strings at first, which shows us the password immidiately in this challenge.
So the response from **"strings ./rev1"** contains the following output:
> Give me your password: 
y0u_5h3ll_p455    
Thats the right password!

Now if we running the binary and passing the password **"y0u_5h3ll_p455"**, we get the flag:
**CSCG{ez_pz_reversing_squ33zy}**

To avoid this security issue, the password could be placed on the server side (for example placed within a file) or the password comparison, within the binary, could use only the hashed password.


## Intro to Reversing 2

**Challenge**

This is the second reversing Challenge with the difficulty baby. We obtain the Flag from the server if we pass the right password. We also have the binary, running on the server.

**Solution**

This time **"strings ./rev2"** does not work for this challenge.
My second try was using **"ltrace ./rev2"** to see if the binary calls some string comparison functions. 

![](writeupfiles/ltraceRev2.png)

The string comparison seems to use an unknown encoding, so lets look into the binary with Ghidra.

![](writeupfiles/rev2Ghidra.png)

The main function contains the strcmp we saw in the ltrace output.
so our input is the variable **local_38** and **s__00100ab0** is the password we are looking for.
The memory contains a bunch of bytes which could be our password we are looking for: 
> FC,FD,EA,C0,BA,EC,E8,FD,FB,BD,F7,BE,EF,B9,FB,F6,BD,C0,BA,B9,F7,E8,F2,FD,E8,F2,FC

Not all bytes are in ascii range, so lets look a bit closer to the rest of this code.

the while loop above the strcmp adds the value -0x77 to each value of our input.
Hence, the password here is transformed with this byte substraction.

Just lets write a short python code to revert this transformation:

```
password = [0xFC,0xFD,0xEA,0xC0,0xBA,0xEC,0xE8,0xFD,0xFB,0xBD,0xF7,0xBE,0xEF,0xB9,0xFB,0xF6,0xBD,0xC0,0xBA,0xB9,0xF7,0xE8,0xF2,0xFD,0xE8,0xF2,0xFC]
result = ""
for p in password:
    p = (p+0x77)%256
    result += chr(p)
print(result)
```


Executing this script will give us the password we are looking for:
**sta71c_tr4n5f0rm4710n_it_is**

Now the last step is again passing the password to the binary on the server, using netcat and receiving the flag.
**CSCG{1s_th4t_wh4t_they_c4ll_on3way_transf0rmati0n?}**

Again, this security issue can be avoided, if the password string isn't in the binary. The password can be placed encrypted on the server.


## Intro to Reversing 3

**Challenge**

Like the two challanges before (Intro to  Reversing 1/2) we have to get a password to receive the flag from the server.

**Solution**

As alwys lets try if we get information about the programm using **strings** and **ltrace**.
**ltrace** shows us that we have a string comparison again, but it looks like the password is encrypted this time.

> lp`7a<qLw\x1ekHopt(f-f*,o}V\x0f\x15J

We can check this by opening ghidra and look at the decompiled code for the main method.
The main method contains again a transformation. This time the program take each char and calculating:
> (inputChar ^ (CharIndex - 10)) - 2

We can calculate the password by coping the string from the **ltrace** string comparison 

> lp`7a<qLw\x1ekHopt(f-f*,o}V\x0f\x15J

and revert the transformation with the following python script:

```
import os

password_encrypted = "lp`7a<qLw\x1ekHopt(f-f*,o}V\x0f\x15J"
password_decrypted = ""
for i in range(0, len(password_encrypted)):
    currentChar = ord(password_encrypted[i])
    currentChar += 2
    currentChar ^= (i+10)
    password_decrypted += chr(currentChar)
print(password_decrypted)
os.system("echo \"{}\" | nc hax1.allesctf.net 9602".format(password_decrypted))
```

Running this script results in the following output:

```
dyn4m1c_k3y_gen3r4t10n_y34h
Give me your password: 
Thats the right password!
Flag: CSCG{pass_1_g3ts_a_x0r_p4ss_2_g3ts_a_x0r_EVERYBODY_GETS_A_X0R}
```

Again, this security issue can be avoided, if the password string isn't in the binary. The password can be placed encrypted on the server.



## reme Part 1

**Challenge**

.NET Reversing can't be that hard, right? But I've got some twists waiting for you 😈

Execute with .NET Core Runtime 2.2 with windows, e.g. dotnet ReMe.dll

**Solution**

We get the files: **ReMe.dll, ReMe.deps.json and ReMe.runtimeconfig.json**.

The dotnet decompiler **ilspy** can be used to decompile **ReMe.dll** (file decompiledReme.cs in the appendix).
One of the interesting parts is a string decryption, which seems to decrypt the first flag:
```
private static void InitialCheck(string[] args)
		{
			Initialize();
			if (Debugger.IsAttached)
			{
				Console.WriteLine("Nope");
				Environment.Exit(-1);
			}
			bool isDebuggerPresent = true;
			CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
			if (isDebuggerPresent)
			{
				Console.WriteLine("Nope");
				Environment.Exit(-1);
			}
			if (IsDebuggerPresent())
			{
				Console.WriteLine("Nope");
				Environment.Exit(-1);
			}
			if (args.Length == 0)
			{
				Console.WriteLine("Usage: ReMe.exe [password] [flag]");
				Environment.Exit(-1);
			}
			if (args[0] != StringEncryption.Decrypt("D/T9XRgUcKDjgXEldEzeEsVjIcqUTl7047pPaw7DZ9I="))
			{
				Console.WriteLine("Nope");
				Environment.Exit(-1);
			}
			else
			{
				Console.WriteLine("There you go. Thats the first of the two flags! CSCG{{{0}}}", args[0]);
			}
			IntPtr moduleHandle = GetModuleHandle("kernel32.dll");
			if (moduleHandle != IntPtr.Zero)
			{
				IntPtr procAddress = GetProcAddress(moduleHandle, "CheckRemoteDebuggerPresent");
				if (Marshal.ReadByte(procAddress) == 233)
				{
					Console.WriteLine("Nope!");
					Environment.Exit(-1);
				}
			}
		}

```
The result from **StringEncryption.Decrypt("D/T9XRgUcKDjgXEldEzeEsVjIcqUTl7047pPaw7DZ9I="))** is compared with the first programm argument. If we pass the correct string, the flag will be printed on the console **Console.WriteLine("There you go. Thats the first of the two flags! CSCG{{{0}}}", args[0]);**.
The code also contains the encryption and decryption function. If we copy the parts we need and executes the encryption method, we get the flag, without running the whole program.
We can write a new c# file, which contains a main method, calling **StringEncryption.Decrypt("D/T9XRgUcKDjgXEldEzeEsVjIcqUTl7047pPaw7DZ9I="))**, and the decryption method:


```
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Text;

 
    
    public static class StringEncryption
	{
		public static void Main(string[] args){
			Console.WriteLine(StringEncryption.Decrypt("D/T9XRgUcKDjgXEldEzeEsVjIcqUTl7047pPaw7DZ9I="));
    	}
		

		public static string Decrypt(string cipherText)
		{
			string password = "A_Wise_Man_Once_Told_Me_Obfuscation_Is_Useless_Anyway";
			cipherText = cipherText.Replace(" ", "+");
			byte[] array = Convert.FromBase64String(cipherText);
			using (Aes aes = Aes.Create())
			{
				Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, new byte[13]
				{
					73,
					118,
					97,
					110,
					32,
					77,
					101,
					100,
					118,
					101,
					100,
					101,
					118
				});
				aes.Key = rfc2898DeriveBytes.GetBytes(32);
				aes.IV = rfc2898DeriveBytes.GetBytes(16);
				using (MemoryStream memoryStream = new MemoryStream())
				{
					using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
					{
						cryptoStream.Write(array, 0, array.Length);
						cryptoStream.Close();
					}
					cipherText = Encoding.Unicode.GetString(memoryStream.ToArray());
				}
			}
			return cipherText;
		}
	}

```
Now if we run this programm, we get the flag content **CanIHazFlag?**.

Flag: **CSCG{CanIHazFlag?}**

The security issue here is that the password/key for the encryption is hardcoded in the programm code. Even if the programm uses a secure encyption like aes, we can easily decrypt the flag because of know the key. Thus the encryption is pretty useless at this point. The encryption key should not be in the programm code.


## reme Part 2

**Challenge**

.NET Reversing can't be that hard, right? But I've got some twists waiting for you 😈

Execute with .NET Core Runtime 2.2 with windows, e.g. dotnet ReMe.dll

**Solution**

We get the files: **ReMe.dll, ReMe.deps.json and ReMe.runtimeconfig.json**.

The dotnet decompiler **ilspy** can be used to decompile **ReMe.dll** (file decompiledReme.cs in the appendix).
The second flag was a bit harder to find, so lets look at the code more presice (see decompiledReme.cs).
The Program starts with the main method. At first it calls an initialization method. This method is hardly readable so put this aside for now.
The rest of the main method seems to be interesting:
1. the intermediate Language representation of the Method "InitialCheck" is loaded as a byte array.
2. the whole dll executable is loaded into a second byte array called "array".
3. the String "THIS_IS_CSCG_NOT_A_MALWARE!" is located in the bytearray "array".
4. a memory Stream starting at the byte behind "THIS_IS_CSCG_NOT_A_MALWARE!" is generated and a third byte array of the length of this stream is generated. 
5. the content of the memory stream is decrypted with aes, while the bytes of the method "InitialCheck" are used as the encryption key. 
6. The decrypted result is now loaded as a method "check".

```
private static void Main(string[] args)
		{
			InitialCheck(args);
			byte[] iLAsByteArray = typeof(Program).GetMethod("InitialCheck", BindingFlags.Static | BindingFlags.NonPublic).GetMethodBody().GetILAsByteArray(); //get Intermediate language of "InitialCheck" as Byte Array
			byte[] array = File.ReadAllBytes(Assembly.GetExecutingAssembly().Location); //Read all bytes of the currently loaded executable -> array all Bytes 
			int[] array2 = array.Locate(Encoding.ASCII.GetBytes("THIS_IS_CSCG_NOT_A_MALWARE!"));//locate the String "This_is_..." in the memory of this executable and store the bytes in array2
			MemoryStream memoryStream = new MemoryStream(array); //create a non-resizable instance of a memory stream based on the bytes of the executable
			memoryStream.Seek(array2[0] + Encoding.ASCII.GetBytes("THIS_IS_CSCG_NOT_A_MALWARE!").Length, SeekOrigin.Begin); //set the position of memory stream to byte after the String "THIS_IS_CSCG..."
			byte[] array3 = new byte[memoryStream.Length - memoryStream.Position]; //create new array of size of bytes after "THIS_IS_CSCG..." String and the end
			memoryStream.Read(array3, 0, array3.Length);//read bytes of array3 
			byte[] rawAssembly = AES_Decrypt(array3, iLAsByteArray); //decrypt array3 with the bytes of InitialCheck 
			object obj = Assembly.Load(rawAssembly).GetTypes()[0].GetMethod("Check", BindingFlags.Static | BindingFlags.Public).Invoke(null, new object[1]
			{
				args
			});
		}
```

So we have a hidden and encrypted method in the program itself. The main method loads bytes after a string **"THIS\_IS\_CSCG..."** and decrypts these bytes.
We can again write our own c# programm to get this hidden and encrypted program. We just have to copy the main method (and the necessary program parts) and write the result of the decryption **byte[] rawAssembly = AES_Decrypt(array3, iLAsByteArray); //decrypt array3 with the bytes of InitialCheck** to a file **output.exe**:

```
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Text;

namespace decrypt{
    internal static class ByteArrayRocks
	{
		private static readonly int[] Empty = new int[0];

		public static int[] Locate(this byte[] self, byte[] candidate)
		{
			if (IsEmptyLocate(self, candidate))
			{
				return Empty;
			}
			List<int> list = new List<int>();
			for (int i = 0; i < self.Length; i++)
			{
				if (IsMatch(self, i, candidate))
				{
					list.Add(i);
				}
			}
			return (list.Count == 0) ? Empty : list.ToArray();
		}

		private static bool IsMatch(byte[] array, int position, byte[] candidate)
		{
			if (candidate.Length > array.Length - position)
			{
				return false;
			}
			for (int i = 0; i < candidate.Length; i++)
			{
				if (array[position + i] != candidate[i])
				{
					return false;
				}
			}
			return true;
		}

		private static bool IsEmptyLocate(byte[] array, byte[] candidate)
		{
			return array == null || candidate == null || array.Length == 0 || candidate.Length == 0 || candidate.Length > array.Length;
		}
	}
    class Program {

            private static void Main(string[] args)
            {
    //			InitialCheck(args);
                Assembly dll = Assembly.LoadFile("/home/joachim/Schreibtisch/CTF/2020/CSCG/Reversing/Reme/ReMe.dll");
                //test c# methods
                //foreach(Type type in dll.GetTypes() {
                    //MethodInfo[] methodJ = type.GetMethods(); 
                    //foreach(MethodInfo i in methodJ) {
                       //Console.WriteLine(i); 
                    //}
                //}
                //Console.WriteLine(dll.GetType("ReMe.Program"));
                MethodInfo[] methodJ2 = dll.GetType("ReMe.Program").GetMethods(BindingFlags.Static | BindingFlags.NonPublic); 
                    foreach(MethodInfo i in methodJ2) {
                        //print all methods in class Program
                       //Console.WriteLine(i); 
                    }
                byte[] iLAsByteArray = dll.GetType("ReMe.Program").GetMethod("InitialCheck", BindingFlags.Static | BindingFlags.NonPublic).GetMethodBody().GetILAsByteArray();
                //byte[] iLAsByteArray = typeof(Program).GetMethod("InitialCheck", BindingFlags.Static | BindingFlags.NonPublic).GetMethodBody().GetILAsByteArray(); //get Intermediate language of "InitialCheck" as Byte Array

                byte[] array = File.ReadAllBytes("/home/joachim/Schreibtisch/CTF/2020/CSCG/Reversing/Reme/ReMe.dll"); //Read all bytes of the currently loaded executable -> array all Bytes 
                //Console.WriteLine(Encoding.Default.GetString(array));
                int[] array2 = array.Locate(Encoding.ASCII.GetBytes("THIS_IS_CSCG_NOT_A_MALWARE!"));//locate the String "This_is_..." in the memory of this executable and store the bytes in array2
                MemoryStream memoryStream = new MemoryStream(array); //create a non-resizable instance of a memory stream based on the bytes of the executable
                memoryStream.Seek(array2[0] + Encoding.ASCII.GetBytes("THIS_IS_CSCG_NOT_A_MALWARE!").Length, SeekOrigin.Begin); //set the position of memory stream to byte after the String "THIS_IS_CSCG..."
                byte[] array3 = new byte[memoryStream.Length - memoryStream.Position]; //create new array of size of bytes after "THIS_IS_CSCG..." String and the end
                memoryStream.Read(array3, 0, array3.Length);//read bytes of array3 
                byte[] rawAssembly = AES_Decrypt(array3, iLAsByteArray); //decrypt array3 with the bytes of InitialCheck 
                File.WriteAllBytes("output.exe", rawAssembly);
                Console.WriteLine(Encoding.Default.GetString(rawAssembly));
                Console.WriteLine(Assembly.Load(rawAssembly).GetTypes()[0].GetMethod("Check",BindingFlags.Static | BindingFlags.Public).GetMethodBody());
                object obj = Assembly.Load(rawAssembly).GetTypes()[0].GetMethod("Check", BindingFlags.Static | BindingFlags.Public).Invoke(null, new object[1]
                {
                	args
                });
            }

		public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
		{
			byte[] result = null;
			byte[] salt = new byte[8]
			{
				1,
				2,
				3,
				4,
				5,
				6,
				7,
				8
			};
			using (MemoryStream memoryStream = new MemoryStream())
			{
				using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
				{
					rijndaelManaged.KeySize = 256;
					rijndaelManaged.BlockSize = 128;
					Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passwordBytes, salt, 1000);
					rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
					rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
					rijndaelManaged.Mode = CipherMode.CBC;
					using (CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndaelManaged.CreateDecryptor(), CryptoStreamMode.Write))
					{
						cryptoStream.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
						cryptoStream.Close();
					}
					result = memoryStream.ToArray();
				}
			}
			return result;
		}

    }
}
```

Now lets take a look into the programm code, by using **ilspy** to decompile the extracted file:

```
using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Text;

[assembly: CompilationRelaxations(8)]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default | DebuggableAttribute.DebuggingModes.DisableOptimizations | DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints | DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
[assembly: TargetFramework(".NETStandard,Version=v2.0", FrameworkDisplayName = "")]
[assembly: AssemblyCompany("ReMe_Inner")]
[assembly: AssemblyConfiguration("Debug")]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: AssemblyInformationalVersion("1.0.0")]
[assembly: AssemblyProduct("ReMe_Inner")]
[assembly: AssemblyTitle("ReMe_Inner")]
[assembly: SecurityPermission(SecurityAction.RequestMinimum, SkipVerification = true)]
[assembly: AssemblyVersion("1.0.0.0")]
[module: UnverifiableCode]
namespace ReMe_Inner
{
	public class Inner
	{
		public static void Check(string[] args)
		{
			if (args.Length <= 1)
			{
				Console.WriteLine("Nope.");
			}
			else
			{
				string[] array = args[1].Split(new string[1]
				{
					"_"
				}, StringSplitOptions.RemoveEmptyEntries);
				if (array.Length != 8)
				{
					Console.WriteLine("Nope.");
				}
				else if ("CSCG{" + array[0] == "CSCG{n0w" && array[1] == "u" && array[2] == "know" && array[3] == "st4t1c" && array[4] == "and" && CalculateMD5Hash(array[5]).ToLower() == "b72f3bd391ba731a35708bfd8cd8a68f" && array[6] == "dotNet" && array[7] + "}" == "R3333}")
				{
					Console.WriteLine("Good job :)");
				}
			}
		}

		public static string CalculateMD5Hash(string input)
		{
			MD5 mD = MD5.Create();
			byte[] bytes = Encoding.ASCII.GetBytes(input);
			byte[] array = mD.ComputeHash(bytes);
			StringBuilder stringBuilder = new StringBuilder();
			for (int i = 0; i < array.Length; i++)
			{
				stringBuilder.Append(array[i].ToString("X2"));
			}
			return stringBuilder.ToString();
		}
	}
}
```
We can already read a part from the flag from the following lines 
```
else if ("CSCG{" + array[0] == "CSCG{n0w" && array[1] == "u" && array[2] == "know" && array[3] == "st4t1c" && array[4] == "and" && CalculateMD5Hash(array[5]).ToLower() == "b72f3bd391ba731a35708bfd8cd8a68f" && array[6] == "dotNet" && array[7] + "}" == "R3333}")
```

> CSCG{n0w\_u\_know\_st4t1c\_and_\<Something>\_dotNet\_R3333}

the last step is to break the md5 hash with an onlinetool (i.e "https://www.md5online.org/")

> b72f3bd391ba731a35708bfd8cd8a68f : dynamic 

Flag : **CSCG{n0w_u_know_st4t1c_and_dynamic_dotNet_R3333}**
