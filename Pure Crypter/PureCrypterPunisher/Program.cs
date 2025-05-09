using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.IO;
using System.Linq;
using System.Reflection.Emit;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using dnlib.DotNet.Writer;
using dnlib.DotNet;
using ProtoBuf;

namespace PureCrypterPunisher
{
    class Program
    {
        static string stringDecryptMethodType = "";
        static string stringDecryptMethodName = "";
        static string protobufsType = "";
        static string mainMethodType = "";
        static string mainMethodName = "";
        static string getResourceMethodType = "";
        static string getResourceMethodName = "";
        static string decryptResourceMethodType = "";
        static string decryptResourceMethodName = "";
        static string getPayloadMethodType = "";
        static string getPayloadMethodName = "";
        static MethodInfo decryptPayloadMethod = null;
        static MethodDef targetMethod = null;
        static string configResults = "";

        private static void ParsePureCrypterPayload(ModuleDefMD mod)
        {
            foreach (var type in mod.GetTypes())
            {
                foreach (MethodDef method in type.Methods)
                {
                    // Skip methods without bodies
                    if (!method.HasBody)
                        continue;


                    for (int i = 0; i < method.Body.Instructions.Count - 8; i++)
                    {
                        // Match the decrypt method
                        if (MatchesDecryptMethodPattern(method.Body.Instructions, i))
                        {
                            stringDecryptMethodType = method.DeclaringType.FullName;
                            stringDecryptMethodName = method.Name;
                        }

                        // Match the main method and set the protobufs message type/name
                        bool success = ProcessMainMethod(method.Body.Instructions, i);
                        if (success)
                        {
                            Console.WriteLine("Profobufs deserialization type name: " + protobufsType);
                            mainMethodType = method.DeclaringType.FullName;
                            mainMethodName = method.Name;
                            Console.WriteLine("PureCrypter Entrypoint: " + mainMethodType + "." + mainMethodName);
                            Console.WriteLine("Get resource method name: " + getResourceMethodType + "." + getResourceMethodName);
                            Console.WriteLine("Decrypt resource method name: " + decryptResourceMethodType + "." + decryptResourceMethodName);
                        }

                        bool foundPayloadMethod = MatchPayloadMethod(method.Body.Instructions, i);
                        if (foundPayloadMethod)
                        {
                            getPayloadMethodType = method.DeclaringType.FullName;
                            getPayloadMethodName = method.Name;
                            Console.WriteLine("Payload download/extract method name: " + getPayloadMethodType + "." + getPayloadMethodName);
                        }

                    }

                }
            }
        }

        private static void ExtractConfig(string payloadsDir, Assembly assembly)
        {
            var resourceType = assembly.GetTypes()
                .FirstOrDefault(t => t.FullName == getResourceMethodType);

            if (resourceType == null)
            {
                throw new Exception("Resource type not found.");
            }

            var getMethod = resourceType.GetMethods(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public)
                .FirstOrDefault(m => m.Name == getResourceMethodName);

            if (getMethod == null)
            {
                throw new Exception("Get resource method not found.");
            }
            // Invoke the method to get the byte array
            var encryptedBytes = (byte[])getMethod.Invoke(null, null);

            if (encryptedBytes == null)
            {
                throw new Exception("Failed to acquire encrypted bytes.");
            }

            // Now find the type and method that processes it
            var decryptMethodType = assembly.GetTypes()
                .FirstOrDefault(t => t.FullName == decryptResourceMethodType);

            var decryptMethod = decryptMethodType.GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public)
                 .FirstOrDefault(m => m.Name == decryptResourceMethodName);

            if (decryptMethod == null)
            {
                throw new Exception("Decrypt method not found.");
            }

            decryptPayloadMethod = decryptMethod;

            // Invoke the decrypt method with the byte array
            byte[] partiallyDecryptedByteArray = (byte[])decryptMethod.Invoke(null, new object[] { encryptedBytes });
            byte[] decryptedByteArray = Decompress(partiallyDecryptedByteArray);
            Type messageType = assembly.GetType(protobufsType);

            object deserialized;
            using (MemoryStream memoryStream = new MemoryStream(decryptedByteArray))
            {
                deserialized = ProtoBuf.Serializer.NonGeneric.Deserialize(messageType, memoryStream);
            }

            HandleObjectProperties(payloadsDir, deserialized, 0);
        }


        private static bool ProcessMainMethod(IList<dnlib.DotNet.Emit.Instruction> instrs, int index)
        {
            try
            {
                if (
                    instrs[index + 0].OpCode == dnlib.DotNet.Emit.OpCodes.Call &&
                    instrs[index + 0].Operand is IMethod method0 &&

                    instrs[index + 1].OpCode == dnlib.DotNet.Emit.OpCodes.Call &&
                    instrs[index + 1].Operand is IMethod method1 &&
                    method1.MethodSig.Params.Count == 1 &&
                    method1.MethodSig.Params[0].FullName == "System.Byte[]" &&
                    method1.MethodSig.RetType.FullName == "System.Byte[]" &&

                    instrs[index + 2].OpCode == dnlib.DotNet.Emit.OpCodes.Stloc_S &&
                    instrs[index + 3].OpCode == dnlib.DotNet.Emit.OpCodes.Ldloc_S &&

                    instrs[index + 4].OpCode == dnlib.DotNet.Emit.OpCodes.Call &&
                    instrs[index + 4].Operand is IMethod method2 &&
                    method2.MethodSig.Params.Count == 1 &&
                    method2.MethodSig.Params[0].FullName == "System.Byte[]" &&
                    method2.MethodSig.RetType.FullName == "System.Byte[]" &&

                    instrs[index + 5].OpCode == dnlib.DotNet.Emit.OpCodes.Newobj &&
                    instrs[index + 5].Operand is IMethod ctor &&
                    ctor.DeclaringType.FullName == "System.IO.MemoryStream" &&
                    ctor.MethodSig.Params.Count == 1 &&
                    ctor.MethodSig.Params[0].FullName == "System.Byte[]" &&

                    instrs[index + 6].OpCode == dnlib.DotNet.Emit.OpCodes.Stloc_S &&
                    instrs[index + 7].OpCode == dnlib.DotNet.Emit.OpCodes.Ldloc_S &&

                    instrs[index + 8].OpCode == dnlib.DotNet.Emit.OpCodes.Ldc_I8 &&
                    instrs[index + 8].Operand is long l && l == 0L &&

                    instrs[index + 9].OpCode == dnlib.DotNet.Emit.OpCodes.Callvirt &&
                    instrs[index + 9].Operand is IMethod method3 &&
                    method3.FullName.Contains("System.IO.Stream::set_Position") &&

                    instrs[index + 10].OpCode == dnlib.DotNet.Emit.OpCodes.Ldloc_S &&

                    instrs[index + 11].OpCode == dnlib.DotNet.Emit.OpCodes.Call &&
                    instrs[index + 11].Operand is MethodSpec methodSpec &&
                    methodSpec.Method is IMethod method4 &&
                    method4.Name == "Deserialize" &&
                    method4.DeclaringType.FullName == "ProtoBuf.Serializer"
                )
                {
                    // Set the name/type of the method used to get the resource
                    getResourceMethodType = method0.DeclaringType.FullName;
                    getResourceMethodName = method0.Name;

                    // Set the name/type of the method used to decrypt the resource
                    decryptResourceMethodType = method1.DeclaringType.FullName;
                    decryptResourceMethodName = method1.Name;

                    // Set the protobufs deserialization type
                    var genericSig = methodSpec.GenericInstMethodSig;
                    if (genericSig != null && genericSig.GenericArguments.Count == 1)
                    {
                        var genericArg = genericSig.GenericArguments[0];
                        var typeDefOrRef = genericArg.ToTypeDefOrRef();
                        if (typeDefOrRef != null)
                            protobufsType = typeDefOrRef.FullName;
                    }

                    return true;
                }
            }
            catch
            { }

            return false;
        }


        private static bool MatchesDecryptMethodPattern(IList<dnlib.DotNet.Emit.Instruction> instrs, int index)
        {
            try
            {
                return
                    instrs[index + 0].OpCode == dnlib.DotNet.Emit.OpCodes.Call &&
                    ((IMethod)instrs[index + 0].Operand).FullName.Contains("System.AppDomain::get_CurrentDomain") &&

                    instrs[index + 1].OpCode == dnlib.DotNet.Emit.OpCodes.Ldsfld &&
                    instrs[index + 1].Operand is IField field &&
                    field.FieldSig.Type.FullName == "System.String" &&

                    instrs[index + 2].OpCode == dnlib.DotNet.Emit.OpCodes.Callvirt &&
                    ((IMethod)instrs[index + 2].Operand).FullName.Contains("System.AppDomain::GetData") &&

                    instrs[index + 3].OpCode == dnlib.DotNet.Emit.OpCodes.Castclass &&
                    instrs[index + 3].Operand.ToString().Contains("System.Collections.Hashtable") &&

                    instrs[index + 4].OpCode.Code.ToString().StartsWith("Ldarg") &&

                    instrs[index + 5].OpCode == dnlib.DotNet.Emit.OpCodes.Box &&
                    instrs[index + 5].Operand.ToString().Contains("System.Int32") &&

                    instrs[index + 6].OpCode == dnlib.DotNet.Emit.OpCodes.Callvirt &&
                    ((IMethod)instrs[index + 6].Operand).FullName.Contains("System.Collections.Hashtable::get_Item") &&

                    instrs[index + 7].OpCode == dnlib.DotNet.Emit.OpCodes.Castclass &&
                    instrs[index + 7].Operand.ToString().Contains("System.String") &&

                    instrs[index + 8].OpCode == dnlib.DotNet.Emit.OpCodes.Ret;

            }
            catch
            {
                return false;
            }
        }


        private static bool MatchPayloadMethod(IList<dnlib.DotNet.Emit.Instruction> instrs, int index)
        {
            try
            {

                var method0 = instrs[index + 0].Operand as IMethod;
                if (instrs[index + 0].OpCode != dnlib.DotNet.Emit.OpCodes.Call)
                    return false;

                // 1: Callvirt returning an object from method0
                var method1 = instrs[index + 1].Operand as IMethod;
                if (instrs[index + 1].OpCode != dnlib.DotNet.Emit.OpCodes.Callvirt)
                    return false;

                // 2: Callvirt bool method (e.g., check method)
                var method2 = instrs[index + 2].Operand as IMethod;
                if (instrs[index + 2].OpCode != dnlib.DotNet.Emit.OpCodes.Callvirt)
                    return false;

                // 3: Conditional branch
                if (instrs[index + 3].OpCode != dnlib.DotNet.Emit.OpCodes.Brtrue_S)
                    return false;

                var method3 = instrs[index + 4].Operand as IMethod;
                if (instrs[index + 4].OpCode != dnlib.DotNet.Emit.OpCodes.Call)
                    return false;

                // 5: Load int32 (0xC00)
                if (instrs[index + 5].OpCode != dnlib.DotNet.Emit.OpCodes.Ldc_I4 || (int)instrs[index + 5].Operand != 0xC00)
                    return false;

                var method4 = instrs[index + 6].Operand as IMethod;
                if (instrs[index + 6].OpCode != dnlib.DotNet.Emit.OpCodes.Call || method4 == null ||
                    !method4.FullName.Contains("System.Net.ServicePointManager::set_SecurityProtocol"))
                    return false;

                var method5 = instrs[index + 10].Operand as IMethod;
                if (instrs[index + 10].OpCode != dnlib.DotNet.Emit.OpCodes.Newobj || !method5.FullName.Contains("System.Net.WebClient"))
                    return false;

                return true;
            }
            catch
            {
                return false;
            }
        }


        private static void PatchCrossReferences(Assembly asm, ModuleDefMD mod)
        {
            // Create instance of the type
            Type t = asm.GetType(stringDecryptMethodType);
            var x = Activator.CreateInstance(t);
            var methodInfo = t.GetMethod(stringDecryptMethodName, new Type[] { typeof(int) });

            foreach (var type in mod.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody)
                        continue;

                    var instrs = method.Body.Instructions;

                    for (int i = 0; i < instrs.Count; i++)
                    {
                        var instr = instrs[i];
                        if ((instr.OpCode == dnlib.DotNet.Emit.OpCodes.Call || instr.OpCode == dnlib.DotNet.Emit.OpCodes.Callvirt) &&
                            instr.Operand is IMethod called &&
                            called.FullName == targetMethod.FullName)
                        {
                            // Look backwards for the int argument
                            var prevInstr = i > 0 ? instrs[i - 1] : null;

                            if (prevInstr == null || prevInstr.OpCode != dnlib.DotNet.Emit.OpCodes.Ldc_I4)
                            {
                                continue;
                            }

                            int index = (int)prevInstr.Operand;
                            Console.WriteLine($"Resolving string index {index} passed to method {called.FullName} in {method.FullName}");

                            object[] parameters = new object[1];
                            parameters[0] = index;
                            string resolvedString = (string)methodInfo.Invoke(x, parameters);
                            Console.WriteLine($"Replacing call instruction with decrypted string: {resolvedString}");
                            // Replace instruction with Ldstr
                            instr.OpCode = dnlib.DotNet.Emit.OpCodes.Ldstr;
                            // Replace operand with decrypted string
                            instr.Operand = resolvedString;
                            // Replace previous instruction with NOP
                            prevInstr.OpCode = dnlib.DotNet.Emit.OpCodes.Nop;
                            prevInstr.Operand = null;
                        }
                    }
                }
            }
        }


        static bool SetTargetMethod(ModuleDefMD mod)
        {
            return (targetMethod = mod.Types.SelectMany(t => t.Methods).FirstOrDefault(m => m.Name == stringDecryptMethodName && m.DeclaringType.FullName == stringDecryptMethodType)) != null;
        }


        static void HandleObjectProperties(string payloadsDir, object obj, int indent = 0, HashSet<object> visited = null)
        {
            if (obj == null) return;

            if (visited == null)
            {
                visited = new HashSet<object>(); // Initialize only on the initial call
            }

            if (!visited.Add(obj))
            {
                return;
            }

            Type type = obj.GetType();
            string indentStr = new string(' ', indent * 2);

            foreach (PropertyInfo prop in type.GetProperties(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
            {
                object value = null;
                try { value = prop.GetValue(obj); } catch { continue; }

                if (value == null)
                {
                    Console.WriteLine($"{indentStr}{prop.Name} ({prop.PropertyType.Name}) = null");
                    configResults += $"{indentStr}{prop.Name} ({prop.PropertyType.Name}) = null\n";
                }
                else if (value is string)
                {
                    Console.WriteLine($"{indentStr}{prop.Name} ({prop.PropertyType.Name}) = \"{value}\"");
                    configResults += $"{indentStr}{prop.Name} ({prop.PropertyType.Name}) = \"{value}\"\n";
                }
                else if (value is System.Collections.IEnumerable enumerable && !(value is string))
                {
                    try
                    {
                        Console.WriteLine("Found byte array in the config...");
                        Console.WriteLine($"{indentStr}{prop.Name} ({prop.PropertyType.Name}) = System.Collections.IEnumerable");
                        configResults += $"{indentStr}{prop.Name} ({prop.PropertyType.Name}) = System.Collections.IEnumerable\n";
                        string hexString = string.Join("", enumerable.Cast<byte>().Select(b => b.ToString("X2")));
                        Console.WriteLine($"{indentStr}{indentStr}Byte Array: {hexString}");
                        configResults += $"{indentStr}{indentStr}Byte Array: {hexString}\n";



                        byte[] decryptedBytes = (byte[])decryptPayloadMethod.Invoke(null, new object[] { enumerable });
                        byte[] decompressed = Decompress(decryptedBytes);
                        string hexString2 = string.Join("", decompressed.Cast<byte>().Select(b => b.ToString("X2")));
                        Console.WriteLine($"{indentStr}{indentStr}Decrypted Payload: {hexString2}");
                        configResults += $"{indentStr}{indentStr}Decrypted Payload: {hexString2}\n";
                        string payloadSha256 = GetSha256(decompressed);
                        string outPath = Path.Combine(payloadsDir, payloadSha256 + ".bin");
                        File.WriteAllBytes(outPath, decompressed);


                    }
                    catch { }
                }
                else if (IsComplexType(prop.PropertyType))
                {
                    Console.WriteLine($"{indentStr}{prop.Name} ({prop.PropertyType.Name}) = {value.GetType().FullName}");
                    configResults += $"{indentStr}{prop.Name} ({prop.PropertyType.Name}) = {value.GetType().FullName}\n";
                    HandleObjectProperties(payloadsDir, value, indent + 1, visited);
                }
                else if (prop.PropertyType.IsEnum)
                {
                    Console.WriteLine($"{indentStr}{prop.Name} (Enum) = {(int)value} ({value})");
                    configResults += $"{indentStr}{prop.Name} (Enum) = {(int)value} ({value})\n";
                }
                else
                {
                    Console.WriteLine($"{indentStr}{prop.Name} ({prop.PropertyType.Name}) = {value}");
                    configResults += $"{indentStr}{prop.Name} ({prop.PropertyType.Name}) = {value}\n";
                }
            }

            foreach (FieldInfo field in type.GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public))
            {
                object value = null;
                try { value = field.GetValue(obj); } catch { continue; }

                if (value == null)
                {
                    Console.WriteLine($"{indentStr}{field.Name} ({field.FieldType.Name}) = null");
                    configResults += $"{indentStr}{field.Name} ({field.FieldType.Name}) = null\n";
                }
                else if (value is string)
                {
                    Console.WriteLine($"{indentStr}{field.Name} ({field.FieldType.Name}) = \"{value}\"");
                    configResults += $"{indentStr}{field.Name} ({field.FieldType.Name}) = \"{value}\"\n";
                }
                else if (value is System.Collections.IEnumerable enumerable && !(value is string))
                {
                    try
                    {
                        Console.WriteLine("Found byte array in the config...");
                        Console.WriteLine($"{indentStr}{field.Name} ({field.FieldType.Name}) = System.Collections.IEnumerable");
                        configResults += $"{indentStr}{field.Name} ({field.FieldType.Name}) = System.Collections.IEnumerable\n";
                        string hexString = string.Join("", enumerable.Cast<byte>().Select(b => b.ToString("X2")));
                        Console.WriteLine($"{indentStr}{indentStr}Byte Array: {hexString}");
                        configResults += $"{indentStr}{indentStr}Byte Array: {hexString}\n";

                        byte[] decryptedBytes = (byte[])decryptPayloadMethod.Invoke(null, new object[] { enumerable });
                        byte[] decompressed = Decompress(decryptedBytes);
                        string hexString2 = string.Join("", decompressed.Cast<byte>().Select(b => b.ToString("X2")));
                        Console.WriteLine($"{indentStr}{indentStr}Decrypted Payload: {hexString2}");
                        configResults += $"{indentStr}{indentStr}Decrypted Payload: {hexString2}\n";
                        string payloadSha256 = GetSha256(decompressed);
                        string outPath = Path.Combine(payloadsDir, payloadSha256 + ".bin");
                        File.WriteAllBytes(outPath, decompressed);

                    }
                    catch { }
                }
                else if (IsComplexType(field.FieldType))
                {
                    Console.WriteLine($"{indentStr}{field.Name} ({field.FieldType.Name}) = {value.GetType().FullName}");
                    configResults += $"{indentStr}{field.Name} ({field.FieldType.Name}) = {value.GetType().FullName}\n";
                    HandleObjectProperties(payloadsDir, value, indent + 1, visited);
                }
                else if (field.FieldType.IsEnum)
                {
                    Console.WriteLine($"{indentStr}{field.Name} (Enum) = {(int)value} ({value})");
                    configResults += $"{indentStr}{field.Name} (Enum) = {(int)value} ({value})\n";
                }
                else
                {
                    Console.WriteLine($"{indentStr}{field.Name} ({field.FieldType.Name}) = {value}");
                    configResults += $"{indentStr}{field.Name} ({field.FieldType.Name}) = {value}\n";
                }
            }
        }

        static string GetSha256(byte[] byteArray)
        {
            byte[] hashBytes;
            using (SHA256 sha256 = SHA256.Create())
            {
                hashBytes = sha256.ComputeHash(byteArray);
            }
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
        }
        static bool IsComplexType(Type type)
        {
            return type != typeof(string) && !type.IsPrimitive && !type.IsEnum && !type.IsValueType;
        }

        public static byte[] Decompress(byte[] byteArray)
        {
            byte[] array3;
            using (MemoryStream memoryStream = new MemoryStream(byteArray))
            {
                byte[] array = new byte[4];
                memoryStream.Read(array, 0, 4);
                int num = BitConverter.ToInt32(array, 0);
                using (GZipStream gzipStream = new GZipStream(memoryStream, CompressionMode.Decompress))
                {
                    byte[] array2 = new byte[num];
                    gzipStream.Read(array2, 0, num);
                    array3 = array2;
                }
            }
            return array3;
        }


        static void ShowHelp()
        {
            Console.WriteLine(@"
        __   __                 ____  _                        
        \ \ / /   _ _ __   __ _| __ )(_)_ __   __ _ _ __ _   _ 
         \ V / | | | '_ \ / _` |  _ \| | '_ \ / _` | '__| | | |
          | || |_| | | | | (_| | |_) | | | | | (_| | |  | |_| |
          |_| \__,_|_| |_|\__, |____/|_|_| |_|\__,_|_|   \__, |
                          |___/                          |___/ 
        
        DESCRIPTION:
            Decrypts PureCrypter Strings, Extracts Config, Downloads/Extracts Payload v1.0
        
        WARNING:
            Run this program in a sandboxed environment!

        USAGE:
            PureCrypterPunisher.exe C:\Path\To\PureCrypter.dll");
        }

        static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                ShowHelp();
                return;
            }

            foreach (string arg in args)
            {
                if (arg.Equals("-h", StringComparison.OrdinalIgnoreCase) ||
                    arg.Equals("/h", StringComparison.OrdinalIgnoreCase) ||
                    arg.Equals("help", StringComparison.OrdinalIgnoreCase))
                {
                    ShowHelp();
                    return;
                }
            }

            Assembly asm = Assembly.LoadFrom(args[0]);
            var mod = ModuleDefMD.Load(args[0]);
            ParsePureCrypterPayload(mod);

            bool setTargetMethod = SetTargetMethod(mod);
            if (!setTargetMethod)
            {
                throw new Exception("Failed to find any cross references to string decryption method.");
            }

            PatchCrossReferences(asm, mod);

            string outFile = args[0] + "_decrypted.dll";
            mod.Write(outFile, new ModuleWriterOptions(mod) { MetadataOptions = { Flags = MetadataFlags.KeepOldMaxStack } });
            Console.WriteLine($"Assembly patched and saved as: {outFile}");

            Console.WriteLine("Attempting to extract configuration/payloads...");
            string payloadsDir = "payloads";
            Directory.CreateDirectory(payloadsDir);
            ExtractConfig(payloadsDir, asm);
            string configOutFile = args[0] + "_config.txt";
            File.WriteAllText(configOutFile, configResults);
        }
    }
}
