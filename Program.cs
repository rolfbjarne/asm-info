﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

using Mono.Cecil;
using Mono.Options;

namespace asminfo
{
	class MainClass
	{
		static string filter;
		static string filtertype;
		static bool show_typedefs;
		static bool show_methoddefs;
		static bool show_fielddefs;
		static bool show_pinvoke;
		static bool show_debug_info;
		static bool show_pe = true;
		static bool show_pe_headers;
		static bool show_attributes;

		static void CollectAssemblies (string directory, HashSet<string> files)
		{
			foreach (var f in Directory.GetFiles (directory)) {
				switch (Path.GetExtension (f).ToUpper ()) {
				case ".EXE":
				case ".DLL":
					files.Add (f);
					break;
				}
			}

			foreach (var d in Directory.GetDirectories (directory))
				CollectAssemblies (d, files);
		}

		public static int Main (string[] args)
		{
			var files = new HashSet<string> ();
			var show_help = false;
			
			OptionSet options = null;
			options = new OptionSet () {
				{ "h|?|help", "Help!", v => show_help = true },
				{ "r|recurse:", "Recursive and find all assemblies in the specified directory", v =>
					{
						if (string.IsNullOrEmpty (v))
							v = Environment.CurrentDirectory;
						CollectAssemblies (v, files);
					}
				},
				{ "pe-headers", "Show PE headers", v => show_pe_headers = true },
				{ "typedef", "List types", v => show_typedefs = true },
				{ "methoddef", "List methods", v => show_methoddefs = true },
				{ "fielddef", "List fields", v => show_fielddefs = true },
				{ "debug-info", "Show debug information", v => show_debug_info = true },
				{ "f|filter=", "Filter to filter out assemblies", v => filter = v },
				{ "a|attributes", "Show attributes", v => show_attributes = true },
				{ "filtertype=", "Filter to the specified type. Substring match based on the full typename.", v => filtertype = v },
			};

			foreach (var f in options.Parse (args))
				files.Add (f);

			if (show_help) {
				Console.WriteLine ("asm-info [options] assembly1 [assembly2+]");
				options.WriteOptionDescriptions (Console.Out);
				return 0;
			}

			if (files.Count == 0) {
				Console.WriteLine ("No files specified");
				return 1;
			}

			foreach (var f in Filtered (files)) {
				try {
					Process (f);
				} catch (Exception e) {
					Console.WriteLine ("Exception while processing {0}: {1}", f, e);
				}
			}

			return 0;
		}

		static IEnumerable<string> Filtered (IEnumerable<string> files)
		{
			if (string.IsNullOrEmpty (filter)) {
				foreach (var f in files)
					yield return f;
			} else {
				var regex = new Regex (filter);
				foreach (var f in files) {
					if (regex.IsMatch (f))
						yield return f;
				}
			}
		}

		static IEnumerable<TypeDefinition> FilteredTypes (IEnumerable<TypeDefinition> types)
		{
			if (string.IsNullOrEmpty (filtertype)) {
				foreach (var f in types)
					yield return f;
			} else {
				foreach (var f in types) {
					var typename = f.FullName;
					if (string.IsNullOrEmpty (typename))
						typename = f.Name;
					if (typename.IndexOf (filtertype, StringComparison.OrdinalIgnoreCase) >= 0)
						yield return f;
				}
			}
		}

		static int Process (string file)
		{
			if (show_typedefs) {
				ShowTypeDefs (file);
			} else if (show_debug_info) {
				ShowDebugInfo (file);
			} else if (show_pe) {
				ShowPE (file);
			} else {
				Console.WriteLine ("No action!");
				return 1;
			}
			return 0;
		}

		static int ShowTypeDefs (string file)
		{
			var ad = AssemblyDefinition.ReadAssembly (file, new ReaderParameters { ReadingMode = ReadingMode.Deferred });
			var rv = 0;
			PrintLine ($"{ad.FullName}");
			rv |= ShowTypeDefs (1, ad.MainModule.Types);
			return rv;
		}

		static int ShowTypeDefs (int indent, IEnumerable<TypeDefinition> types)
		{
			var rv = 0;
			foreach (var td in FilteredTypes (types))
				rv |= ShowTypeDef (indent, td);
			return rv;
		}

		static void RenderConstant (CustomAttributeArgument arg)
		{
			var obj = arg.Value;
			var resolvedType = arg.Type.Resolve ();

			if (resolvedType?.IsEnum == true) {
				if (resolvedType.HasCustomAttributes && resolvedType.CustomAttributes.Any (v => v.AttributeType.Name == "FlagsAttribute")) {
					var enumFields = resolvedType.Fields.Where (v => {
						if (!v.IsStatic)
							return false;

						if (obj is byte b) {
							return 0 != (b & (byte) v.Constant);
						} else if (obj is sbyte sb) {
							return 0 != (sb & (sbyte) v.Constant);
						} else if (obj is short sh) {
							return 0 != (sh & (short) v.Constant);
						} else if (obj is ushort ush) {
							return 0 != (ush & (ushort) v.Constant);
						} else if (obj is int i) {
							return 0 != (i & (int) v.Constant);
						} else if (obj is uint u) {
							return 0 != (u & (uint) v.Constant);
						} else if (obj is long l) {
							return 0 != (l & (long) v.Constant);
						} else if (obj is ulong ul) {
							return 0 != (ul & (ulong) v.Constant);
						} else {
							throw new NotImplementedException ($"Unknown enum type: {obj.GetType ().FullName}");
						}
					});
					if (enumFields.Any ()) {
						Print ($"{string.Join (" | ", enumFields.Select (v => $"{resolvedType.FullName}.{v.Name}"))}");
						return;
					} else {
						Print ("(" + resolvedType.FullName + ") ");
					}
				} else {
					var enumField = resolvedType.Fields.FirstOrDefault (v => {
						return v.IsStatic && v.Constant == obj;
					});
					if (enumField != null) {
						Print ($"{resolvedType.FullName}.{enumField.Name}");
						return;
					} else {
						Print ("(" + resolvedType.FullName + ") ");
					}
				}
			}

			if (obj is null) {
				Print ("null");
			} else if (obj is string str) {
				Print ($"\"{str.Replace ("\"", "\\\"")}\"");
			} else if (obj is byte b) {
				Print ($"{b}");
			} else if (obj is sbyte sb) {
				Print ($"{sb}");
			} else if (obj is short sh) {
				Print ($"{sh}");
			} else if (obj is ushort ush) {
				Print ($"{ush}");
			} else if (obj is int i) {
				Print ($"{i}");
			} else if (obj is uint u) {
				Print ($"{u}");
			} else if (obj is long l) {
				Print ($"{l}");
			} else if (obj is ulong ul) {
				Print ($"{ul}");
			} else {
				Print ($"Unknown type: {obj.GetType ().FullName} Value: {obj}");
			}
		}

		static void RenderAttribute (CustomAttribute ca)
		{
			Print ($"[{ca.AttributeType.FullName} (");
			var argCount = 0;
			if (ca.HasConstructorArguments) {
				for (var i = 0; i < ca.ConstructorArguments.Count; i++) {
					if (argCount > 0)
						Print (", ");
					var arg = ca.ConstructorArguments [i];
					RenderConstant (arg);
					argCount++;
				}
			}
			if (ca.HasFields) {
				for (var i = 0; i < ca.Fields.Count; i++) {
					if (argCount > 0)
						Print (", ");
					var field = ca.Fields [i];
					Print (field.Name);
					Print (" = ");
					RenderConstant (field.Argument);
					argCount++;
				}
			}

			PrintLine (")]");
		}

		static void ShowAttributes (int indent, ICustomAttributeProvider provider)
		{
			if (!show_attributes)
				return;

			if (!provider.HasCustomAttributes)
				return;

			foreach (var ca in provider.CustomAttributes) {
				PrintIndent (indent);
				RenderAttribute (ca);
			}
		}

		static int ShowTypeDef (int indent, TypeDefinition td)
		{
			var rv = 0;

			ShowAttributes (indent, td);

			PrintIndent (indent);
			Print ($"{td.FullName}");
			if (td.BaseType != null)
				Print ($" : {td.BaseType?.FullName}");
			Print ($" ({ToString (td.Attributes)})");
			Print ($" {td.Methods.Count} methods, {td.Fields.Count} fields, {td.Properties.Count} properties, {td.Events.Count} events, {td.HasNestedTypes} nested types");
			PrintLine ("");
			if (td.HasNestedTypes)
				rv |= ShowTypeDefs (indent + 1, td.NestedTypes);
			if (show_methoddefs && td.HasMethods)
				ShowMethodDefs (indent + 1, td.Methods);
			if (show_fielddefs && td.HasFields)
				ShowFieldDefs (indent + 1, td.Fields);
			return rv;
		}

		static int ShowFieldDefs (int indent, IEnumerable<FieldDefinition> fields)
		{
			var rv = 0;
			foreach (var field in fields)
				rv |= ShowFieldDef (indent, field);
			return rv;
		}

		static int ShowFieldDef (int indent, FieldDefinition field)
		{
			var rv = 0;

			ShowAttributes (indent, field);
			PrintIndent (indent);
			Print (field.Name);
			Print ($" ({ToString (field.Attributes)})");
			PrintLine (string.Empty);
			return rv;
		}

		static int ShowMethodDefs (int indent, IEnumerable<MethodDefinition> methods)
		{
			var rv = 0;
			foreach (var method in methods)
				rv |= ShowMethodDef (indent, method);
			return rv;
		}

		static int ShowMethodDef (int indent, MethodDefinition method)
		{
			var rv = 0;
			ShowAttributes (indent, method);
			PrintIndent (indent);
			if (method.HasPInvokeInfo) {
				var pimpl = method.PInvokeInfo;
				Print ($"[DllImport (\"{pimpl.Module.Name}\", EntryPoint = \"{pimpl.EntryPoint}\")] ");
			}
			Print (method.FullName);
			Print ($" ({ToString (method.Attributes)})");
			PrintLine (string.Empty);
			return rv;
		}

		static void Print (string message)
		{
			Console.Write (message);
		}

		static void PrintLine (string message)
		{
			Console.WriteLine (message);
		}

		static void PrintIndent (int indent)
		{
			Console.Write (new string ('\t', indent));
		}

		static int ShowDebugInfo (string file)
		{
			AssemblyDefinition ad;
			var rp = new ReaderParameters { ReadingMode = ReadingMode.Deferred };

			rp.ReadSymbols = true;
			try {
				ad = AssemblyDefinition.ReadAssembly (file, rp);
			} catch (Mono.Cecil.Cil.SymbolsNotFoundException) {
				rp.ReadSymbols = false;
				ad = AssemblyDefinition.ReadAssembly (file, rp);
			}

			Console.WriteLine ($"{ad.FullName}");
			foreach (var d in ad.MainModule.CustomDebugInformations) {
				Console.WriteLine ($"\tCustom debug info: {d.Kind}");
			}
			var reader = ad.MainModule.SymbolReader;
			Console.WriteLine ($"\tSymbolReader: {reader?.GetType ()}");
			if (ad.MainModule.HasDebugHeader) {
				var dh = ad.MainModule.GetDebugHeader ();
				if (dh.HasEntries) {
					foreach (var e in dh.Entries) {
						Console.WriteLine ($"\tDebugHeader: {e.Directory.Type}");
					}
				}
			}
			return 0;
		}

		static string GetVisibility (FieldAttributes attributes)
		{
			var visibility = attributes & FieldAttributes.FieldAccessMask;
			switch (visibility) {
			case FieldAttributes.Private:
				return "private";
			case FieldAttributes.Public:
				return "public";
			case FieldAttributes.Assembly:
				return "internal";
			case FieldAttributes.Family:
				return "private protected";
			case FieldAttributes.FamANDAssem:
				return "private protected";
			case FieldAttributes.FamORAssem:
				return "internal protected";
			default:
				return $"unknown visibility ({visibility})";
			}
		}

		static string GetVisibility (MethodAttributes attributes)
		{
			var visibility = attributes & MethodAttributes.MemberAccessMask;
			switch (visibility) {
			case MethodAttributes.Private:
				return "private";
			case MethodAttributes.Public:
				return "public";
			case MethodAttributes.Assembly:
				return "internal";
			case MethodAttributes.Family:
				return "private protected";
			case MethodAttributes.FamANDAssem:
				return "private protected";
			case MethodAttributes.FamORAssem:
				return "internal protected";
			default:
				return $"unknown visibility ({visibility})";
			}
		}

		static string GetVisibility (TypeAttributes attributes)
		{
			switch (attributes & TypeAttributes.VisibilityMask) {
			case TypeAttributes.NotPublic:
				return "internal";
			case TypeAttributes.Public:
			case TypeAttributes.NestedPublic:
				return "public";
			case TypeAttributes.NestedAssembly:
				return "internal";
			case TypeAttributes.NestedFamANDAssem:
				return "private protected";
			case TypeAttributes.NestedFamily:
				return "protected";
			case TypeAttributes.NestedFamORAssem:
				return "internal protected";
			case TypeAttributes.NestedPrivate:
				return "private";
			default:
				return "unknown visibility";
			}
		}

		static string ToString (FieldAttributes attributes)
		{
			var sb = new StringBuilder ();
			sb.Append (GetVisibility (attributes));
			if ((attributes & FieldAttributes.HasDefault) == FieldAttributes.HasDefault)
				sb.Append (" hasdefault");
			if ((attributes & FieldAttributes.HasFieldMarshal) == FieldAttributes.HasFieldMarshal)
				sb.Append (" hasfieldmarshal");
			if ((attributes & FieldAttributes.HasFieldRVA) == FieldAttributes.HasFieldRVA)
				sb.Append (" hasfieldrva");
			if ((attributes & FieldAttributes.InitOnly	) == FieldAttributes.InitOnly)
				sb.Append (" initonly");
			if ((attributes & FieldAttributes.Literal) == FieldAttributes.Literal)
				sb.Append (" literal");
			if ((attributes & FieldAttributes.NotSerialized) == FieldAttributes.NotSerialized)
				sb.Append (" notserialized");
			if ((attributes & FieldAttributes.PInvokeImpl) == FieldAttributes.PInvokeImpl)
				sb.Append (" pinvokeimpl");
			if ((attributes & FieldAttributes.RTSpecialName) == FieldAttributes.RTSpecialName)
				sb.Append (" rtspecialname");
			if ((attributes & FieldAttributes.SpecialName) == FieldAttributes.SpecialName)
				sb.Append (" specialname");
			if ((attributes & FieldAttributes.Static) == FieldAttributes.Static)
				sb.Append (" static");
			return sb.ToString ();
		}

		static string ToString (TypeAttributes attributes)
		{
			var sb = new StringBuilder ();
			sb.Append (GetVisibility (attributes));
			if ((attributes & TypeAttributes.Abstract) == TypeAttributes.Abstract)
				sb.Append (" abstract");
			if ((attributes & TypeAttributes.BeforeFieldInit) == TypeAttributes.BeforeFieldInit)
				sb.Append (" beforefieldinit");
			if ((attributes & TypeAttributes.Forwarder) == TypeAttributes.Forwarder)
				sb.Append (" forwarder");
			if ((attributes & TypeAttributes.Interface) == TypeAttributes.Interface)
				sb.Append (" interface");
			if ((attributes & TypeAttributes.Sealed) == TypeAttributes.Sealed)
				sb.Append (" sealed");
			return sb.ToString ();
		}

		static string ToString (MethodAttributes attributes)
		{
			var sb = new StringBuilder ();
			sb.Append (GetVisibility (attributes));
			if ((attributes & MethodAttributes.Abstract) == MethodAttributes.Abstract)
				sb.Append (" abstract");
			if ((attributes & MethodAttributes.CheckAccessOnOverride) == MethodAttributes.CheckAccessOnOverride)
				sb.Append (" checkaccessonoverride");
			if ((attributes & MethodAttributes.CompilerControlled) == MethodAttributes.CompilerControlled)
				sb.Append (" compilercontrolled");
			if ((attributes & MethodAttributes.Final) == MethodAttributes.Final)
				sb.Append (" final");
			if ((attributes & MethodAttributes.HasSecurity) == MethodAttributes.HasSecurity)
				sb.Append (" hassecurity");
			if ((attributes & MethodAttributes.HideBySig) == MethodAttributes.HideBySig)
				sb.Append (" hidebysig");
			if ((attributes & MethodAttributes.NewSlot) == MethodAttributes.NewSlot)
				sb.Append (" newslot");
			if ((attributes & MethodAttributes.PInvokeImpl) == MethodAttributes.PInvokeImpl)
				sb.Append (" pinvokeimpl");
			if ((attributes & MethodAttributes.RequireSecObject) == MethodAttributes.RequireSecObject)
				sb.Append (" requiresecobject");
			if ((attributes & MethodAttributes.ReuseSlot) == MethodAttributes.ReuseSlot)
				sb.Append (" reuseslot");
			if ((attributes & MethodAttributes.RTSpecialName) == MethodAttributes.RTSpecialName)
				sb.Append (" rtspecialname");
			if ((attributes & MethodAttributes.SpecialName) == MethodAttributes.SpecialName)
				sb.Append (" specialname");
			if ((attributes & MethodAttributes.Static) == MethodAttributes.Static)
				sb.Append (" static");
			if ((attributes & MethodAttributes.UnmanagedExport) == MethodAttributes.UnmanagedExport)
				sb.Append (" unmanagedexport");
			if ((attributes & MethodAttributes.Virtual) == MethodAttributes.Virtual)
				sb.Append (" virtual");
			return sb.ToString ();
		}

		public static void ShowPE (string file)
		{
			using (var fs = new FileStream (file, System.IO.FileMode.Open, System.IO.FileAccess.Read)) {
				// Get the PE timestamp.
				fs.Position = 136;
				byte[] buf = new byte[4];
				fs.Read (buf, 0, 4);
				int t2 = (buf [3] << 24) + (buf [2] << 16) + (buf [1] << 8) + buf [0];
				var d = new DateTime (1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
				var d2 = d.AddSeconds (t2);
				fs.Position = 0;

				// Calculate MD5
				var md5 = System.Security.Cryptography.MD5.Create();
				var hash = md5.ComputeHash (fs);
				var sb = new StringBuilder();
				for (int i = 0; i < hash.Length; i++)
					sb.Append (hash [i].ToString ("X2"));
				fs.Position = 0;

				var rp = new ReaderParameters (ReadingMode.Deferred);
				var resolver = new DefaultAssemblyResolver ();
				resolver.AddSearchDirectory (Path.GetDirectoryName (file));
				rp.AssemblyResolver = resolver;

				var mod = AssemblyDefinition.ReadAssembly (fs, rp);

				Console.WriteLine ("{0} (MD5: {1}) {2}:", file, sb.ToString (), mod.FullName);

				Console.WriteLine ("    PE timestamp: {0}", d2);

				// Print the GUID
				Console.WriteLine ("    Main module MVID: {0}", mod.MainModule.Mvid);

				Console.WriteLine ("    Architecture: {0}", mod.MainModule.Architecture);
				Console.WriteLine ("    Runtime: {0}", mod.MainModule.Runtime);
				// Print references
				if (mod.MainModule.HasAssemblyReferences) {
					Console.WriteLine ("    References:");
					foreach (var r in mod.MainModule.AssemblyReferences.OrderBy (v => v.FullName))
						Console.WriteLine ("        {0}", r.FullName);
				} else {
					Console.WriteLine ("    No direct assembly references.");
				}
				if (mod.MainModule.HasCustomAttributes) {
					try {
						var all_attributes = mod.MainModule.GetCustomAttributes ().ToList ();
						var anrs = new Dictionary<string, List<CustomAttribute>> ();
						foreach (var ca in all_attributes) {
							var args = new List<CustomAttributeArgument> ();
							if (ca.HasConstructorArguments)
								args.AddRange (ca.ConstructorArguments);
							if (ca.HasFields)
								args.AddRange (ca.Fields.Select (v => v.Argument));
							if (ca.HasProperties)
								args.AddRange (ca.Properties.Select (v => v.Argument));
							foreach (var arg in args) {
								if (arg.Type.Namespace != "System" || arg.Type.Name != "Type")
									continue;
								var tr = arg.Value as TypeReference;
								var ar = tr.Scope as AssemblyNameReference;
								if (ar == null)
									continue;
								if (!anrs.TryGetValue (ar.FullName, out var list))
									anrs [ar.FullName] = list = new List<CustomAttribute> ();
								list.Add (ca);
							}
						}
						if (anrs.Count == 0)
							Console.WriteLine ($"    No assembly references in {all_attributes.Count} custom attributes");
						else {
							Console.WriteLine ("    Assembly references in custom attributes:");
							foreach (var r in anrs.OrderBy (v => v.Key)) {
								Console.WriteLine ("        {0}", r.Key);
								foreach (var ca in r.Value) {
									Console.Write ($"            {ca.AttributeType.FullName} (");
									bool first = true;
									if (ca.HasConstructorArguments) {
										foreach (var arg in ca.ConstructorArguments) {
											if (!first)
												Console.Write (", ");
											first = false;
											Console.Write (arg.Value);
										}
									}
									if (ca.HasFields) {
										foreach (var arg in ca.Fields) {
											if (!first)
												Console.Write (", ");
											first = false;
											Console.Write ($"{arg.Name} = {arg.Argument.Value}");
										}
									}
									if (ca.HasProperties) {
										foreach (var arg in ca.Properties) {
											if (!first)
												Console.Write (", ");
											first = false;
											Console.Write ($"{arg.Name} = {arg.Argument.Value}");
										}
									}
									Console.WriteLine (")");
								}
							}
						}
					} catch (Exception e) {
						Console.WriteLine ($"    Failed to load custom attributes for '{mod.Name.Name}': {e.Message}");
					}
				} else {
					Console.WriteLine ("    No custom attributes.");
				}

				if (mod.MainModule.HasResources) {
					Console.WriteLine ($"    {mod.MainModule.Resources.Count} resource(s):");
					foreach (var res in mod.MainModule.Resources) {
						switch (res.ResourceType) {
						case ResourceType.Embedded:
							var er = (EmbeddedResource) res;
							Console.WriteLine ($"        {res.Name} ({res.ResourceType}) Size: {er.GetResourceData ().Length} bytes");
							break;
						default:
							Console.WriteLine ($"        {res.Name} ({res.ResourceType})");
							break;
						}
					}
				} else {
					Console.WriteLine ("    No embedded resources.");
				}


				if (show_pe_headers) {
					var pe = new PeHeaderReader (file);
					Console.WriteLine ("PE File:");

					Console.WriteLine ("    FileHeader.Machine: {0}", pe.FileHeader.Machine);
					Console.WriteLine ("    FileHeader.NumberOfSections: {0}", pe.FileHeader.NumberOfSections);
					Console.WriteLine ("    FileHeader.TimeDateStamp: {0}", pe.FileHeader.TimeDateStamp);
					Console.WriteLine ("    FileHeader.PointerToSymbolTable: {0}", pe.FileHeader.PointerToSymbolTable);
					Console.WriteLine ("    FileHeader.NumberOfSymbols: {0}", pe.FileHeader.NumberOfSymbols);
					Console.WriteLine ("    FileHeader.SizeOfOptionalHeader: {0}", pe.FileHeader.SizeOfOptionalHeader);
					Console.WriteLine ("    FileHeader.Characteristics: {0}", pe.FileHeader.Characteristics);
					Console.WriteLine ("    Is32BitHeader: {0}", pe.Is32BitHeader);
					Console.WriteLine ("    TimeStamp: {0}", pe.TimeStamp);
					if (pe.Is32BitHeader) {
						Console.WriteLine ("    OptionalHeader32.Magic: {0}", pe.OptionalHeader32.Magic);
						Console.WriteLine ("    OptionalHeader32.MajorLinkerVersion: {0}", pe.OptionalHeader32.MajorLinkerVersion);
						Console.WriteLine ("    OptionalHeader32.MinorLinkerVersion: {0}", pe.OptionalHeader32.MinorLinkerVersion);
						Console.WriteLine ("    OptionalHeader32.SizeOfCode: {0}", pe.OptionalHeader32.SizeOfCode);
						Console.WriteLine ("    OptionalHeader32.SizeOfInitializedData: {0}", pe.OptionalHeader32.SizeOfInitializedData);
						Console.WriteLine ("    OptionalHeader32.SizeOfUninitializedData: {0}", pe.OptionalHeader32.SizeOfUninitializedData);
						Console.WriteLine ("    OptionalHeader32.AddressOfEntryPoint: {0}", pe.OptionalHeader32.AddressOfEntryPoint);
						Console.WriteLine ("    OptionalHeader32.BaseOfCode: {0}", pe.OptionalHeader32.BaseOfCode);
						Console.WriteLine ("    OptionalHeader32.BaseOfData: {0}", pe.OptionalHeader32.BaseOfData);
						Console.WriteLine ("    OptionalHeader32.ImageBase: {0}", pe.OptionalHeader32.ImageBase);
						Console.WriteLine ("    OptionalHeader32.SectionAlignment: {0}", pe.OptionalHeader32.SectionAlignment);
						Console.WriteLine ("    OptionalHeader32.FileAlignment: {0}", pe.OptionalHeader32.FileAlignment);
						Console.WriteLine ("    OptionalHeader32.MajorOperatingSystemVersion: {0}", pe.OptionalHeader32.MajorOperatingSystemVersion);
						Console.WriteLine ("    OptionalHeader32.MinorOperatingSystemVersion: {0}", pe.OptionalHeader32.MinorOperatingSystemVersion);
						Console.WriteLine ("    OptionalHeader32.MajorImageVersion: {0}", pe.OptionalHeader32.MajorImageVersion);
						Console.WriteLine ("    OptionalHeader32.MinorImageVersion: {0}", pe.OptionalHeader32.MinorImageVersion);
						Console.WriteLine ("    OptionalHeader32.MajorSubsystemVersion: {0}", pe.OptionalHeader32.MajorSubsystemVersion);
						Console.WriteLine ("    OptionalHeader32.MinorSubsystemVersion: {0}", pe.OptionalHeader32.MinorSubsystemVersion);
						Console.WriteLine ("    OptionalHeader32.Win32VersionValue: {0}", pe.OptionalHeader32.Win32VersionValue);
						Console.WriteLine ("    OptionalHeader32.SizeOfImage: {0}", pe.OptionalHeader32.SizeOfImage);
						Console.WriteLine ("    OptionalHeader32.SizeOfHeaders: {0}", pe.OptionalHeader32.SizeOfHeaders);
						Console.WriteLine ("    OptionalHeader32.CheckSum: {0}", pe.OptionalHeader32.CheckSum);
						Console.WriteLine ("    OptionalHeader32.Subsystem: {0}", pe.OptionalHeader32.Subsystem);
						Console.WriteLine ("    OptionalHeader32.DllCharacteristics: {0}", pe.OptionalHeader32.DllCharacteristics);
						Console.WriteLine ("    OptionalHeader32.SizeOfStackReserve: {0}", pe.OptionalHeader32.SizeOfStackReserve);
						Console.WriteLine ("    OptionalHeader32.SizeOfStackCommit: {0}", pe.OptionalHeader32.SizeOfStackCommit);
						Console.WriteLine ("    OptionalHeader32.SizeOfHeapReserve: {0}", pe.OptionalHeader32.SizeOfHeapReserve);
						Console.WriteLine ("    OptionalHeader32.SizeOfHeapCommit: {0}", pe.OptionalHeader32.SizeOfHeapCommit);
						Console.WriteLine ("    OptionalHeader32.LoaderFlags: {0}", pe.OptionalHeader32.LoaderFlags);
						Console.WriteLine ("    OptionalHeader32.NumberOfRvaAndSizes: {0}", pe.OptionalHeader32.NumberOfRvaAndSizes);
					} else {
					}

					foreach (var section in pe.ImageSectionHeaders) {
						var c = Array.IndexOf (section.Name, (char) 0);
						Console.WriteLine ("    ImageSectionHeaders.Name: {0}", new string (section.Name, 0, c == -1 ? section.Name.Length : c));
						Console.WriteLine ("    ImageSectionHeaders.VirtualSize: {0}", section.VirtualSize);
						Console.WriteLine ("    ImageSectionHeaders.VirtualAddress: {0}", section.VirtualAddress);
						Console.WriteLine ("    ImageSectionHeaders.SizeOfRawData: {0}", section.SizeOfRawData);
						Console.WriteLine ("    ImageSectionHeaders.PointerToRawData: {0}", section.PointerToRawData);
						Console.WriteLine ("    ImageSectionHeaders.PointerToRelocations: {0}", section.PointerToRelocations);
						Console.WriteLine ("    ImageSectionHeaders.PointerToLinenumbers: {0}", section.PointerToLinenumbers);
						Console.WriteLine ("    ImageSectionHeaders.NumberOfRelocations: {0}", section.NumberOfRelocations);
						Console.WriteLine ("    ImageSectionHeaders.NumberOfLinenumbers: {0}", section.NumberOfLinenumbers);
						Console.WriteLine ("    ImageSectionHeaders.Characteristics: {0}", section.Characteristics);
					}
				}
			}
		}
	
	}
}
