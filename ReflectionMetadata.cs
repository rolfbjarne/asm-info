using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

public static class Helper {
	public static bool TryGetDebugInfoForAssembly (string file, [NotNullWhen (true)] out string? value)
	{
		value = null;

		using var fs = new FileStream (file, FileMode.Open, FileAccess.Read);
		using var peReader = new PEReader (fs);
		var reader = PEReaderExtensions.GetMetadataReader (peReader);
		var debugDirectory = peReader.ReadDebugDirectory ();

		for (var i = 0; i < debugDirectory.Length; i++) {
			var entry = debugDirectory [i];
			if (entry.Type == DebugDirectoryEntryType.CodeView) {
				var codeViewData = peReader.ReadCodeViewDebugDirectoryData (entry);
				var id = new BlobContentId (codeViewData.Guid, entry.Stamp);
				value = id.AsString ();
				return true;
			}
		}

		return false;
	}

	public static bool TryGetDebugInfoForPortablePdb (string file, [NotNullWhen (true)] out string? value)
	{
		value = null;

		using var fs = new FileStream (file, FileMode.Open, FileAccess.Read);
		using var pdbReaderProvider = MetadataReaderProvider.FromPortablePdbStream (fs);
		var reader = pdbReaderProvider.GetMetadataReader ();
		var header = reader.DebugMetadataHeader;
		if (header is null)
			return false;

		var id = new BlobContentId (header.Id);
		value = id.AsString ();
		return true;
	}

	static string AsString (this BlobContentId self)
	{
		return $"GUID: {self.Guid}, Stamp: {self.Stamp}";
	}
}
