using System.Diagnostics;
using System.Formats.Tar;
using System.IO;
using System.Threading.Tasks;

namespace SafeFolder; 

public class FilePacker {

    private string directory;
    private static readonly string _safeFolderName = System.Reflection.Assembly.GetExecutingAssembly().Location;
    
    public FilePacker(string directory) {
        this.directory = directory;
    }

    public async Task<Stream> PackIntoTar() {
        var tarStream = new MemoryStream();
        await using var tarWriter = new TarWriter(tarStream, leaveOpen: false);
        foreach (var entry in Directory.EnumerateFileSystemEntries(directory)) {
            if (entry.EndsWith(".enc") || entry == _safeFolderName
#if DEBUG
                || entry.EndsWith(".pdb")
#endif
               ) {
                continue;
            }
            var filename = Path.GetFileName(entry);
            await tarWriter.WriteEntryAsync(entry, filename);
        }

        return tarStream;
    }
}