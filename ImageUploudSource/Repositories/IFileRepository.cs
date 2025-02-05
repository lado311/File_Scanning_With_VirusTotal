namespace ImageUploudSource.Repositories
{
    public interface IFileRepository
    {
        Task<bool> ScanFileWithVirusTotal(string filePath);
        Task<string> UploadAndScanImage(IFormFile file);
    }
}
