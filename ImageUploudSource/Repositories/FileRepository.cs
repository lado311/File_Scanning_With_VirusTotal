using ImageUploudSource.Exceptions;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace ImageUploudSource.Repositories
{
    public class FileRepository(IConfiguration configuration, IWebHostEnvironment environment) : IFileRepository
    {

        private static readonly List<string> AllowedExtensions = new() { ".txt",".jpg", ".jpeg", ".png", ".gif", ".bmp" };
        private readonly HttpClient client = new HttpClient();
        public async Task<bool> ScanFileWithVirusTotal(string filePath)
        {
            try
            {
                string apiKey = configuration["VirusTotal:ApiKey"];

                string uploadJson = await ScanRequest(apiKey, filePath);
                if (string.IsNullOrEmpty(uploadJson))
                    throw new BadRequestException("upload json not founded");

                // **get Id from Json (file scanning ID)**
                var jsonDoc = JsonDocument.Parse(uploadJson);
                string ScanningId = await GetScanningId(jsonDoc);

                //await Task.Delay(5000);

                if(await ScanResponse(ScanningId))
                    return true;

                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"VirusTotal Error: {ex.Message}");
                return false;
            }
        }

        public async Task<string> ScanRequest(string apiKey, string filePath)
        {
            client.DefaultRequestHeaders.Add("x-apikey", apiKey);

            // **1️⃣ ფაილის ატვირთვა VirusTotal-ზე**
            using var content = new MultipartFormDataContent();
            content.Add(new StreamContent(File.OpenRead(filePath)), "file", Path.GetFileName(filePath));

            var uploadResponse = await client.PostAsync("https://www.virustotal.com/api/v3/files", content);
            var uploadJson = await uploadResponse.Content.ReadAsStringAsync();

            if (!uploadResponse.IsSuccessStatusCode)
            {
                Console.WriteLine($"VirusTotal Upload Failed: {uploadJson}");
                return string.Empty;
            }
            return uploadJson;
        }
        public async Task<bool> ScanResponse(string fileId)
        {
            var scanResponse = await client.GetAsync($"https://www.virustotal.com/api/v3/analyses/{fileId}");
            var scanJson = await scanResponse.Content.ReadAsStringAsync();

            if (!scanResponse.IsSuccessStatusCode)
            {
                Console.WriteLine($"VirusTotal Scan Check Failed: {scanJson}");
                return false;
            }

            var scanDoc = JsonDocument.Parse(scanJson);
            var status = scanDoc.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("status").GetString();

            if (status == "completed")
            {
                int maliciousCount = scanDoc.RootElement
                    .GetProperty("data").GetProperty("attributes")
                    .GetProperty("stats").GetProperty("malicious").GetInt32();

                return maliciousCount == 0; // თუ 0-ია, უსაფრთხოა
            }
            return false;
        }

        public async Task<string> GetScanningId(JsonDocument jsonDocument)
        {
            return jsonDocument.RootElement.GetProperty("data").GetProperty("id").GetString();
        }

        /*public async Task<bool> ScanFileWithVirusTotal(string filePath)
        {
            try
            {
                string apiKey = configuration["VirusTotal:ApiKey"]; //your Virus total API key

                using var client = new HttpClient();
                client.DefaultRequestHeaders.Add("x-apikey", apiKey);

                using var content = new MultipartFormDataContent();
                content.Add(new StreamContent(File.OpenRead(filePath)), "file", Path.GetFileName(filePath));

                var response = await client.PostAsync("https://www.virustotal.com/api/v3/files", content);
                var jsonResponse = await response.Content.ReadAsStringAsync();

                return response.IsSuccessStatusCode && !jsonResponse.Contains("\"malicious\":1");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"VirusTotal Error: {ex.Message}");
                return false;
            }
        }*/


        public async Task<string> UploadAndScanImage(IFormFile file)
        {
            if (file == null || file.Length == 0)
                throw new BadRequestException("file not uplouded");

            var extension = Path.GetExtension(file.FileName).ToLower();
            if (!AllowedExtensions.Contains(extension))
                throw new BadRequestException("you can uploud only pictures type of files");

            if (file.Length > 5 * 1024 * 1024)
                throw new BadRequestException("file size is so many");

            var safeFileName = Path.GetFileNameWithoutExtension(file.FileName);
            safeFileName = string.Join("_", safeFileName.Split(Path.GetInvalidFileNameChars()));
            var newFileName = $"{safeFileName}_{Guid.NewGuid()}{extension}";

            var uploadsFolder = Path.Combine(environment.ContentRootPath, "uploads");
            Directory.CreateDirectory(uploadsFolder);
            var filePath = Path.Combine(uploadsFolder, newFileName);

            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }

            
                // **🔍 2. VirusTotal-ის დამატებითი სკანირება**
            var isSafeWithVirusTotal = await ScanFileWithVirusTotal(filePath);
            if (!isSafeWithVirusTotal)
            {
                File.Delete(filePath); // delete virus file
                throw new BadRequestException("The file contains a virus (VirusTotal). Upload failed.");
            }
            Console.WriteLine($"[INFO] VirusTotal cleared file: {filePath}");

            return filePath;
        }

    }
}
