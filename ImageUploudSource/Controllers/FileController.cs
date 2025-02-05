using ImageUploudSource.Repositories;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace ImageUploudSource.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class FileController(IFileRepository fileRepository) : ControllerBase
    {
        [HttpPost("uploud-file")]
        public async Task<IActionResult> UploudFile(IFormFile file)
        {
            return Ok(await fileRepository.UploadAndScanImage(file));
        }
    }
}
