using System;
using System.IO;
using System.Threading.Tasks;
using Azure.Storage.Blobs;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.Extensions.Logging;
using nClam;

namespace pocantivirusfuncapp
{
	public static class Function1
    {
        static readonly string serverName = "20.103.95.112";
        static readonly int serverPort = 3310;
        static readonly string quarantineContainer = "defaultcontainer";
        static readonly string cleanContainer = "cleancontainer";
        static readonly string infectedContainer = "infectedcontainer";
        static readonly string conn = "DefaultEndpointsProtocol=https;AccountName=azuredefenderpocsaclamav;AccountKey=xHXkPOBwY7qIcQ4h+qT6t7GWxS09BKXiATu7+rajogsagPprdJiIayjP70meeJ3C7+uLzdu+mb3d+AStqRvyyw==;EndpointSuffix=core.windows.net";
        [FunctionName("scanstorageaccountpocclamav")]
        public static async Task Run([BlobTrigger("defaultcontainer/{name}", Connection = "AzureWebJobsStorage")] Stream myBlob, string name, ILogger log)
        {
            try
            {
                log.LogInformation($"C# Blob trigger function Processed blob\n Name:{name} \n Size: {myBlob.Length} Bytes");
                var clam = new ClamClient(serverName, serverPort);
                bool isClean = false;
                bool pingTest = await clam.PingAsync();

                if (!pingTest)
                {
                    log.LogError("error in pingTest");
                }
                var result = await clam.SendAndScanFileAsync(myBlob);

                switch (result.Result)
                {
                    case ClamScanResults.Clean:
                        log.LogInformation("File is Clean");
                        isClean = true;
                        await MoveContainer(name, log, isClean);
                        break;

                    case ClamScanResults.Unknown:
                        log.LogInformation("Unknown Issue");
                        await MoveContainer(name, log, isClean);
                        break;

                    case ClamScanResults.VirusDetected:
                        log.LogError("Virus Detected in File");
                        await MoveContainer(name, log, isClean);
                        break;

                    case ClamScanResults.Error:
                        log.LogError("Error scanning file");
                        await MoveContainer(name, log, isClean);
                        break;

                    default:
                        log.LogWarning("Default step executed!!!");
                        break;
                }
            }
            catch (Exception ex) { log.LogError(ex.Message); }
        }

        private static async Task DeleteBlob(string name, ILogger log)
        {
            var container = new BlobClient(conn, quarantineContainer, name);
            bool isDeleted = await container.DeleteIfExistsAsync();

            if (isDeleted)
            {
                log.LogInformation($"Suspicious Blob deleted - {name}");
            }
            else
            {
                log.LogWarning($"Suspicious Blob couldn't be deleted - {name}");
            }

        }

        private static async Task MoveContainer(string name, ILogger log, bool isClean)
        {
            var blobServiceClient = new BlobServiceClient(conn);
            var sourceBlobContainerClient = blobServiceClient.GetBlobContainerClient(quarantineContainer);
            var sourceBlobClient = sourceBlobContainerClient.GetBlobClient(name);
            await sourceBlobClient.DownloadToAsync(name);

            if (isClean) // move file to clean container
            {
                var destBlobContainerClient = blobServiceClient.GetBlobContainerClient(cleanContainer);
                var destBlobClient = destBlobContainerClient.GetBlobClient(name);
                await destBlobClient.UploadAsync(name);
            }
            else //move file to infected container
            {
                var destBlobContainerClient = blobServiceClient.GetBlobContainerClient(infectedContainer);
                var destBlobClient = destBlobContainerClient.GetBlobClient(name);
                await destBlobClient.UploadAsync(name);
            }

            await sourceBlobClient.DeleteIfExistsAsync();
        }
    }
}
