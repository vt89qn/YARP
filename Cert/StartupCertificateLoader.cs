namespace YARP.Cert;

class StartupCertificateLoader(CertificateRepository certificateStore, ILogger<StartupCertificateLoader> logger) : IHostedService
{
	public async Task StartAsync(CancellationToken cancellationToken)
	{
		try
		{
			certificateStore.Initialize();
			await Task.CompletedTask;
		}
		catch (Exception ex)
		{
			logger.LogError(ex, "StartupCertificateLoader->StartAsync");
			throw;
		}
	}

	public Task StopAsync(CancellationToken cancellationToken)
		=> Task.CompletedTask;
}