using McMaster.AspNetCore.Kestrel.Certificates;
using Microsoft.AspNetCore.Connections;
using System.Security.Cryptography.X509Certificates;

namespace YARP.Cert;

public class ServerCertificateSelector(AcmeCertificateFactory acmeCertificateFactory, CertificateRepository certificateStore, ILogger<ServerCertificateSelector> logger) : IServerCertificateSelector
{
	public X509Certificate2 Select(ConnectionContext context, string domainName)
	{
		var cert = certificateStore.GetCertificate(domainName);
		if (cert == null || cert.NotAfter < DateTime.UtcNow.AddDays(5))
		{
			Task.Run(async () =>
			{
				try
				{
					await acmeCertificateFactory.CreateCertificateAsync(domainName);
				}
				catch (Exception ex)
				{
					logger.LogError(ex, "Failed to create certificate for {domain}", domainName);
				}
			});
		}
		return cert;
	}
}