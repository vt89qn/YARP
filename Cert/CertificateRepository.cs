
using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;

namespace YARP.Cert;

public class CertificateRepository(ILogger<CertificateRepository> logger)
{
	readonly string certsPath = $@"{SystemConsts.BASE_PATH}/SSL/certs";
	private readonly ConcurrentDictionary<string, X509Certificate2> certs =
		new(StringComparer.OrdinalIgnoreCase);

	public void Initialize()
	{
		var allCert = Directory.GetFiles(certsPath, "*.pfx")
			.Select(x => new { file = x, cert = X509CertificateLoader.LoadPkcs12(File.ReadAllBytes(x), string.Empty), domain = Path.GetFileName(x).Split('_').First().ToLower() }).ToList();

		var validCerts = allCert.Where(x => x.cert.NotAfter > DateTime.UtcNow.AddDays(1))
		 .GroupBy(x => x.domain).Select(x => new { domain = x.Key, x.OrderByDescending(y => y.cert.NotAfter).First().cert })
		 .ToList();
		foreach (var x in validCerts)
		{
			certs[x.domain] = x.cert;
		}
		foreach (var cert in allCert)
		{
			if (!validCerts.Any(x => x.cert == cert.cert))
			{
				try
				{
					File.Delete(cert.file);
				}
				catch (Exception ex)
				{
					logger.LogError(ex, "CertificateRepository->Initialize");
				}
			}
		}
	}
	public X509Certificate2 GetCertificate(string domainName)
	{
		if (certs.TryGetValue(domainName, out var cert) && cert.NotAfter > DateTime.UtcNow.AddDays(1))
		{
			return cert;
		}
		return null;
	}

	public void Save(X509Certificate2 certificate, string domainName)
	{
		certs[domainName] = certificate;
		File.WriteAllBytes($@"{certsPath}/{domainName}_{certificate.Thumbprint}.pfx", certificate.Export(X509ContentType.Pfx));
	}

}