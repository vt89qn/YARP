
using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;

namespace YARP.Cert;

public class CertificateRepository()
{
	readonly string certsPath = $@"{SystemConsts.BASE_PATH}/SSL/certs";
	private readonly ConcurrentDictionary<string, X509Certificate2> certs =
		new(StringComparer.OrdinalIgnoreCase);

	public X509Certificate2 GetCertificate(string domainName)
	{
		if (certs.TryGetValue(domainName, out var cert))
		{
			if (cert?.NotAfter > DateTime.UtcNow.AddDays(1))
			{
				return cert;
			}
			return null;
		}
		var allCerts = Directory.GetFiles(certsPath, "*.pfx").Where(x => Path.GetFileName(x).StartsWith($"{domainName}_"))
		 .Select(x => new { file = x, cert = X509CertificateLoader.LoadPkcs12(File.ReadAllBytes(x), string.Empty) }).ToList();
		var bestCert = allCerts.Where(x => x.cert.NotAfter > DateTime.UtcNow.AddDays(1)).OrderByDescending(x => x.cert.NotAfter).FirstOrDefault();
		if (bestCert == null)
		{
			certs[domainName] = null;
			return null;
		}
		try
		{
			foreach (var allCert in allCerts)
			{
				if (allCert.file != bestCert.file)
				{
					File.Delete(allCert.file);
				}
			}
		}
		catch { }
		certs[domainName] = bestCert.cert;
		return bestCert.cert;
	}

	public void Save(X509Certificate2 certificate, string domainName, CancellationToken cancellationToken)
	{
		certs[domainName] = certificate;
		File.WriteAllBytes($@"{certsPath}/{domainName}_{certificate.Thumbprint}.pfx", certificate.Export(X509ContentType.Pfx));
	}

}