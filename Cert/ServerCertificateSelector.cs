
using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using McMaster.AspNetCore.Kestrel.Certificates;
using Microsoft.AspNetCore.Connections;

namespace YARP.Cert;

public class ServerCertificateSelector(AcmeCertificateFactory acmeCertificateFactory,CertificateRepository certificateStore) : IServerCertificateSelector
{
    public X509Certificate2 Select(ConnectionContext context, string domainName)
    {
        var cert = certificateStore.GetCertificate(domainName);
        if (cert == null || cert.NotAfter < DateTime.UtcNow.AddDays(5))
        {
            _ = acmeCertificateFactory.CreateCertificateAsync(domainName, CancellationToken.None);
        }
        return cert;
    }
}