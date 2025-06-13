namespace YARP.Cert;

using McMaster.AspNetCore.Kestrel.Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Options;

public class KestrelOptionsSetup(IServerCertificateSelector certificateSelector) : IConfigureOptions<KestrelServerOptions>
{
	public void Configure(KestrelServerOptions options)
	{
		options.ConfigureHttpsDefaults(httpsOptions => httpsOptions.UseServerCertificateSelector(certificateSelector));
	}
}
