
using McMaster.AspNetCore.Kestrel.Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Options;
using Serilog;
using Serilog.Events;
using YARP.Cert;

namespace YARP;
static class HostBuilderExtensions
{
	public static IHostBuilder UseSerilog(this IHostBuilder builder)
	{
		return builder.UseSerilog((context, configuration) =>
			configuration.ReadFrom.Configuration(context.Configuration).Enrich.FromLogContext()
			.MinimumLevel.Debug().MinimumLevel.Override("Microsoft", LogEventLevel.Warning).MinimumLevel.Override("System", LogEventLevel.Warning)
			.WriteTo.Logger(lc => lc.Filter.ByIncludingOnly($"@l in ['Error', 'Warning']")
							.WriteTo.File(path: $@"{SystemConsts.BASE_PATH}/Logs/error-.log", rollingInterval: RollingInterval.Day, retainedFileCountLimit: 24
								, outputTemplate: "{Timestamp:HHmmss.fff}	{Message:lj}{NewLine}{Exception}"))
			);
	}
}
static class ApplicationBuilderExtensions
{
	public static IApplicationBuilder UseHttpChallengeResponseMiddleware(this IApplicationBuilder app)
	{
		app.Map("/.well-known/acme-challenge", mapped =>
		{
			mapped.UseMiddleware<HttpChallengeResponseMiddleware>();
		});
		return app;
	}
}
static class ServiceCollectionExtensions
{
	public static IServiceCollection AddCert(this IServiceCollection services)
	{
		services.AddTransient<IConfigureOptions<KestrelServerOptions>, KestrelOptionsSetup>();

		services.AddSingleton<HttpChallengeResponseStore>()
			.AddSingleton<HttpChallengeResponseMiddleware>()
			.AddSingleton<CertificateRepository>()
			.AddSingleton<AccountStore>()
			.AddSingleton<AcmeCertificateFactory>()
			.AddSingleton<IHostedService, StartupCertificateLoader>()
			.AddSingleton<IStartupFilter, HttpChallengeStartupFilter>()
			.AddSingleton<IServerCertificateSelector, ServerCertificateSelector>();
		return services;
	}
}
static class KestrelHttpsOptionsExtensions
{
	public static HttpsConnectionAdapterOptions UseCert(
		this HttpsConnectionAdapterOptions httpsOptions,
		IServerCertificateSelector selector)
	{
		httpsOptions.UseServerCertificateSelector(selector);
		return httpsOptions;
	}
}