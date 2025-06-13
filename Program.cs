using McMaster.AspNetCore.Kestrel.Certificates;
using Serilog;
using Serilog.Events;
using YARP;
using YARP.Cert;


// namespace YARP;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseWindowsService();

SystemConsts.BASE_PATH = builder.Environment.ContentRootPath;

foreach (var file in Directory.EnumerateFiles($@"{SystemConsts.BASE_PATH}/Configs", "*.json", SearchOption.AllDirectories))
{
	builder.Configuration.AddJsonFile(file, optional: true, reloadOnChange: true);
}

builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

builder.Services.AddSingleton<HttpChallengeResponseStore>()
.AddSingleton<HttpChallengeResponseMiddleware>()
.AddSingleton<CertificateRepository>()
.AddSingleton<AccountStore>()
.AddSingleton<AcmeCertificateFactory>()
.AddSingleton<IServerCertificateSelector, ServerCertificateSelector>();
builder.WebHost.ConfigureKestrel(options =>
{
	options.ConfigureHttpsDefaults(configureOptions =>
	{
		configureOptions.ServerCertificateSelector = (context, name) =>
	   {
		   var selector = options.ApplicationServices.GetRequiredService<IServerCertificateSelector>();
		   return selector.Select(context, name);
	   };
	});
});

builder.Host.UseSerilog((context, configuration) =>
configuration.ReadFrom.Configuration(context.Configuration).Enrich.FromLogContext()
.MinimumLevel.Debug().MinimumLevel.Override("Microsoft", LogEventLevel.Warning).MinimumLevel.Override("System", LogEventLevel.Warning)
.WriteTo.Logger(lc => lc.Filter.ByIncludingOnly($"@l in ['Error', 'Warning']")
				.WriteTo.File(path: $@"{SystemConsts.BASE_PATH}/Logs/error-.log", rollingInterval: RollingInterval.Day, retainedFileCountLimit: 24
					, outputTemplate: "{Timestamp:HHmmss.fff}	{Message:lj}{NewLine}{Exception}"))
);

var app = builder.Build();
app.MapReverseProxy();
app.UseHttpChallengeResponseMiddleware();

app.Run();