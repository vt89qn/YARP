using YARP;
using YARP.ReverseProxy;


var builder = WebApplication.CreateBuilder(args);

builder.Host.UseWindowsService();

var basePath = builder.Configuration.GetValue<string>("Settings:BasePath");

foreach (var file in Directory.EnumerateFiles(Path.Combine(basePath, "Configs"), "*.json", SearchOption.AllDirectories))
{
	builder.Configuration.AddJsonFile(file, optional: true, reloadOnChange: true);
}

builder.Services.AddReverseProxy().LoadFromReverseProxyConfig(builder.Configuration.GetSection("ReverseProxy"));

builder.Services.Configure<AppSettings>(builder.Configuration.GetSection("Settings"));

builder.Services.AddCert();

builder.Host.AddLog(Path.Combine(basePath, "Logs"));

var app = builder.Build();
app.MapReverseProxy();
app.Run();