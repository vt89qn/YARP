using Serilog;
using YARP;


var builder = WebApplication.CreateBuilder(args);

builder.Host.UseWindowsService();

SystemConsts.BASE_PATH = @"C:/YARP";

foreach (var file in Directory.EnumerateFiles($@"{SystemConsts.BASE_PATH}/Configs", "*.json", SearchOption.AllDirectories))
{
	builder.Configuration.AddJsonFile(file, optional: true, reloadOnChange: true);
}

builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

builder.Services.AddCert();

builder.Host.UseSerilog();

var app = builder.Build();
app.MapReverseProxy();
app.Run();