﻿using System.Collections.ObjectModel;
using System.Globalization;
using Yarp.ReverseProxy.Configuration;

namespace YARP.ReverseProxy;

static class ReverseProxyBuilderExtensions
{
	public static IReverseProxyBuilder LoadFromReverseProxyConfig(this IReverseProxyBuilder builder, IConfiguration config)
	{
		IConfiguration config2 = config;
		if (config2 == null)
		{
			throw new ArgumentNullException("config");
		}

		builder.Services.AddSingleton((Func<IServiceProvider, IProxyConfigProvider>)((IServiceProvider sp) => new ProxyConfigProvider(sp.GetRequiredService<ILogger<ProxyConfigProvider>>(), config2)));
		return builder;
	}
}

static class ConfigurationReadingExtensions
{
	internal static int? ReadInt32(this IConfiguration configuration, string name)
	{
		return configuration[name] is string value ? int.Parse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture) : null;
	}

	internal static long? ReadInt64(this IConfiguration configuration, string name)
	{
		return configuration[name] is string value ? long.Parse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture) : null;
	}

	internal static double? ReadDouble(this IConfiguration configuration, string name)
	{
		return configuration[name] is string value ? double.Parse(value, CultureInfo.InvariantCulture) : null;
	}

	internal static TimeSpan? ReadTimeSpan(this IConfiguration configuration, string name)
	{
		// Format "c" => [-][d'.']hh':'mm':'ss['.'fffffff]. 
		// You also can find more info at https://docs.microsoft.com/dotnet/standard/base-types/standard-timespan-format-strings#the-constant-c-format-specifier
		return configuration[name] is string value ? TimeSpan.ParseExact(value, "c", CultureInfo.InvariantCulture) : null;
	}

	internal static Uri ReadUri(this IConfiguration configuration, string name)
	{
		return configuration[name] is string value ? new Uri(value) : null;
	}

	internal static TEnum? ReadEnum<TEnum>(this IConfiguration configuration, string name) where TEnum : struct
	{
		return configuration[name] is string value ? Enum.Parse<TEnum>(value, ignoreCase: true) : null;
	}

	internal static bool? ReadBool(this IConfiguration configuration, string name)
	{
		return configuration[name] is string value ? bool.Parse(value) : null;
	}

	internal static Version ReadVersion(this IConfiguration configuration, string name)
	{
		return configuration[name] is string value && !string.IsNullOrEmpty(value) ? Version.Parse(value + (value.Contains('.') ? "" : ".0")) : null;
	}

	internal static IReadOnlyDictionary<string, string> ReadStringDictionary(this IConfigurationSection section)
	{
		if (section.GetChildren() is var children && !children.Any())
		{
			return null;
		}

		return new ReadOnlyDictionary<string, string>(children.ToDictionary(s => s.Key, s => s.Value!, StringComparer.OrdinalIgnoreCase));
	}

	internal static string[] ReadStringArray(this IConfigurationSection section)
	{
		if (section.GetChildren() is var children && !children.Any())
		{
			return null;
		}

		return children.Select(s => s.Value!).ToArray();
	}
}