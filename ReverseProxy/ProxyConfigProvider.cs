using Microsoft.Extensions.Primitives;
using System.Diagnostics.CodeAnalysis;
using System.Security.Authentication;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace YARP.ReverseProxy;

internal sealed class ProxyConfigProvider(
	ILogger<ProxyConfigProvider> logger,
	IConfiguration configuration) : IProxyConfigProvider, IDisposable
{
	private readonly object _lockObject = new();
	private readonly ILogger<ProxyConfigProvider> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
	private readonly IConfiguration _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
	private ConfigurationSnapshot _snapshot;
	private CancellationTokenSource _changeToken;
	private bool _disposed;
	private IDisposable _subscription;

	public void Dispose()
	{
		if (!_disposed)
		{
			_subscription?.Dispose();
			_changeToken?.Dispose();
			_disposed = true;
		}
	}

	public IProxyConfig GetConfig()
	{
		// First time load
		if (_snapshot is null)
		{
			_subscription = ChangeToken.OnChange(_configuration.GetReloadToken, updateSnapshot);
			updateSnapshot();
		}

		return _snapshot;
	}

	[MemberNotNull(nameof(_snapshot))]
	private void updateSnapshot()
	{
		// Prevent overlapping updates, especially on startup.
		lock (_lockObject)
		{
			Log.LoadData(_logger);
			ConfigurationSnapshot newSnapshot;
			try
			{
				newSnapshot = new ConfigurationSnapshot();

				foreach (var section in _configuration.GetSection("Clusters").GetChildren())
				{
					newSnapshot.Clusters.Add(createCluster(section));
				}

				foreach (var section in _configuration.GetSection("Routes").GetChildren())
				{
					newSnapshot.Routes.Add(createRoute(section));
				}

				var hostMaps = _configuration.GetSection("HostMaps").Get<Dictionary<string, List<HostMap>>>().
					SelectMany(pair => pair.Value).ToList() ?? [];
				if (hostMaps != null)
				{
					// Logic chuyển đổi giống hệt như trước
					foreach (var map in hostMaps)
					{
						var hostId = $"{map.Hosts.First()}_{Guid.NewGuid().ToString().Split('-').First()}";
						var routeId = $"route_{hostId}";
						var clusterId = $"cluster_{hostId}";

						newSnapshot.Clusters.Add(new ClusterConfig
						{
							ClusterId = clusterId,
							Destinations = new Dictionary<string, DestinationConfig>(StringComparer.OrdinalIgnoreCase)
							{
								{ $"destination1", new DestinationConfig{Address = map.Target} }
							}
						});
						newSnapshot.Routes.Add(new RouteConfig
						{
							RouteId = routeId,
							ClusterId = clusterId,
							Match = new RouteMatch
							{
								Hosts = map.Hosts,
								Path = "/{**catch-all}"
							}
						});
					}
				}

			}
			catch (Exception ex)
			{
				Log.ConfigurationDataConversionFailed(_logger, ex);

				// Re-throw on the first time load to prevent app from starting.
				if (_snapshot is null)
				{
					throw;
				}

				return;
			}

			var oldToken = _changeToken;
			_changeToken = new CancellationTokenSource();
			newSnapshot.ChangeToken = new CancellationChangeToken(_changeToken.Token);
			_snapshot = newSnapshot;

			try
			{
				oldToken?.Cancel(throwOnFirstException: false);
			}
			catch (Exception ex)
			{
				Log.ErrorSignalingChange(_logger, ex);
			}
		}
	}

	private static ClusterConfig createCluster(IConfigurationSection section)
	{
		var destinations = new Dictionary<string, DestinationConfig>(StringComparer.OrdinalIgnoreCase);
		foreach (var destination in section.GetSection(nameof(ClusterConfig.Destinations)).GetChildren())
		{
			destinations.Add(destination.Key, createDestination(destination));
		}

		return new ClusterConfig
		{
			ClusterId = section.Key,
			LoadBalancingPolicy = section[nameof(ClusterConfig.LoadBalancingPolicy)],
			SessionAffinity = createSessionAffinityConfig(section.GetSection(nameof(ClusterConfig.SessionAffinity))),
			HealthCheck = createHealthCheckConfig(section.GetSection(nameof(ClusterConfig.HealthCheck))),
			HttpClient = createHttpClientConfig(section.GetSection(nameof(ClusterConfig.HttpClient))),
			HttpRequest = createProxyRequestConfig(section.GetSection(nameof(ClusterConfig.HttpRequest))),
			Metadata = section.GetSection(nameof(ClusterConfig.Metadata)).ReadStringDictionary(),
			Destinations = destinations,
		};
	}

	private static RouteConfig createRoute(IConfigurationSection section)
	{
		if (!string.IsNullOrEmpty(section["RouteId"]))
		{
			throw new Exception("The route config format has changed, routes are now objects instead of an array. The route id must be set as the object name, not with the 'RouteId' field.");
		}

		return new RouteConfig
		{
			RouteId = section.Key,
			Order = section.ReadInt32(nameof(RouteConfig.Order)),
			MaxRequestBodySize = section.ReadInt64(nameof(RouteConfig.MaxRequestBodySize)),
			ClusterId = section[nameof(RouteConfig.ClusterId)],
			AuthorizationPolicy = section[nameof(RouteConfig.AuthorizationPolicy)],
			RateLimiterPolicy = section[nameof(RouteConfig.RateLimiterPolicy)],
			OutputCachePolicy = section[nameof(RouteConfig.OutputCachePolicy)],
			TimeoutPolicy = section[nameof(RouteConfig.TimeoutPolicy)],
			Timeout = section.ReadTimeSpan(nameof(RouteConfig.Timeout)),
			CorsPolicy = section[nameof(RouteConfig.CorsPolicy)],
			Metadata = section.GetSection(nameof(RouteConfig.Metadata)).ReadStringDictionary(),
			Transforms = createTransforms(section.GetSection(nameof(RouteConfig.Transforms))),
			Match = createRouteMatch(section.GetSection(nameof(RouteConfig.Match))),
		};
	}

	private static Dictionary<string, string>[] createTransforms(IConfigurationSection section)
	{
		if (section.GetChildren() is var children && !children.Any())
		{
			return null;
		}

		return children
			.Select(subSection => subSection.GetChildren().ToDictionary(d => d.Key, d => d.Value!, StringComparer.OrdinalIgnoreCase))
			.ToArray();
	}

	private static RouteMatch createRouteMatch(IConfigurationSection section)
	{
		if (!section.Exists())
		{
			return new RouteMatch();
		}

		return new RouteMatch()
		{
			Methods = section.GetSection(nameof(RouteMatch.Methods)).ReadStringArray(),
			Hosts = section.GetSection(nameof(RouteMatch.Hosts)).ReadStringArray(),
			Path = section[nameof(RouteMatch.Path)],
			Headers = createRouteHeaders(section.GetSection(nameof(RouteMatch.Headers))),
			QueryParameters = createRouteQueryParameters(section.GetSection(nameof(RouteMatch.QueryParameters)))
		};
	}

	private static RouteHeader[] createRouteHeaders(IConfigurationSection section)
	{
		if (!section.Exists())
		{
			return null;
		}

		return section.GetChildren().Select(createRouteHeader).ToArray();
	}

	private static RouteHeader createRouteHeader(IConfigurationSection section)
	{
		return new RouteHeader()
		{
			Name = section[nameof(RouteHeader.Name)]!,
			Values = section.GetSection(nameof(RouteHeader.Values)).ReadStringArray(),
			Mode = section.ReadEnum<HeaderMatchMode>(nameof(RouteHeader.Mode)) ?? HeaderMatchMode.ExactHeader,
			IsCaseSensitive = section.ReadBool(nameof(RouteHeader.IsCaseSensitive)) ?? false,
		};
	}

	private static RouteQueryParameter[] createRouteQueryParameters(IConfigurationSection section)
	{
		if (!section.Exists())
		{
			return null;
		}

		return section.GetChildren().Select(createRouteQueryParameter).ToArray();
	}

	private static RouteQueryParameter createRouteQueryParameter(IConfigurationSection section)
	{
		return new RouteQueryParameter()
		{
			Name = section[nameof(RouteQueryParameter.Name)]!,
			Values = section.GetSection(nameof(RouteQueryParameter.Values)).ReadStringArray(),
			Mode = section.ReadEnum<QueryParameterMatchMode>(nameof(RouteQueryParameter.Mode)) ?? QueryParameterMatchMode.Exact,
			IsCaseSensitive = section.ReadBool(nameof(RouteQueryParameter.IsCaseSensitive)) ?? false,
		};
	}

	private static SessionAffinityConfig createSessionAffinityConfig(IConfigurationSection section)
	{
		if (!section.Exists())
		{
			return null;
		}

		return new SessionAffinityConfig
		{
			Enabled = section.ReadBool(nameof(SessionAffinityConfig.Enabled)),
			Policy = section[nameof(SessionAffinityConfig.Policy)],
			FailurePolicy = section[nameof(SessionAffinityConfig.FailurePolicy)],
			AffinityKeyName = section[nameof(SessionAffinityConfig.AffinityKeyName)]!,
			Cookie = createSessionAffinityCookieConfig(section.GetSection(nameof(SessionAffinityConfig.Cookie)))
		};
	}

	private static SessionAffinityCookieConfig createSessionAffinityCookieConfig(IConfigurationSection section)
	{
		if (!section.Exists())
		{
			return null;
		}

		return new SessionAffinityCookieConfig
		{
			Path = section[nameof(SessionAffinityCookieConfig.Path)],
			SameSite = section.ReadEnum<SameSiteMode>(nameof(SessionAffinityCookieConfig.SameSite)),
			HttpOnly = section.ReadBool(nameof(SessionAffinityCookieConfig.HttpOnly)),
			MaxAge = section.ReadTimeSpan(nameof(SessionAffinityCookieConfig.MaxAge)),
			Domain = section[nameof(SessionAffinityCookieConfig.Domain)],
			IsEssential = section.ReadBool(nameof(SessionAffinityCookieConfig.IsEssential)),
			SecurePolicy = section.ReadEnum<CookieSecurePolicy>(nameof(SessionAffinityCookieConfig.SecurePolicy)),
			Expiration = section.ReadTimeSpan(nameof(SessionAffinityCookieConfig.Expiration))
		};
	}

	private static HealthCheckConfig createHealthCheckConfig(IConfigurationSection section)
	{
		if (!section.Exists())
		{
			return null;
		}

		return new HealthCheckConfig
		{
			Passive = createPassiveHealthCheckConfig(section.GetSection(nameof(HealthCheckConfig.Passive))),
			Active = createActiveHealthCheckConfig(section.GetSection(nameof(HealthCheckConfig.Active))),
			AvailableDestinationsPolicy = section[nameof(HealthCheckConfig.AvailableDestinationsPolicy)]
		};
	}

	private static PassiveHealthCheckConfig createPassiveHealthCheckConfig(IConfigurationSection section)
	{
		if (!section.Exists())
		{
			return null;
		}

		return new PassiveHealthCheckConfig
		{
			Enabled = section.ReadBool(nameof(PassiveHealthCheckConfig.Enabled)),
			Policy = section[nameof(PassiveHealthCheckConfig.Policy)],
			ReactivationPeriod = section.ReadTimeSpan(nameof(PassiveHealthCheckConfig.ReactivationPeriod))
		};
	}

	private static ActiveHealthCheckConfig createActiveHealthCheckConfig(IConfigurationSection section)
	{
		if (!section.Exists())
		{
			return null;
		}

		return new ActiveHealthCheckConfig
		{
			Enabled = section.ReadBool(nameof(ActiveHealthCheckConfig.Enabled)),
			Interval = section.ReadTimeSpan(nameof(ActiveHealthCheckConfig.Interval)),
			Timeout = section.ReadTimeSpan(nameof(ActiveHealthCheckConfig.Timeout)),
			Policy = section[nameof(ActiveHealthCheckConfig.Policy)],
			Path = section[nameof(ActiveHealthCheckConfig.Path)],
			Query = section[nameof(ActiveHealthCheckConfig.Query)]
		};
	}

	private static HttpClientConfig createHttpClientConfig(IConfigurationSection section)
	{
		if (!section.Exists())
		{
			return null;
		}

		SslProtocols? sslProtocols = null;
		if (section.GetSection(nameof(HttpClientConfig.SslProtocols)) is IConfigurationSection sslProtocolsSection)
		{
			foreach (var protocolConfig in sslProtocolsSection.GetChildren().Select(s => Enum.Parse<SslProtocols>(s.Value!, ignoreCase: true)))
			{
				sslProtocols = sslProtocols is null ? protocolConfig : sslProtocols | protocolConfig;
			}
		}

		WebProxyConfig webProxy;
		var webProxySection = section.GetSection(nameof(HttpClientConfig.WebProxy));
		if (webProxySection.Exists())
		{
			webProxy = new WebProxyConfig()
			{
				Address = webProxySection.ReadUri(nameof(WebProxyConfig.Address)),
				BypassOnLocal = webProxySection.ReadBool(nameof(WebProxyConfig.BypassOnLocal)),
				UseDefaultCredentials = webProxySection.ReadBool(nameof(WebProxyConfig.UseDefaultCredentials))
			};
		}
		else
		{
			webProxy = null;
		}

		return new HttpClientConfig
		{
			SslProtocols = sslProtocols,
			DangerousAcceptAnyServerCertificate = section.ReadBool(nameof(HttpClientConfig.DangerousAcceptAnyServerCertificate)),
			MaxConnectionsPerServer = section.ReadInt32(nameof(HttpClientConfig.MaxConnectionsPerServer)),
			EnableMultipleHttp2Connections = section.ReadBool(nameof(HttpClientConfig.EnableMultipleHttp2Connections)),
			RequestHeaderEncoding = section[nameof(HttpClientConfig.RequestHeaderEncoding)],
			ResponseHeaderEncoding = section[nameof(HttpClientConfig.ResponseHeaderEncoding)],
			WebProxy = webProxy
		};
	}

	private static ForwarderRequestConfig createProxyRequestConfig(IConfigurationSection section)
	{
		if (!section.Exists())
		{
			return null;
		}

		return new ForwarderRequestConfig
		{
			ActivityTimeout = section.ReadTimeSpan(nameof(ForwarderRequestConfig.ActivityTimeout)),
			Version = section.ReadVersion(nameof(ForwarderRequestConfig.Version)),
			VersionPolicy = section.ReadEnum<HttpVersionPolicy>(nameof(ForwarderRequestConfig.VersionPolicy)),
			AllowResponseBuffering = section.ReadBool(nameof(ForwarderRequestConfig.AllowResponseBuffering))
		};
	}

	private static DestinationConfig createDestination(IConfigurationSection section)
	{
		return new DestinationConfig
		{
			Address = section[nameof(DestinationConfig.Address)]!,
			Health = section[nameof(DestinationConfig.Health)],
			Metadata = section.GetSection(nameof(DestinationConfig.Metadata)).ReadStringDictionary(),
			Host = section[nameof(DestinationConfig.Host)]
		};
	}

	private static class Log
	{
		private static readonly Action<ILogger, Exception> _errorSignalingChange = LoggerMessage.Define(
		LogLevel.Error,
			EventIds.ErrorSignalingChange,
			"An exception was thrown from the change notification.");

		private static readonly Action<ILogger, Exception> _loadData = LoggerMessage.Define(
		LogLevel.Information,
			EventIds.LoadData,
			"Loading proxy data from config.");

		private static readonly Action<ILogger, Exception> _configurationDataConversionFailed = LoggerMessage.Define(
			LogLevel.Error,
			EventIds.ConfigurationDataConversionFailed,
			"Configuration data conversion failed.");

		public static void ErrorSignalingChange(ILogger logger, Exception exception)
		{
			_errorSignalingChange(logger, exception);
		}

		public static void LoadData(ILogger logger)
		{
			_loadData(logger, null);
		}

		public static void ConfigurationDataConversionFailed(ILogger logger, Exception exception)
		{
			_configurationDataConversionFailed(logger, exception);
		}
	}
}
