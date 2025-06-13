using Microsoft.Extensions.Primitives;
using Yarp.ReverseProxy.Configuration;

namespace YARP.ReverseProxy;
class ConfigurationSnapshot : IProxyConfig
{
	public List<RouteConfig> Routes { get; internal set; } = [];

	public List<ClusterConfig> Clusters { get; internal set; } = [];

	IReadOnlyList<RouteConfig> IProxyConfig.Routes => Routes;

	IReadOnlyList<ClusterConfig> IProxyConfig.Clusters => Clusters;

	// This field is required.
	public IChangeToken ChangeToken { get; internal set; } = default!;
}