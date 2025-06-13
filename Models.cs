namespace YARP;
public class AppSettings
{
	public string BasePath { get; set; }
	public string AcmeEmail { get; set; }
}
public class HostMap
{
	public List<string> Hosts { get; set; } = [];
	public string Target { get; set; } = string.Empty;
}