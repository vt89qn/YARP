using Microsoft.Extensions.Options;
using System.Text.Json;
namespace YARP.Cert;

public class AccountStore(IOptions<AppSettings> settings)
{
	readonly string accountPath = Path.Combine(settings.Value.BasePath, "SSL", "account.json");
	public async Task<AccountModel> GetAccountAsync()
	{
		if (File.Exists(accountPath))
		{
			var json = await File.ReadAllTextAsync(accountPath);
			return JsonSerializer.Deserialize<AccountModel>(json);
		}
		return null;
	}


	public async Task SaveAccountAsync(AccountModel account)
	{
		var json = JsonSerializer.Serialize(account);
		await File.WriteAllTextAsync(accountPath, json);
	}
}