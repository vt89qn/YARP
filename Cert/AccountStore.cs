using System.Text.Json;
namespace YARP.Cert;

public class AccountStore()
{
    readonly string accountPath = $@"{SystemConsts.BASE_PATH}/SSL/account.json";
    public AccountModel GetAccount()
    {
        if (File.Exists(accountPath))
        {
            var account = JsonSerializer.Deserialize<AccountModel>(File.ReadAllText(accountPath));
            return account;
        }
        return null;
    }

    public void SaveAccount(AccountModel account)
    {
        File.WriteAllText(accountPath, JsonSerializer.Serialize(account));
    }
}