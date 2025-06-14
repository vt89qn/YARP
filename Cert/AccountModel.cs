using System.Text.Json.Serialization;
using Certes;

namespace YARP.Cert;
public class AccountModel
{
    private byte[] _privateKey = Array.Empty<byte>();

    /// <summary>
    /// A unique identifier.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// A list of email addresses associated with the account.
    /// At least one should be specified.
    /// </summary>
    public string[] EmailAddresses { get; set; } = Array.Empty<string>();

    /// <summary>
    /// The private key for the account.
    /// This should be DER encoded key content.
    /// </summary>
    public byte[] PrivateKey
    {
        get => _privateKey;
        set
        {
            _privateKey = value;
            Key = KeyFactory.FromDer(value);
        }
    }

    [JsonIgnore] internal IKey Key { get; private set; }
}