using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;

namespace YARP.Cert;

public class AcmeCertificateFactory(AccountStore accountStore, CertificateRepository certificateStore, HttpChallengeResponseStore challengeStore, ILogger<AcmeCertificateFactory> logger)
{
	private AcmeClient client;
	private IKey acmeAccountKey;

	private static readonly SemaphoreSlim clientCreationLock = new(1, 1);
	private readonly ConcurrentDictionary<string, SemaphoreSlim> domainLocks = new();

	public async Task CreateAcmeClientAsync()
	{
		if (client != null) return;
		await clientCreationLock.WaitAsync();
		if (client != null) return;
		try
		{
			var account = accountStore.GetAccount();
			acmeAccountKey = account != null
				? KeyFactory.FromDer(account.PrivateKey)
				: KeyFactory.NewKey(Certes.KeyAlgorithm.ES256);
			client = new AcmeClient(WellKnownServers.LetsEncryptV2, acmeAccountKey);
			if (account == null || !await existingAccountIsValidAsync())
			{
				await createAccountAsync();
			}
		}
		catch (Exception ex)
		{
			logger.LogError(ex, "CreateAcmeClientAsync");
		}
		finally
		{
			clientCreationLock.Release();
		}
	}
	private async Task<AccountModel> createAccountAsync()
	{
		try
		{
			await client.CreateAccountAsync(SystemConsts.SSL_Email);

			var accountModel = new AccountModel
			{
				Id = 0,
				EmailAddresses = [SystemConsts.SSL_Email],
				PrivateKey = acmeAccountKey.ToDer(),
			};

			accountStore.SaveAccount(accountModel);

			return accountModel;
		}
		catch (Exception ex)
		{
			logger.LogError(ex, "CreateAccountAsync");
		}
		return null;
	}

	private async Task<bool> existingAccountIsValidAsync()
	{
		// double checks the account is still valid
		Account existingAccount;
		try
		{
			existingAccount = await client.GetAccountAsync();
		}
		catch (AcmeRequestException exception)
		{
			logger.LogWarning(
				"An account key was found, but could not be matched to a valid account. Validation error: {acmeError}",
				exception.Error);
			return false;
		}

		if (existingAccount.Status != AccountStatus.Valid)
		{
			logger.LogWarning(
				"An account key was found, but the account is no longer valid. Account status: {status}." +
				"A new account will be registered.",
				existingAccount.Status);
			return false;
		}

		return true;
	}

	public async Task CreateCertificateAsync(string domainName)
	{
		await CreateAcmeClientAsync();
		var domainLock = domainLocks.GetOrAdd(domainName, _ => new SemaphoreSlim(1, 1));
		await domainLock.WaitAsync();
		try
		{
			var existingCert = certificateStore.GetCertificate(domainName);
			if (existingCert != null && existingCert.NotAfter > DateTime.UtcNow.AddDays(7))
			{
				return;
			}

			var order = await client.CreateOrderAsync(domainName);

			var authorizations = await client.GetOrderAuthorizations(order);
			if (!await validateDomainOwnershipAsync(authorizations.First()))
			{
				return;
			}
			var cert = await completeCertificateRequestAsync(order, domainName);

			if (cert != null)
			{
				certificateStore.Save(cert, domainName);
			}
		}
		catch (Exception ex)
		{
			logger.LogError(ex, "CreateCertificateAsync");
		}
		finally
		{
			domainLock.Release();
			domainLocks.TryRemove(domainName, out _);
		}
	}

	private async Task<bool> validateDomainOwnershipAsync(IAuthorizationContext authorizationContext)
	{
		var authorization = await client.GetAuthorizationAsync(authorizationContext);
		var domainName = authorization.Identifier.Value;

		if (authorization.Status == AuthorizationStatus.Valid)
		{
			// Short circuit if authorization is already complete
			return true;
		}
		try
		{
			var validator = new Http01DomainValidator(challengeStore, client, domainName, logger);

			await validator.ValidateOwnershipAsync(authorizationContext);
			return true;
		}
		catch (Exception ex)
		{
			logger.LogError(ex, "validator.ValidateOwnershipAsync");
		}
		return false;
	}

	private async Task<X509Certificate2> completeCertificateRequestAsync(IOrderContext order, string domainName)
	{
		if (client == null)
		{
			throw new InvalidOperationException();
		}

		var csrInfo = new CsrInfo
		{
			CommonName = domainName,
		};
		var privateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
		var acmeCert = await client.GetCertificateAsync(csrInfo, privateKey, order);

		var pfxBuilder = acmeCert.ToPfx(privateKey);
		var pfxBytes = pfxBuilder.Build(domainName, string.Empty);

		return X509CertificateLoader.LoadPkcs12(pfxBytes, string.Empty, X509KeyStorageFlags.Exportable);
	}
}
