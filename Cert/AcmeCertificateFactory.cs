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

	private readonly ConcurrentDictionary<string, IOrderContext> orderings =
		new(StringComparer.OrdinalIgnoreCase);
	public async Task<AccountModel> GetOrCreateAccountAsync()
	{
		try
		{
			var account = accountStore.GetAccount();

			acmeAccountKey = account != null
				? KeyFactory.FromDer(account.PrivateKey)
				: KeyFactory.NewKey(Certes.KeyAlgorithm.ES256);
			client = CreateAcmeClient(acmeAccountKey);
			if (account != null && await existingAccountIsValidAsync())
			{
				return account;
			}

			account = await createAccountAsync();
			return account;
		}
		catch (Exception ex)
		{
			logger.LogError(ex, "GetOrCreateAccountAsync");
		}
		return default;
	}
	public AcmeClient CreateAcmeClient(IKey acmeAccountKey)
	{
		return new AcmeClient(WellKnownServers.LetsEncryptV2, acmeAccountKey);
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
	bool isGettingAccount = false;
	public async Task CreateCertificateAsync(string domainName, CancellationToken cancellationToken)
	{
		cancellationToken.ThrowIfCancellationRequested();
		if (isGettingAccount)
			return;

		if (client == null)
		{
			isGettingAccount = true;
			await GetOrCreateAccountAsync();
			isGettingAccount = false;
		}
		if (orderings.TryGetValue(domainName, out _)) return;
		orderings[domainName] = null;
		try
		{
			var order = await client.CreateOrderAsync(domainName);

			var authorizations = await client.GetOrderAuthorizations(order);

			cancellationToken.ThrowIfCancellationRequested();
			await Task.WhenAll(beginValidateAllAuthorizations(authorizations, cancellationToken));

			cancellationToken.ThrowIfCancellationRequested();
			var cert = await completeCertificateRequestAsync(order, domainName, cancellationToken);

			if (cert != null)
			{
				certificateStore.Save(cert, domainName, cancellationToken);
			}
		}
		catch (Exception ex)
		{
			logger.LogError(ex, "CreateCertificateAsync");
		}
		orderings.TryRemove(domainName, out _);
	}

	private IEnumerable<Task> beginValidateAllAuthorizations(IEnumerable<IAuthorizationContext> authorizations,
		CancellationToken cancellationToken)
	{
		foreach (var authorization in authorizations)
		{
			yield return validateDomainOwnershipAsync(authorization, cancellationToken);
		}
	}

	private async Task validateDomainOwnershipAsync(IAuthorizationContext authorizationContext,
		CancellationToken cancellationToken)
	{
		cancellationToken.ThrowIfCancellationRequested();
		if (client == null)
		{
			throw new InvalidOperationException();
		}

		var authorization = await client.GetAuthorizationAsync(authorizationContext);
		var domainName = authorization.Identifier.Value;

		if (authorization.Status == AuthorizationStatus.Valid)
		{
			// Short circuit if authorization is already complete
			return;
		}

		cancellationToken.ThrowIfCancellationRequested();



		try
		{
			var validator = new Http01DomainValidator(challengeStore, client, domainName, logger);

			await validator.ValidateOwnershipAsync(authorizationContext, cancellationToken);
		}
		catch (Exception ex)
		{
			logger.LogError(ex, "validator.ValidateOwnershipAsync");
		}

		throw new InvalidOperationException($"Failed to validate ownership of domainName '{domainName}'");

	}

	private async Task<X509Certificate2> completeCertificateRequestAsync(IOrderContext order, string domainName,
		CancellationToken cancellationToken)
	{
		cancellationToken.ThrowIfCancellationRequested();
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
