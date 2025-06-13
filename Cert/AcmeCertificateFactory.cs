using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;

namespace YARP.Cert;

public class AcmeCertificateFactory(AccountStore accountStore, CertificateRepository certificateStore, HttpChallengeResponseStore challengeStore, IOptions<AppSettings> settings, ILogger<AcmeCertificateFactory> logger)
{
	//private AcmeClient client;


	private AcmeContext context;
	//private IAccountContext accountContext;

	private static readonly SemaphoreSlim contextCreationLock = new(1, 1);
	private readonly ConcurrentDictionary<string, SemaphoreSlim> domainLocks = new();

	async Task<Account> getAccountAsync()
	{
		var accountContext = await context.Account();
		return await accountContext.Resource();
	}
	async Task<AccountModel> createAccountAsync(IKey acmeAccountKey)
	{
		try
		{
			var acmeEmail = settings.Value.AcmeEmail;
			var accountContext = await context.NewAccount(acmeEmail, termsOfServiceAgreed: true);

			var accountModel = new AccountModel
			{
				Id = 0,
				EmailAddresses = [acmeEmail],
				PrivateKey = acmeAccountKey.ToDer(),
			};

			await accountStore.SaveAccountAsync(accountModel);

			return accountModel;
		}
		catch (Exception ex)
		{
			logger.LogError(ex, "createAccountAsync");
		}
		return null;
	}
	async Task createAcmeContextAsync()
	{
		if (context != null) return;
		await contextCreationLock.WaitAsync();
		if (context != null) return;
		try
		{
			var account = await accountStore.GetAccountAsync();
			var acmeAccountKey = account != null
				? KeyFactory.FromDer(account.PrivateKey)
				: KeyFactory.NewKey(Certes.KeyAlgorithm.ES256);
			context = new(WellKnownServers.LetsEncryptV2, acmeAccountKey);
			if (account == null || !await existingAccountIsValidAsync())
			{
				await createAccountAsync(acmeAccountKey);
			}
		}
		catch (Exception ex)
		{
			logger.LogError(ex, "createAcmeContextAsync");
		}
		finally
		{
			contextCreationLock.Release();
		}
	}



	private async Task<bool> existingAccountIsValidAsync()
	{
		// double checks the account is still valid
		Account existingAccount;
		try
		{
			existingAccount = await getAccountAsync();
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
		await createAcmeContextAsync();
		var domainLock = domainLocks.GetOrAdd(domainName, _ => new SemaphoreSlim(1, 1));
		await domainLock.WaitAsync();
		try
		{
			var existingCert = certificateStore.GetCertificate(domainName);
			if (existingCert != null && existingCert.NotAfter > DateTime.UtcNow.AddDays(7))
			{
				return;
			}

			var order = await context.NewOrder([domainName]);

			var authorizations = await order.Authorizations();
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
			logger.LogError(ex, "createAcmeContextAsync");
		}
		finally
		{
			domainLock.Release();
			domainLocks.TryRemove(domainName, out _);
		}
	}

	private async Task<bool> validateDomainOwnershipAsync(IAuthorizationContext authorizationContext)
	{
		var authorization = await authorizationContext.Resource();
		var domainName = authorization.Identifier.Value;

		if (authorization.Status == AuthorizationStatus.Valid)
		{
			// Short circuit if authorization is already complete
			return true;
		}
		try
		{
			var validator = new Http01DomainValidator(challengeStore, domainName, logger);

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
		var csrInfo = new CsrInfo
		{
			CommonName = domainName,
		};
		var privateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
		var acmeCert = await order.Generate(csrInfo, privateKey);

		var pfxBuilder = acmeCert.ToPfx(privateKey);
		var pfxBytes = pfxBuilder.Build(domainName, string.Empty);

		return X509CertificateLoader.LoadPkcs12(pfxBytes, string.Empty, X509KeyStorageFlags.Exportable);
	}
}
