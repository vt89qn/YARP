// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Certes.Acme;
using Certes.Acme.Resource;

namespace YARP.Cert;

class Http01DomainValidator(HttpChallengeResponseStore challengeStore, AcmeClient client, string domainName, ILogger logger)
{
	public async Task ValidateOwnershipAsync(IAuthorizationContext authzContext)
	{
		await PrepareHttpChallengeResponseAsync(authzContext);
		await WaitForChallengeResultAsync(authzContext);
	}

	private async Task PrepareHttpChallengeResponseAsync(
		IAuthorizationContext authorizationContext)
	{
		if (client == null)
		{
			throw new InvalidOperationException();
		}

		var httpChallenge = await client.CreateChallengeAsync(authorizationContext, ChallengeTypes.Http01);
		if (httpChallenge == null)
		{
			throw new InvalidOperationException(
				$"Did not receive challenge information for challenge type {ChallengeTypes.Http01}");
		}

		var keyAuth = httpChallenge.KeyAuthz;
		challengeStore.AddChallengeResponse(httpChallenge.Token, keyAuth);
		await client.ValidateChallengeAsync(httpChallenge);
	}
	async Task WaitForChallengeResultAsync(IAuthorizationContext authorizationContext)
	{
		var retries = 60;
		var delay = TimeSpan.FromSeconds(2);

		while (retries > 0)
		{
			retries--;

			var authorization = await client.GetAuthorizationAsync(authorizationContext);



			switch (authorization.Status)
			{
				case AuthorizationStatus.Valid:
					return;
				case AuthorizationStatus.Pending:
					await Task.Delay(delay);
					continue;
				case AuthorizationStatus.Invalid:
					throw InvalidAuthorizationError(authorization);
				case AuthorizationStatus.Revoked:
					throw new InvalidOperationException(
						$"The authorization to verify domainName '{domainName}' has been revoked.");
				case AuthorizationStatus.Expired:
					throw new InvalidOperationException(
						$"The authorization to verify domainName '{domainName}' has expired.");
				case AuthorizationStatus.Deactivated:
				default:
					throw new ArgumentOutOfRangeException("authorization",
						"Unexpected response from server while validating domain ownership.");
			}
		}

		throw new TimeoutException("Timed out waiting for domain ownership validation.");
	}

	private Exception InvalidAuthorizationError(Authorization authorization)
	{
		var reason = "unknown";
		var domainName = authorization.Identifier.Value;
		try
		{
			var errors = authorization.Challenges.Where(a => a.Error != null).Select(a => a.Error)
				.Select(error => $"{error.Type}: {error.Detail}, Code = {error.Status}");
			reason = string.Join("; ", errors);
		}
		catch
		{
			logger.LogTrace("Could not determine reason why validation failed. Response: {resp}", authorization);
		}

		logger.LogError("Failed to validate ownership of domainName '{domainName}'. Reason: {reason}", domainName,
			reason);

		return new InvalidOperationException($"Failed to validate ownership of domainName '{domainName}'");
	}
}
