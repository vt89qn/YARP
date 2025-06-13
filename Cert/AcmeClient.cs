using System.Collections.Concurrent;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;

namespace YARP.Cert;
public class AcmeClient( Uri directoryUri, IKey acmeAccountKey)
{
    private readonly AcmeContext context=new(directoryUri, acmeAccountKey);
    private IAccountContext accountContext;
    private readonly ConcurrentDictionary<string, IOrderContext> orders =
        new(StringComparer.OrdinalIgnoreCase);

    public async Task<Account> GetAccountAsync()
    {
        accountContext = await context.Account();
        return await accountContext.Resource();
    }

    public IKey GetAccountKey()
    {
        return acmeAccountKey;
    }

    public async Task CreateAccountAsync(string emailAddress)
    {
        accountContext = await context.NewAccount(emailAddress, termsOfServiceAgreed: true);
    }

    public  IOrderContext GetOrder(string domainName)
    {
        if (orders.TryGetValue(domainName, out var order))
        {
            return order;
        }
        return null;
    }
    public  IOrderContext RemoveOrder(string domainName)
    {
        if (orders.TryRemove(domainName, out var order))
        {
            return order;
        }
        return null;
    }
    public async Task<IOrderContext> CreateOrderAsync(string domainName)
    {
        var order = await context.NewOrder([domainName]);
        orders[domainName] = order;
        return order;
    }

    public async Task<Order> GetOrderDetailsAsync(IOrderContext order)
    {
        return await order.Resource();
    }

    public async Task<IEnumerable<IAuthorizationContext>> GetOrderAuthorizations(IOrderContext orderContext)
    {
        return await orderContext.Authorizations();
    }

    public async Task<Authorization> GetAuthorizationAsync(IAuthorizationContext authorizationContext)
    {
        return await authorizationContext.Resource();
    }

    public async Task<IChallengeContext> CreateChallengeAsync(IAuthorizationContext authorizationContext, string challengeType)
    {
        return await authorizationContext.Challenge(challengeType);
    }

    public async Task<Challenge> ValidateChallengeAsync(IChallengeContext httpChallenge)
    {
        return await httpChallenge.Validate();
    }

    public async Task<CertificateChain> GetCertificateAsync(CsrInfo csrInfo, IKey privateKey, IOrderContext order)
    {
        return await order.Generate(csrInfo, privateKey);
    }
}