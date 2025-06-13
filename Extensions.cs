
using YARP.Cert;

static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Adds middleware use to verify domain ownership.
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <returns>The application builder</returns>
    public static IApplicationBuilder UseHttpChallengeResponseMiddleware(this IApplicationBuilder app)
    {
        app.Map("/.well-known/acme-challenge", mapped =>
        {
            mapped.UseMiddleware<HttpChallengeResponseMiddleware>();
        });
        return app;
    }
}