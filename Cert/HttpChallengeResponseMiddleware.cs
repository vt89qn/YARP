// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace YARP.Cert;

public class HttpChallengeResponseMiddleware(
    HttpChallengeResponseStore responseStore,
    ILogger<HttpChallengeResponseMiddleware> logger) : IMiddleware
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        // assumes that this middleware has been mapped
        var token = context.Request.Path.ToString();
        if (token.StartsWith("/"))
        {
            token = token[1..];
        }

        if (!responseStore.TryGetResponse(token, out var value))
        {
            await next(context);
            return;
        }

        logger.LogDebug("Confirmed challenge request for {token}", token);

        context.Response.ContentLength = value?.Length ?? 0;
        context.Response.ContentType = "application/octet-stream";
        await context.Response.WriteAsync(value!, context.RequestAborted);
    }
}
