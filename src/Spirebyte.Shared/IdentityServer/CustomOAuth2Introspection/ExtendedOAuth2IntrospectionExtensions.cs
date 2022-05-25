// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Spirebyte.Shared.IdentityServer.CustomOAuth2Introspection;

/// <summary>
///     Extensions for registering the OAuth 2.0 introspection authentication handler
/// </summary>
public static class ExtendedOAuth2IntrospectionExtensions
{
    /// <summary>
    ///     Adds the OAuth 2.0 introspection handler.
    /// </summary>
    /// <param name="builder">The builder.</param>
    /// <returns></returns>
    public static AuthenticationBuilder AddExtendedOAuth2Introspection(this AuthenticationBuilder builder)
    {
        return builder.AddExtendedOAuth2Introspection(ExtendedOAuth2IntrospectionDefaults.AuthenticationScheme);
    }

    /// <summary>
    ///     Adds the OAuth 2.0 introspection handler.
    /// </summary>
    /// <param name="builder">The builder.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <returns></returns>
    public static AuthenticationBuilder AddExtendedOAuth2Introspection(this AuthenticationBuilder builder,
        string authenticationScheme)
    {
        return builder.AddExtendedOAuth2Introspection(authenticationScheme, null);
    }

    /// <summary>
    ///     Adds the OAuth 2.0 introspection handler.
    /// </summary>
    /// <param name="services">The services.</param>
    /// <param name="configureOptions">The configure options.</param>
    /// <returns></returns>
    public static AuthenticationBuilder AddExtendedOAuth2Introspection(this AuthenticationBuilder services,
        Action<ExtendedOAuth2IntrospectionOptions> configureOptions)
    {
        return services.AddExtendedOAuth2Introspection(ExtendedOAuth2IntrospectionDefaults.AuthenticationScheme,
            configureOptions);
    }


    /// <summary>
    ///     Adds the OAuth 2.0 introspection handler.
    /// </summary>
    /// <param name="builder">The builder.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="configureOptions">The configure options.</param>
    /// <returns></returns>
    public static AuthenticationBuilder AddExtendedOAuth2Introspection(this AuthenticationBuilder builder,
        string authenticationScheme, Action<ExtendedOAuth2IntrospectionOptions> configureOptions)
    {
        builder.Services.AddHttpClient(ExtendedOAuth2IntrospectionDefaults.BackChannelHttpClientName);

        builder.Services.TryAddEnumerable(ServiceDescriptor
            .Singleton<IPostConfigureOptions<ExtendedOAuth2IntrospectionOptions>,
                PostConfigureOAuth2IntrospectionOptions>());
        return builder.AddScheme<ExtendedOAuth2IntrospectionOptions, ExtendedOAuth2IntrospectionHandler>(
            authenticationScheme, configureOptions);
    }
}