// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.AspNetCore.OAuth2Introspection;
using Spirebyte.Shared.IdentityServer.CustomOAuth2Introspection.Context;
using AuthenticationFailedContext = Spirebyte.Shared.IdentityServer.CustomOAuth2Introspection.Context.AuthenticationFailedContext;
using TokenValidatedContext = Spirebyte.Shared.IdentityServer.CustomOAuth2Introspection.Context.TokenValidatedContext;
using UpdateClientAssertionContext = Spirebyte.Shared.IdentityServer.CustomOAuth2Introspection.Context.UpdateClientAssertionContext;

namespace Spirebyte.Shared.IdentityServer.CustomOAuth2Introspection
{
    /// <summary>
    /// Default implementation.
    /// </summary>
    public class ExtendedOAuth2IntrospectionEvents
    {
        /// <summary>
        /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
        /// </summary>
        public Func<AuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
        /// </summary>
        public Func<TokenValidatedContext, Task> OnTokenValidated { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked when client assertion need to be updated.
        /// </summary>
        public Func<UpdateClientAssertionContext, Task> OnUpdateClientAssertion { get; set; } = context => Task.CompletedTask;
        
        public Func<OAuth2ChallengeContext, Task> OnChallenge { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
        /// </summary>
        public virtual Task AuthenticationFailed(AuthenticationFailedContext context) => OnAuthenticationFailed(context);

        /// <summary>
        /// Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
        /// </summary>
        public virtual Task TokenValidated(TokenValidatedContext context) => OnTokenValidated(context);

        /// <summary>
        /// Invoked when client assertion need to be updated.
        /// </summary>
        public virtual Task UpdateClientAssertion(UpdateClientAssertionContext context) => OnUpdateClientAssertion(context);
        
        public virtual Task Challenge(OAuth2ChallengeContext context) => OnChallenge(context);

    }
}