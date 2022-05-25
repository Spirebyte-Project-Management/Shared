// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.AspNetCore.OAuth2Introspection;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Spirebyte.Shared.IdentityServer.CustomOAuth2Introspection.Context
{
    /// <summary>
    /// Context for the UpdateClientAssertion event
    /// </summary>
    public class UpdateClientAssertionContext : ResultContext<ExtendedOAuth2IntrospectionOptions>
    {
        /// <summary>
        /// ctor
        /// </summary>
        public UpdateClientAssertionContext(
            HttpContext context,
            AuthenticationScheme scheme,
            ExtendedOAuth2IntrospectionOptions options)
            : base(context, scheme, options) { }

        /// <summary>
        /// The client assertion
        /// </summary>
        public ClientAssertion ClientAssertion { get; set; }

        /// <summary>
        /// The client assertion expiration time
        /// </summary>
        public DateTime ClientAssertionExpirationTime { get; set; }
    }
}