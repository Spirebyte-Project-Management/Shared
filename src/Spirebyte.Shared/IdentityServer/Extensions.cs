﻿using System.Security.Cryptography.X509Certificates;
using System.Text;
using Convey;
using IdentityModel.AspNetCore.AccessTokenValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Spirebyte.Shared.IdentityServer.Options;

namespace Spirebyte.Shared.IdentityServer;

public static class Extensions
{
    private const string SectionName = "jwt";

    
    public static IConveyBuilder AddIdentityServerAuthentication(this IConveyBuilder builder, string sectionName = SectionName,
        Action<JwtBearerOptions> optionsFactory = null)
    {
        if (string.IsNullOrWhiteSpace(sectionName))
        {
            sectionName = SectionName;
        }

        var options = builder.GetOptions<JwtOptions>(sectionName);
        return builder.AddIdentityServerAuthentication(options, optionsFactory);
    }
    
    private static IConveyBuilder AddIdentityServerAuthentication(this IConveyBuilder builder, JwtOptions options,
        Action<JwtBearerOptions> optionsFactory = null)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            RequireAudience = options.RequireAudience,
            ValidIssuer = options.ValidIssuer,
            ValidIssuers = options.ValidIssuers,
            ValidateActor = options.ValidateActor,
            ValidAudience = options.ValidAudience,
            ValidAudiences = options.ValidAudiences,
            ValidateAudience = options.ValidateAudience,
            ValidateIssuer = options.ValidateIssuer,
            ValidateLifetime = options.ValidateLifetime,
            ValidateTokenReplay = options.ValidateTokenReplay,
            ValidateIssuerSigningKey = options.ValidateIssuerSigningKey,
            SaveSigninToken = options.SaveSigninToken,
            RequireExpirationTime = options.RequireExpirationTime,
            RequireSignedTokens = options.RequireSignedTokens,
            ClockSkew = TimeSpan.Zero
        };

        if (!string.IsNullOrWhiteSpace(options.AuthenticationType))
        {
            tokenValidationParameters.AuthenticationType = options.AuthenticationType;
        }

        if (!string.IsNullOrWhiteSpace(options.NameClaimType))
        {
            tokenValidationParameters.NameClaimType = options.NameClaimType;
        }

        if (!string.IsNullOrWhiteSpace(options.RoleClaimType))
        {
            tokenValidationParameters.RoleClaimType = options.RoleClaimType;
        }
        
        builder.Services.AddAuthentication("token")
 
            // JWT tokens (default scheme)
            .AddJwtBearer("token", o =>
            {
                o.Authority = options.Authority;
                o.Audience = options.Audience;
                o.MetadataAddress = options.MetadataAddress;
                o.SaveToken = options.SaveToken;
                o.RefreshOnIssuerKeyNotFound = options.RefreshOnIssuerKeyNotFound;
                o.RequireHttpsMetadata = options.RequireHttpsMetadata;
                o.IncludeErrorDetails = options.IncludeErrorDetails;
                o.TokenValidationParameters = tokenValidationParameters;
                if (!string.IsNullOrWhiteSpace(options.Challenge))
                {
                    o.Challenge = options.Challenge;
                }

                optionsFactory?.Invoke(o);
                
                o.ForwardDefaultSelector = Selector.ForwardReferenceToken("introspection");
            })
 
            // reference tokens
            .AddOAuth2Introspection("introspection", o =>
            {
                o.Authority = options.Authority;
                
                o.ClientId = options.ClientId;
                o.ClientSecret = options.ClientSecret;
            });

        return builder;
    }
}