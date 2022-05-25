using System.Security.Cryptography.X509Certificates;
using System.Text;
using Convey;
using IdentityModel;
using IdentityModel.AspNetCore.AccessTokenValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Spirebyte.Shared.IdentityServer.Options;

namespace Spirebyte.Shared.IdentityServer;

public static class Extensions
{
    private const string SectionName = "jwt";

    
    public static IConveyBuilder AddIdentityServerAuthentication(this IConveyBuilder builder, string sectionName = SectionName,
        Action<JwtBearerOptions> optionsFactory = null, bool withBasic = false)
    {
        if (string.IsNullOrWhiteSpace(sectionName))
        {
            sectionName = SectionName;
        }

        var options = builder.GetOptions<JwtOptions>(sectionName);
        return withBasic ? builder.AddIdentityServerAuthenticationWithBasicToken(options, optionsFactory) : builder.AddIdentityServerAuthentication(options, optionsFactory);
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
        
        builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        
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
    
    private static IConveyBuilder AddIdentityServerAuthenticationWithBasicToken(this IConveyBuilder builder, JwtOptions options,
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
        
        builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        
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
                
                o.ForwardDefaultSelector = ForwardReferenceTokenWithBasic("introspection", "basic-introspection");
            })
 
            // reference tokens
            .AddOAuth2Introspection("introspection", o =>
            {
                o.Authority = options.Authority;
                
                o.ClientId = options.ClientId;
                o.ClientSecret = options.ClientSecret;
            })
            // reference tokens
            .AddOAuth2Introspection("basic-introspection", o =>
            {
                o.TokenRetriever = TokenRetrieval.BasicFromAuthorizationHeader();
                
                o.Authority = options.Authority;
                o.ClientId = options.ClientId;
                o.ClientSecret = options.ClientSecret;
            });

        return builder;
    }

    /// <summary>
    /// Provides a forwarding func for JWT vs reference tokens (based on existence of dot in token)
    /// </summary>
    /// <param name="introspectionScheme">Scheme name of the introspection handler</param>
    /// <returns></returns>
    public static Func<HttpContext, string> ForwardReferenceTokenWithBasic(string introspectionScheme = "Introspection", string basicIntrospectionScheme = "Basic-introspection")
    {
        return context =>
        {
            var (str3, str4) = Selector.GetSchemeAndCredential(context);
            if (str3.Equals("Bearer", StringComparison.OrdinalIgnoreCase) && !str4.Contains("."))
            {
                return introspectionScheme;
            }
            if (str3.Equals("Basic", StringComparison.OrdinalIgnoreCase) && !str4.Contains(":"))
            {
                return basicIntrospectionScheme;
            }
            return string.Empty;
        };
    }
    
    public static AuthorizationOptions AddEitherOrScopePolicy(this AuthorizationOptions options, string policyName, string firstScope, string secondScope)
    {
        options.AddPolicy(policyName, p =>
        {
            p.RequireAuthenticatedUser();
            p.RequireScope(firstScope, secondScope);
        });

        return options;
    }
    
    public static AuthorizationPolicyBuilder RequireEitherOrScope(this AuthorizationPolicyBuilder builder, string firstScope, string secondScope)
    {
        return builder.RequireAssertion(context => context.User.HasClaim(c => c.Type == JwtClaimTypes.Scope && (c.Value == firstScope || c.Value == secondScope)));
    }
}