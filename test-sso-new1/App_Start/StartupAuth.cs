using Microsoft.AspNet.Identity;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Logging;
using Microsoft.Extensions.DependencyInjection;
using IdentityModel.Client;
using System.Net.Http;
using System.Collections.Generic;
using IdentityModel;
using System.Web;

[assembly: OwinStartup(typeof(test_sso_new1.App_Start.StartupAuth))]

namespace test_sso_new1.App_Start
{
    public class StartupAuth
    {
        // The Client ID is used by the application to uniquely identify itself to Microsoft identity platform.
        string _clientId = System.Configuration.ConfigurationManager.AppSettings["clientId"];

        string _clientSecret = System.Configuration.ConfigurationManager.AppSettings["clientSecret"];

        // RedirectUri is the URL where the user will be redirected to after they sign in.
        string _redirectUri = System.Configuration.ConfigurationManager.AppSettings["redirectUri"];

        // Tenant is the tenant ID (e.g. contoso.onmicrosoft.com, or 'common' for multi-tenant)
        static string _tenant = System.Configuration.ConfigurationManager.AppSettings["tenant"];

        // Authority is the URL for authority, composed of the Microsoft identity platform and the tenant name (e.g. https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0)
        static string _authority = String.Format(System.Globalization.CultureInfo.InvariantCulture, System.Configuration.ConfigurationManager.AppSettings["authority"], _tenant);

        static string _metadataAddress = _authority + "/.well-known/openid-configuration";

        string authenticatedPage = System.Configuration.ConfigurationManager.AppSettings["authenticatedUri"];

        public void Configuration(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                // Sets the ClientId, authority, RedirectUri as obtained from web.config
                ClientId = _clientId,
                ClientSecret = _clientSecret,
                Authority = _authority,
                RedirectUri = _redirectUri,
                // PostLogoutRedirectUri is the page that users will be redirected to after sign-out. In this case, it is using the home page
                PostLogoutRedirectUri = _redirectUri,
                // Scope = OpenIdConnectScope.OpenIdProfile,
                Scope = OpenIdConnectScope.OpenId,
                // ResponseType is set to request the code id_token - which contains basic information about the signed-in user
                ResponseType = OpenIdConnectResponseType.CodeIdToken,
                // ValidateIssuer set to false to allow personal and work accounts from any organization to sign in to your application
                // To only allow users from a single organizations, set ValidateIssuer to true and 'tenant' setting in web.config to the tenant name
                // To allow users from only a list of specific organizations, set ValidateIssuer to true and use ValidIssuers parameter
                TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false // This is a simplification
                    // NameClaimType = "name"
                },
                // OpenIdConnectAuthenticationNotifications configures OWIN to send notification of failed authentications to OnAuthenticationFailed method
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    /*
                    AuthorizationCodeReceived = async n =>
                    {
                        // Exchange code for access and ID tokens
                        var tokenClient = new TokenClient($"{_authority}/token", _clientId, _clientSecret);

                        var tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(n.Code, _redirectUri);
                        if (tokenResponse.IsError)
                        {
                            throw new Exception(tokenResponse.Error);
                        }

                        var userInfoClient = new UserInfoClient($"{_authority}/userinfo");
                        var userInfoResponse = await userInfoClient.GetAsync(tokenResponse.AccessToken);

                        var claims = new List<Claim>(userInfoResponse.Claims)
                        {
                            new Claim("id_token", tokenResponse.IdentityToken),
                            new Claim("access_token", tokenResponse.AccessToken)
                        };

                        n.AuthenticationTicket.Identity.AddClaims(claims);
                    },
                    */

                    AuthorizationCodeReceived = async n =>
                    {
                        // * request Id Token
                        // * mengambil "sub" (user id di sso)
                        // * memasukkan sub ke list active session

                        try
                        {
                            var client = new HttpClient();

                            var response = await client.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
                            {
                                Address = _authority + "/protocol/openid-connect/token",
                                GrantType = "authorization_code",
                                Code = n.Code,
                                RedirectUri = _redirectUri,
                                ClientId = _clientId,
                                ClientSecret = _clientSecret,
                            });

                            // var accessToken = response.AccessToken;
                            var idToken = response.IdentityToken;

                            var disco = await client.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
                            {
                                Address = _authority,
                                Policy =
                                    {
                                        RequireHttps = false
                                    }
                            });

                            var keys = new List<Microsoft.IdentityModel.Tokens.SecurityKey>();
                            foreach (var webKey in disco.KeySet.Keys)
                            {
                                var key = new Microsoft.IdentityModel.Tokens.JsonWebKey()
                                {
                                    Kty = webKey.Kty,
                                    Alg = webKey.Alg,
                                    Kid = webKey.Kid,
                                    X = webKey.X,
                                    Y = webKey.Y,
                                    Crv = webKey.Crv,
                                    E = webKey.E,
                                    N = webKey.N,
                                };
                                keys.Add(key);
                            }

                            var parameters = new TokenValidationParameters
                            {
                                ValidIssuer = _authority,
                                ValidAudience = _clientId,
                                IssuerSigningKeys = keys,

                                NameClaimType = JwtClaimTypes.Name,
                                RoleClaimType = JwtClaimTypes.Role,
                            };

                            var handler = new JwtSecurityTokenHandler();
                            handler.InboundClaimTypeMap.Clear();

                            var jsonIdToken = handler.ValidateToken(idToken, parameters, out var _);
                            var sub = jsonIdToken.FindFirst("sub")?.Value;
                            var email = jsonIdToken.FindFirst("email")?.Value;

                            // GlobalVariables.InsertSession(sub);
                            GlobalVariables.InsertSession2(sub, email);


                        }
                        catch (Exception e)
                        {
                            throw e;
                        }
                    },

                    AuthenticationFailed = OnAuthenticationFailed
                },

                // Disable Https for Development
                RequireHttpsMetadata = false,
                MetadataAddress = _metadataAddress,
                ProtocolValidator = new CustomOpenIdConnectProtocolValidator(false)
                // SaveTokens = true
            });

            JwtSecurityTokenHandler.DefaultMapInboundClaims = false;
            IdentityModelEventSource.ShowPII = true;
        }

        // Handle failed authentication requests by redirecting the user to the home page with an error in the query string
        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            context.HandleResponse();
            context.Response.Redirect("/?errormessage=" + context.Exception.Message);
            return Task.FromResult(0);
        }
    }

    public class CustomOpenIdConnectProtocolValidator : OpenIdConnectProtocolValidator
    {
        public CustomOpenIdConnectProtocolValidator(bool shouldValidateNonce)
        {
            this.ShouldValidateNonce = shouldValidateNonce;
            this.RequireStateValidation = false;
        }
        protected override void ValidateNonce(OpenIdConnectProtocolValidationContext validationContext)
        {
            if (this.ShouldValidateNonce)
            {
                base.ValidateNonce(validationContext);
            }
        }

        private bool ShouldValidateNonce { get; set; }
    }
}
