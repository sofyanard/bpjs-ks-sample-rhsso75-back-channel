using IdentityModel;
using IdentityModel.Client;
using IdentityModel.Jwk;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using Newtonsoft.Json;

namespace test_sso_new1.Controllers
{
    public class LogoutController : ApiController
    {
        static string _tenant = System.Configuration.ConfigurationManager.AppSettings["tenant"];
        static string _authority = String.Format(System.Globalization.CultureInfo.InvariantCulture, System.Configuration.ConfigurationManager.AppSettings["authority"], _tenant);
        static string _clientId = System.Configuration.ConfigurationManager.AppSettings["clientId"];
        static string _clientSecret = System.Configuration.ConfigurationManager.AppSettings["clientSecret"];

        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        public LogoutController()
        {
            log.Info("Logout Controller is started!");
        }

        // POST: api/Logout
        public async Task<IHttpActionResult> Post([FromBody] LogoutTokenModel logoutTokenModel)
        {
            try
            {
                string logoutToken = logoutTokenModel.logout_token;

                log.Info("Logout Notification is received!");
                log.Info($"logout_token : {logoutToken}");

                log.Info("ValidateLogoutToken start");
                var user = await ValidateLogoutToken(logoutToken);
                log.Info("ValidateLogoutToken finish");

                // these are the sub & sid to signout
                var sub = user.FindFirst("sub")?.Value;
                log.Info($"sub = {sub}");
                var sid = user.FindFirst("sid")?.Value;
                log.Info($"sid = {sid}");

                // GlobalVariables.DeleteSession(sub);
                try
                {
                    GlobalVariables.DeleteSession2(sub, null);
                    log.Info($"LogoutController.GlobalVariables.DeleteSession2 - sub = {sub}");
                }
                catch (Exception e)
                {
                    log.Info($"GlobalVariables.DeleteSession2 error : {e.Message}");
                }

                return Ok();
            }
            catch (Exception e)
            {
                log.Error($"LogoutController.Post error : {e.Message}");
                return InternalServerError(e);
            }
            
            return BadRequest();
        }

        private async Task<ClaimsPrincipal> ValidateLogoutToken(string logout_token)
        {
            // https://ashend.medium.com/openid-connect-backchannel-logout-144a3198d2a
            log.Info("ValidateJwt start");
            var claims = await ValidateJwt(logout_token);
            log.Info("ValidateJwt finish");

            if (claims.FindFirst("sub") == null && claims.FindFirst("sid") == null) throw new Exception("Invalid logout token");

            /*
            var nonce = claims.FindFirst("nonce").Value;
            if (!String.IsNullOrWhiteSpace(nonce)) throw new Exception("Invalid logout token");
            Console.WriteLine($"nonce is: {nonce}");

            var eventsJson = claims.FindFirst("events")?.Value;
            if (String.IsNullOrWhiteSpace(eventsJson)) throw new Exception("Invalid logout token");
            Console.WriteLine($"eventsJson is: {eventsJson}");

            var events = JObject.Parse(eventsJson);
            var logoutEvent = events.TryGetValue("http://schemas.openid.net/event/backchannel-logout");
            if (logoutEvent == null) throw new Exception("Invalid logout token");
            */

            return claims;
        }

        private static async Task<ClaimsPrincipal> ValidateJwt(string jwt)
        {
            // read discovery document to find issuer and key material
            var client = new HttpClient();
            log.Info("GetDiscoveryDocumentAsync start");
            var disco = await client.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest { 
                Address = _authority,
                Policy =
                    {
                        RequireHttps = false
                    }
            });
            log.Info("GetDiscoveryDocumentAsync finish");

            try
            {
                var discoRslt = JsonConvert.SerializeObject(disco);
                log.Info($"discoRslt = {discoRslt}");
            }
            catch (Exception e)
            {
                log.Error($"discoRslt error : {e.Message}");
            }
            
            var keys = new List<Microsoft.IdentityModel.Tokens.SecurityKey>();
            log.Info("keys defined");
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
            log.Info("keys added");

            var parameters = new TokenValidationParameters
            {
                ValidIssuer = disco.Issuer,
                ValidAudience = _clientId,
                IssuerSigningKeys = keys,

                NameClaimType = JwtClaimTypes.Name,
                RoleClaimType = JwtClaimTypes.Role,

                TokenReplayCache = null,
                RequireExpirationTime = false
            };
            log.Info("parameters set");

            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();

            log.Info("handler.ValidateToken start");
            ClaimsPrincipal user;
            try
            {
                user = handler.ValidateToken(jwt, parameters, out var _);
            }
            catch (Exception e)
            {
                log.Error($"handler.ValidateToken error : {e.Message}");
                user = null;
            }
            
            return user;
        }
    }
}

/*
Sample Logout_token:

eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJicEpCdHFqMEZORURSWm1QQ0NoSGVCcU1UcFZhRWVNRkdmTkFGajl3LVdnIn0.eyJpYXQiOjE2MzUwMzk2MTcsImp0aSI6IjVlNTRkY2FjLWRiOTUtNDk2MS05YWRhLWE0NTRmYTMxNzQ0YyIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9hdXRoL3JlYWxtcy9zc29yZWFsbSIsImF1ZCI6ImRvdG5ldHdlYmZvcm0iLCJzdWIiOiIwOWU5MDQ2My0wNWQwLTRmMWMtOTJlMi1jYTIwZGRkN2U0OTUiLCJ0eXAiOiJMb2dvdXQiLCJzaWQiOiI3YTA3ZTU4My04MDdlLTQ4Y2EtOGI4Yy1iYTIyM2ZkNmQzMGMiLCJldmVudHMiOnsiaHR0cDovL3NjaGVtYXMub3BlbmlkLm5ldC9ldmVudC9iYWNrY2hhbm5lbC1sb2dvdXQiOnt9LCJyZXZva2Vfb2ZmbGluZV9hY2Nlc3MiOnRydWV9fQ.SsBZ__PC9fup83Zfnik3muPIp4dpOWb2GGxfbhAXB6mPPPAQBYbJOFkoVMHt4TH5mQYVKI-jj8h7dFL4u5sZwb66vaq54P4V7ChjvrM5zOSsZYGhMsl3R8ZLvOTBDIIllPkDLVDDdujgYvRzXwDAKq8UY1lCUjSwMRxeo69Vy3ntqoh73ftRMRyYyjsGORSFflXBrZgHyS4vj_rBvHgB3GKfNey0VibRtq6V3oNePcyRS04hOTS5CusaI6LoHvqZsndZXoXpW86ys007GRn0GJvcIMCxukRBu6mTcU3272tIOY9RB_4cg0UMSwjSrgBFg-x2OU30OOF0sEu4UZSY9g

{
  "iat": 1635039617,
  "jti": "5e54dcac-db95-4961-9ada-a454fa31744c",
  "iss": "http://localhost:8080/auth/realms/ssorealm",
  "aud": "dotnetwebform",
  "sub": "09e90463-05d0-4f1c-92e2-ca20ddd7e495",
  "typ": "Logout",
  "sid": "7a07e583-807e-48ca-8b8c-ba223fd6d30c",
  "events": {
    "http://schemas.openid.net/event/backchannel-logout": {},
    "revoke_offline_access": true
  }
}

id_token
    eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJRamx3U25qOEVVVlhMQktaU2E1Vk1CcEJJWGhjNF9YZXFQUzFZZGxrWU1VIn0.eyJleHAiOjE2MzUwNDEyMzAsImlhdCI6MTYzNTA0MDkzMCwiYXV0aF90aW1lIjoxNjM1MDQwOTMwLCJqdGkiOiJiYTA1ZjRiYS1jYTM4LTQ5MjItODRjMS01YTA3OWQ3ZTU3M2MiLCJpc3MiOiJodHRwOi8vMTIzLjE3Ni4xMjAuNzc6ODA4MC9hdXRoL3JlYWxtcy9rb21vZG8iLCJhdWQiOiJzc290ZXN0MyIsInN1YiI6ImQ5OGMzYjBhLTFjYWYtNDlmZS1hODJkLTFiZWY5MmI1MDJjYSIsInR5cCI6IklEIiwiYXpwIjoic3NvdGVzdDMiLCJzZXNzaW9uX3N0YXRlIjoiZTNiNmZjNTAtZjdiNC00NzNhLWI0MzItMGI1ZTA3MGU2N2RmIiwiYXRfaGFzaCI6Ii0tYzBfNlMzS0xMQ0RCZnliUURsSnciLCJhY3IiOiIxIiwic2lkIjoiZTNiNmZjNTAtZjdiNC00NzNhLWI0MzItMGI1ZTA3MGU2N2RmIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiT3JjYSIsInByZWZlcnJlZF91c2VybmFtZSI6Im9yY2EiLCJnaXZlbl9uYW1lIjoiT3JjYSIsImVtYWlsIjoib3JjYUBnbWFpbC5jb20ifQ.A23s-NA1yhqxSDunDmCZP_wtdpMyitA0dVrSs8MIR6YIOtUWL90TPu0sWYdS-94f2R6byVclGa5iyuICn3gNY6mcUoIIJNLpjalz6vKx1Q4yOHPxw1riH2eoWe33lz2co4qAUvPRL1DdMVLQFlouikaEC7pZv-yNaFtriJkKftzVhXvJ_k7R3QY7Zi7dPbIEJhz2A9LIMu77oCuAbwRTWJu3y6jt8n11JigFBrRMrU3X-CVuionzPveg7hDnHxwB-m-MBs84ZgRQ0F4VFklpi696-6r_9NVduoxBWFCtzpUK6bhKBxMXontUkTU-uxxu1tg47WGtwXuXT8XPmgk7OQ

{
  "exp": 1635041230,
  "iat": 1635040930,
  "auth_time": 1635040930,
  "jti": "ba05f4ba-ca38-4922-84c1-5a079d7e573c",
  "iss": "http://123.176.120.77:8080/auth/realms/komodo",
  "aud": "ssotest3",
  "sub": "d98c3b0a-1caf-49fe-a82d-1bef92b502ca",
  "typ": "ID",
  "azp": "ssotest3",
  "session_state": "e3b6fc50-f7b4-473a-b432-0b5e070e67df",
  "at_hash": "--c0_6S3KLLCDBfybQDlJw",
  "acr": "1",
  "sid": "e3b6fc50-f7b4-473a-b432-0b5e070e67df",
  "email_verified": false,
  "name": "Orca",
  "preferred_username": "orca",
  "given_name": "Orca",
  "email": "orca@gmail.com"
}

access_token
    eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJRamx3U25qOEVVVlhMQktaU2E1Vk1CcEJJWGhjNF9YZXFQUzFZZGxrWU1VIn0.eyJleHAiOjE2MzUwNDEyMzAsImlhdCI6MTYzNTA0MDkzMCwiYXV0aF90aW1lIjoxNjM1MDQwOTMwLCJqdGkiOiIyZThlMmI3Yi01NjUzLTRmY2EtODM0Mi03ODVmNDUxYzgyOWMiLCJpc3MiOiJodHRwOi8vMTIzLjE3Ni4xMjAuNzc6ODA4MC9hdXRoL3JlYWxtcy9rb21vZG8iLCJhdWQiOlsic3NvdGVzdDIiLCJzc290ZXN0MyIsInJlYWxtLW1hbmFnZW1lbnQiLCJhY2NvdW50Il0sInN1YiI6ImQ5OGMzYjBhLTFjYWYtNDlmZS1hODJkLTFiZWY5MmI1MDJjYSIsInR5cCI6IkJlYXJlciIsImF6cCI6InNzb3Rlc3QzIiwic2Vzc2lvbl9zdGF0ZSI6ImUzYjZmYzUwLWY3YjQtNDczYS1iNDMyLTBiNWUwNzBlNjdkZiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovLzEyMy4xNzYuMTIwLjc3OjgwODMiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwiZGVmYXVsdC1yb2xlcy1rb21vZG8iLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7InJlYWxtLW1hbmFnZW1lbnQiOnsicm9sZXMiOlsidmlldy1yZWFsbSIsInZpZXctaWRlbnRpdHktcHJvdmlkZXJzIiwibWFuYWdlLWlkZW50aXR5LXByb3ZpZGVycyIsImltcGVyc29uYXRpb24iLCJyZWFsbS1hZG1pbiIsImNyZWF0ZS1jbGllbnQiLCJtYW5hZ2UtdXNlcnMiLCJxdWVyeS1yZWFsbXMiLCJ2aWV3LWF1dGhvcml6YXRpb24iLCJxdWVyeS1jbGllbnRzIiwicXVlcnktdXNlcnMiLCJtYW5hZ2UtZXZlbnRzIiwibWFuYWdlLXJlYWxtIiwidmlldy1ldmVudHMiLCJ2aWV3LXVzZXJzIiwidmlldy1jbGllbnRzIiwibWFuYWdlLWF1dGhvcml6YXRpb24iLCJtYW5hZ2UtY2xpZW50cyIsInF1ZXJ5LWdyb3VwcyJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgZW1haWwgcHJvZmlsZSBnb29kLXNlcnZpY2UiLCJzaWQiOiJlM2I2ZmM1MC1mN2I0LTQ3M2EtYjQzMi0wYjVlMDcwZTY3ZGYiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJPcmNhIiwicHJlZmVycmVkX3VzZXJuYW1lIjoib3JjYSIsImdpdmVuX25hbWUiOiJPcmNhIiwiZW1haWwiOiJvcmNhQGdtYWlsLmNvbSJ9.PK9fNWt7_V1U7JAi98l-SN5bU4U3vkddWD87wmEgyP4UoMg6yAvx6088az12aVT8ScMa4WJuU3Pok-njXbrJ-vLSIQQP4EbtoGXaqeBEYwgR3m6BUYHnbKJsPffNOysqKaUrpqZeBjWN-yjP60bMxXQbrDWSLTtmUJzpirUISNrqgg8aoSkcQv-ut_JdwA0qesna4QTPSWMAgQQX_eUqM7_-G2O9U_hsBcghBYtpp4B4XVnlihRGygaFLZ4BjUMMwRcLdKxjCnqgTuibSs7ThXr4zFw699pyyBiMuLEb2HrtCF92bNUd8AUukkkbCt6EEonbCjsQDoZXphR8FD3TpQ
refresh_token
    eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJlYjkxYjA3My1mMzM5LTQ1M2YtYTg5NS1lZTU4MzFhOGNiOWUifQ.eyJleHAiOjE2MzUwNDI3MzAsImlhdCI6MTYzNTA0MDkzMCwianRpIjoiY2ZhYzIwYWEtNzgxYi00M2U1LThhOGYtOTkxMGNiY2U4MDQxIiwiaXNzIjoiaHR0cDovLzEyMy4xNzYuMTIwLjc3OjgwODAvYXV0aC9yZWFsbXMva29tb2RvIiwiYXVkIjoiaHR0cDovLzEyMy4xNzYuMTIwLjc3OjgwODAvYXV0aC9yZWFsbXMva29tb2RvIiwic3ViIjoiZDk4YzNiMGEtMWNhZi00OWZlLWE4MmQtMWJlZjkyYjUwMmNhIiwidHlwIjoiUmVmcmVzaCIsImF6cCI6InNzb3Rlc3QzIiwic2Vzc2lvbl9zdGF0ZSI6ImUzYjZmYzUwLWY3YjQtNDczYS1iNDMyLTBiNWUwNzBlNjdkZiIsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUgZ29vZC1zZXJ2aWNlIiwic2lkIjoiZTNiNmZjNTAtZjdiNC00NzNhLWI0MzItMGI1ZTA3MGU2N2RmIn0.0C95pOXC2FoeXO7mHy3A0x1QkmBcr1-
*/