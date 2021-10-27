using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace test_sso_new1
{
    public partial class SiteMaster : MasterPage
    {
        string authenticatedPage = System.Configuration.ConfigurationManager.AppSettings["authenticatedUri"];

        protected void Page_Load(object sender, EventArgs e)
        {
            if (!Request.IsAuthenticated)
            {
                if (!this.Page.Request.FilePath.ToLower().Contains("/default"))
                {
                    Response.Redirect("~/Default.aspx");
                }
            }
            else
            {
                var userClaims = HttpContext.Current.User.Identity as System.Security.Claims.ClaimsIdentity;
                string nama = userClaims?.FindFirst("name")?.Value;
                string email = userClaims?.Claims.Where(x => x.Type.Contains("emailaddress")).FirstOrDefault()?.Value;

                if (GlobalVariables.IsSessionActive(email))
                {
                    Label1.Text = nama;

                    string sub = GlobalVariables.FindSubByEmail(email);
                    if (sub != null)
                    {
                        Session["sub"] = sub;
                        Session["email"] = email;
                    }
                }
                else
                {
                    HttpContext.Current.GetOwinContext().Authentication.SignOut(
                        OpenIdConnectAuthenticationDefaults.AuthenticationType,
                        CookieAuthenticationDefaults.AuthenticationType);

                    Session.Remove("sub");
                    Session.Remove("email");
                }
            }
        }
    }
}