using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace test_sso_new1
{
    public partial class _Default : Page
    {
        string authenticatedPage = System.Configuration.ConfigurationManager.AppSettings["authenticatedUri"];

        protected void Page_Load(object sender, EventArgs e)
        {
            
        }

        protected void Button1_Click(object sender, EventArgs e)
        {
            if (!Request.IsAuthenticated)
            {
                HttpContext.Current.GetOwinContext().Authentication.Challenge(
                new AuthenticationProperties { RedirectUri = authenticatedPage },
                OpenIdConnectAuthenticationDefaults.AuthenticationType);
            }
            else
            {
                Response.Redirect(authenticatedPage);
            }
        }
    }
}