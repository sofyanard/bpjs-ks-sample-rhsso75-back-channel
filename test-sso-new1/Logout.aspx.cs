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
    public partial class Logout : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string sub = Session["sub"]?.ToString();
            string email = Session["email"]?.ToString();
            // GlobalVariables.DeleteSession(sub);
            GlobalVariables.DeleteSession2(sub, email);
            Session.Remove("sub");
            Session.Remove("email");

            HttpContext.Current.GetOwinContext().Authentication.SignOut(
                OpenIdConnectAuthenticationDefaults.AuthenticationType,
                CookieAuthenticationDefaults.AuthenticationType);

            Response.Redirect("~/Default.aspx");
        }
    }
}