using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace test_sso_new1
{
    public class LogoutTokenModel
    {
        public string logout_token { get; set; }
    }

    public class SessionItemModel
    {
        public string Email { get; set; }
        public string Sub { get; set; }

        public SessionItemModel(string sub, string email)
        {
            this.Sub = sub;
            this.Email = email;
        }
    }
}