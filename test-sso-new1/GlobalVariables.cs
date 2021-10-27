using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace test_sso_new1
{
    public static class GlobalVariables
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        private static List<string> _listActiveSession { get; set; }

        private static List<SessionItemModel> _listActiveSession2 { get; set; }

        public static void InsertSession(string sub)
        {
            if (_listActiveSession == null)
            {
                _listActiveSession = new List<string>();
            }

            if (!_listActiveSession.Any(s => s.Equals(sub)))
            {
                _listActiveSession.Add(sub);
            }
        }

        public static void InsertSession2(string sub, string email)
        {
            log.Info($"GlobalVariables.InsertSession2 - sub = {sub}, email = {email}");

            if (_listActiveSession2 == null)
            {
                _listActiveSession2 = new List<SessionItemModel>();
            }

            if (!(_listActiveSession2.Any(s => s.Sub.Equals(sub)) || _listActiveSession2.Any(s => s.Email.Equals(email))))
            {
                _listActiveSession2.Add(new SessionItemModel(sub, email));
            }
        }

        public static void DeleteSession(string sub)
        {
            try
            {
                _listActiveSession.Remove(sub);
            }
            catch (Exception)
            {
                
            }
            
        }

        public static void DeleteSession2(string sub, string email = null)
        {
            log.Info($"GlobalVariables.DeleteSession2 - sub = {sub}, email = {email}");

            List<SessionItemModel> listSessionItemModel = new List<SessionItemModel>();

            listSessionItemModel = _listActiveSession2?.Where(s => s.Sub.Equals(sub) || s.Email.Equals(email))?.ToList();

            foreach (SessionItemModel sessionItemModel in listSessionItemModel)
            {
                try
                {
                    _listActiveSession2.Remove(sessionItemModel);
                }
                catch (Exception)
                {

                }
            }
        }

        public static string FindSubByEmail(string email)
        {
            log.Info($"GlobalVariables.FindSubByEmail - email = {email}");

            return _listActiveSession2?.FirstOrDefault(s => s.Email.Equals(email))?.Sub;
        }

        public static bool IsSessionActive(string email)
        {
            log.Info($"GlobalVariables.IsSessionActive - email = {email}");

            return _listActiveSession2.Any(s => s.Email.Equals(email));
        }
    }
}