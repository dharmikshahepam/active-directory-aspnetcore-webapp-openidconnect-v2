﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Common
{
    public static class TestConstants
    {
        public const string Headless = "headless";
        public const string HeaderText = "Header";
        public const string EmailText = "Email";
        public const string PasswordText = "Password";
        public const string TodoTitle1 = "Testing create todo item";
        public const string TodoTitle2 = "Testing edit todo item";
        public const string LocalhostUrl = @"https://localhost:";
        public const string KestrelEndpointEnvVar = "Kestrel:Endpoints:Http:Url";
        public const string HttpStarColon = "http://*:";
        public const string HttpsStarColon = "https://*:";
        public const string WebAppCrashedString = $"The web app process has exited prematurely.";
        public const string OIDCUser = "fIDLAB@MSIDLAB3.com";
        public static readonly string s_oidcWebAppExe = Path.DirectorySeparatorChar.ToString() + "WebApp-OpenIDConnect-DotNet.exe";
        public static readonly string s_oidcWebAppPath = Path.DirectorySeparatorChar.ToString() + "WebApp-OpenIDConnect";
    }
}