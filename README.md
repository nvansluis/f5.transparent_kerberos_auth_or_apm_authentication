# f5.transparent_kerberos_auth_or_apm_authentication
This iRule can be used when it is required to offer both Kerberos authentication and for example SAML or another authentication method in a mixed environment for devices that are domain joined and devices that are not domain joined. This iRule uses javascript and HTML5 Web Workers to determine if the browser can successfully authenticate by using Kerberos or will need to fallback to another authentication method.

I've been testing this iRule with Internet Explorer, Edge, Firefox and Chrome. All these browsers seem to be working fine. Only Chrome seems to do things a bit differently and is showing a login prompt for a split second, but it's working.


