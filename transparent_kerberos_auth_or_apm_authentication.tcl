# iRule: f5.transparent_kerberos_auth_or_apm_authentication

when RULE_INIT {

	set static::webworker_task {
self.addEventListener('message', function(e) {

	fetch(e.data, function(xhr) {	
		var status = xhr.status;
		self.postMessage(status);
	});

}, false);

	function fetch(url, callback) {
		var xhr;
		
		if(typeof XMLHttpRequest !== 'undefined') xhr = new XMLHttpRequest();
		else {
			var versions = ["MSXML2.XmlHttp.6.0",
                                        "MSXML2.XmlHttp.5.0", 
                                        "MSXML2.XmlHttp.4.0",
                                        "MSXML2.XmlHttp.3.0", 
                                        "MSXML2.XmlHttp.2.0",
                                        "Microsoft.XmlHttp"]

			 for(var i = 0, len = versions.length; i < len; i++) {
			 	try {
			 		xhr = new ActiveXObject(versions[i]);
			 		break;
			 	}
			 	catch(e){}
			 } 
		}
		
		xhr.onreadystatechange = ensureReadiness;
		
		function ensureReadiness() {
			if(xhr.readyState < 4) {
				return;
			}
			
			if(xhr.status !== 200) {
				return;
			}

			// all is well	
			if(xhr.readyState === 4) {
				callback(xhr);
			}			
		}
		xhr.open('GET', url, true);
                xhr.withCredentials = true;
		xhr.send('');
	}
}

set static::html_start { <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
	<head>
	<meta charset="utf-8">
	<title></title>
	</head>
	<body>
	<script>
	}
	
		set static::html_end {
	var clientTime = new Date().getTime();
	var timeDiff = Math.abs(clientTime - serverTime) / 1000; 
	
	//# if client's time differs to server
	if (timeDiff > 120) {
		var url = window.location.href + (window.location.href.match(/[\?]/g) ? '&' : '?') + 'domainjoined=timeshift';
		window.location.replace(url);
	}
	
	var evtFired = false;
	setTimeout(function() {
		if (!evtFired) {
		  url += ( url.match( /[\?]/g ) ? '&' : '?' ) + 'domainjoined=false';
		  window.location.replace(url);
		}
	}, 500);
	
	var worker = new Worker('worker.js');
	
	worker.addEventListener('message', function(e) {
	  evtFired = true;
	  url += ( url.match( /[\?]/g ) ? '&' : '?' ) + 'domainjoined=true';
	  window.location.replace(url);
	}, false);
	
	worker.postMessage('/kerberos/test/');
	</script>
	</body>
	</html>
	}
}

when HTTP_REQUEST {

	if {[string tolower [HTTP::path]] starts_with "/f5-oauth2"} { return }

	set domainjoined 0
	
	if { [HTTP::cookie exists "DOMAINJOINED"] } {
		ACCESS::enable
		if { [HTTP::cookie "DOMAINJOINED"] == 1 } {
			set domainjoined 1
		}
	return
	}

	set cur_time [clock seconds]
	set expr_time [expr {$cur_time + 180}]
	set formated_time [clock format $expr_time -format "%a, %d %h %Y %T GMT" -gmt true]
	set server_time_ms [expr {$cur_time * 1000}]
	
	set domainjoined [URI::query [HTTP::uri] domainjoined]
	
	switch $domainjoined {
		"false" {
			ACCESS::enable
			HTTP::uri [string map {"?domainjoined=false" ""} [HTTP::uri]]
			HTTP::uri [string map {"&domainjoined=false" ""} [HTTP::uri]]
			HTTP::respond 307 Location [HTTP::uri] Set-Cookie "DOMAINJOINED=0; expires=$formated_time; path=/; secure"
			return
		}
		"true" {
			ACCESS::disable
			HTTP::uri [string map {"?domainjoined=true" ""} [HTTP::uri]]
			HTTP::uri [string map {"&domainjoined=true" ""} [HTTP::uri]]
			HTTP::respond 307 Location [HTTP::uri] Set-Cookie "DOMAINJOINED=1; expires=$formated_time; path=/; secure"
			return
		}
		"timeshift" {
  			# Client time differs more than 2 minutes, set cookie expiry to 1 week from now
			set expr_time [expr {$cur_time + 604800}]
			set formated_time [clock format $expr_time -format "%a, %d %h %Y %T GMT" -gmt true]
			ACCESS::enable
			HTTP::uri [string map {"?domainjoined=false" ""} [HTTP::uri]]
			HTTP::uri [string map {"&domainjoined=false" ""} [HTTP::uri]]
			HTTP::respond 307 Location [HTTP::uri] Set-Cookie "DOMAINJOINED=0; expires=$formated_time; path=/; secure"
			return
		}
		default {
			ACCESS::disable
		}
	}
	switch [HTTP::uri] {
		"/saml/idp/profile/redirectorpost/worker.js" {
			HTTP::respond 200 content $static::webworker_task Content-Type "application/javascript" "Access-Control-Allow-Credentials" "true"
			return
		}
		"/kerberos/test/" {
			if { [HTTP::header exists "Authorization"] && [string tolower [HTTP::header "Authorization"]] starts_with "negotiate" &&
		[HTTP::header "Authorization"] ne "Negotiate TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKAGFKAAAADw=="} {
				HTTP::respond 200 content "OK"
				return
				}
			else {
				HTTP::respond 401 "WWW-Authenticate" "Negotiate"
				return
				}
		}
	}
	if { ( [HTTP::cookie exists MRHSession] ) and ( [ACCESS::session exists -state_allow [HTTP::cookie value MRHSession]] ) } {
		ACCESS::enable
	}
	else {
		set content "$static::html_start\nvar url = '[HTTP::uri]';\nvar serverTime = $server_time_ms; $static::html_end"
		HTTP::respond 200 content $content
	}

}

when ACCESS_SESSION_STARTED {
	if {not [info exists domainjoined]} {set domainjoined 0}
	ACCESS::session data set session.custom.domainjoined $domainjoined
	ACCESS::session data set session.server.landinguri [HTTP::uri]
}
