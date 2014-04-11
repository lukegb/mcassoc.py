from bottle import route, run, template, request
from mcassoc import MCAssoc

MCASSOC_SITE_ID = 'test' # this is public
MCASSOC_SHARED_SECRET = None # this is secret, but shared with mcassoc
MCASSOC_INSTANCE_SECRET = 'arbitrary' # this is only known to you and not mcassoc
MCASSOC_INSECURE_MODE = MCASSOC_SHARED_SECRET is None

m = MCAssoc(MCASSOC_SITE_ID, MCASSOC_SHARED_SECRET, MCASSOC_INSTANCE_SECRET)
m.insecure_mode = MCASSOC_INSECURE_MODE

# note: running in insecure mode disables all signature verification
# people will be able to fake whatever MC account they want!

from bottle import static_file
@route('/static/<filename>')
def server_static(filename):
	return static_file(filename, root='static')

@route('/')
def index():
    return template("""
<html><body>Pick a username (i.e. a local one) and go to /assoc/&lt;username&gt;</body></html>
""")

@route('/assoc/<username>')
def assoc_iframe(username):
	return template("""
<!DOCTYPE html>
<html>
<head>
	<title>Example Association</title>
	<script src="/static/client.js"></script>
</head>
<body>
	<h1>Example page</h1>
	<iframe id="mcassoc" width="600" height="400" frameBorder="0" seamless scrolling="no"></iframe>
	<script>
MCAssoc.init('{{ site_id }}', '{{ key }}', '{{ stage2 }}');
	</script>
</body>
</html>
""", site_id=MCASSOC_SITE_ID, key=m.generate_key(username), stage2='http://127.0.0.1:9888/complete/' + username)

@route('/complete/<username>', method='POST')
def assoc_complete(username):
	try:
		signed_data = request.forms.get('data')
		data = m.unwrap_data(signed_data)
		key_username = m.unwrap_key(data['key'])
	except Exception as e:
		return template("""<!DOCTYPE html><html><body><h1>Failed</h1><p>{{ why }}</p></html>""", why=repr(e))
	return template("""
<!DOCTYPE html><html><body>
<h1>Success!</h1>
<dl>
	<dt>Site username given:</dt>
		<dd>{{ site_username_url }}</dd>
	<dt>Site username checked:</dt>
		<dd>{{ site_username }}</dd>
	<dt>Site username OK?</dt>
		<dd>{{ site_username_ok }}</dd>
	<br>
	<dt>Minecraft username:</dt>
		<dd>{{ data['username'] }}</dd>
	<dt>Minecraft UUID:</dt>
		<dd>{{ data['uuid'] }}</dd>
	<dt></dt>
		<dd><img src="http://minotar.net/avatar/{{ data['username'] }}"></dd>
</dl>
</html>
""",
		site_username_url=username, site_username=key_username, site_username_ok=(username==key_username),
		data=data
	)

run(host='localhost', port=9888)