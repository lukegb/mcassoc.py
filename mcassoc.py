import hmac
from hashlib import sha1
import base64
import time
try:
	import json
except ImportError:
	import simplejson as json

class SignatureError(Exception):
	pass

class MCAssoc(object):
	def __init__(self, site_id, shared_secret, instance_secret, timestamp_leeway=300):
		self.site_id = site_id
		self.shared_secret = shared_secret.decode('hex')
		self.instance_secret = instance_secret
		self.timestamp_leeway = timestamp_leeway
		self.insecure_mode = False

	def _base_sign(self, data, key):
		if key is None and not self.insecure_mode:
			raise SignatureError("key must not be None")
		elif self.insecure_mode:
			key = "insecure"

		return hmac.new(key, data, sha1).digest()

	def _sign(self, data, key):
		digest = self._base_sign(data, key)
		return base64.b64encode(data + digest)

	def _constanteq(self, a, b):
		if len(a) != len(b):
			return False
		result = 0
		for x, y in zip(a, b):
			result |= ord(x) ^ ord(y)
		return result == 0

	def _verify(self, input, key):
		signed_data = base64.b64decode(input)

		if len(signed_data) <= 20:
			raise SignatureError("signed data too short to have signature")

		data = signed_data[:len(signed_data)-20]

		if self.insecure_mode:
			return data

		signature = signed_data[len(signed_data)-20:]

		my_signature = self._base_sign(data, key)

		if self._constanteq(my_signature, signature):
			return data
		else:
			raise SignatureError("signature invalid")

	def generate_key(self, data):
		return self._sign(data, self.instance_secret)

	def unwrap_key(self, input):
		return self._verify(input, self.instance_secret)

	def unwrap_data(self, input, at_time=None):
		if at_time is None:
			at_time = time.time()

		# verify signature
		data = self._verify(input, self.shared_secret)

		# load JSON-formatted data
		rdata = json.loads(data)

		# check the timestamp
		if not ((at_time - self.timestamp_leeway) < rdata['now'] < (at_time + self.timestamp_leeway)):
			raise SignatureError("timestamp stale (was %d seconds old)" % (at_time - rdata['now']))

		# check the key
		try:
			self._verify(rdata['key'], self.instance_secret)
		except:
			raise
			raise SignatureError("key invalid")

		# now we know the data is valid - continue!
		return rdata


