hmacauth

[![Build Status](https://travis-ci.org/boourns/hmacauth.svg?branch=master)](https://travis-ci.org/boourns/hmacauth)

HTTP middleware in Go for Rails-compatible HMAC authentication

Share a secret key and authenticate rails clients in go

**Rails Side

```
require 'active_support/all'
class JSONSerializer
  class << self
    def dump(value)
      ActiveSupport::JSON.encode(value)
    end

    def load(value)
      ActiveSupport::JSON.decode(value)
    end
  end
end
verifier = ActiveSupport::MessageVerifier.new('testkey', :serializer => JSONSerializer)
expiry_time = (Time.now + 1.hour).to_i
user_id = 12345
# expiry epoch must be first field in token
# all entries in token array must be integers
# put whatever else you want in the token to validate the credentials (like a matching username)
token = verifier.generate([expiry_time, user_id])
params[:token] = token

```

Go side

`hmacauth.Authenticate` takes the message verifier key, the URL param from which to pull out the HMAC token, and the protected HTTP handler function that takes an extra parameter: the original decoded token as a string.  In this case the token would need to be JSON decoded still.


```
handler := hmacauth.Authenticate("testkey", "token", func(response http.ResponseWriter, request *http.Request, token string) {
  response.Write([]byte(token))
})
```


        

