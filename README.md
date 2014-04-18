hmacauth

HTTP middleware in Go for Rails-compatible HMAC authentication

Share a secret key and authenticate rails clients in go

**Rails Side

```
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
token = verifier.generate({ user_id: 123})
params[:token] = token

```

Go side

`hmacauth.Authenticate` takes the message verifier key, the URL param from which to pull out the HMAC token, and the protected HTTP handler function that takes an extra parameter: the original decoded token as a string.  In this case the token would need to be JSON decoded still.


```
handler := hmacauth.Authenticate("testkey", "token", func(response http.ResponseWriter, request *http.Request, token string) {
  response.Write([]byte(token))
})
```


        

