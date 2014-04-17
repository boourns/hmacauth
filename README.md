hmacauth

HTTP middleware in Go for Rails-compatible HMAC authentication

Share a secret key and authenticate rails clients in go

== Rails Side

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

== Go side


