# typed: false

require "resolv"

class ATProto
  MAX_DNS_TIME = Sponge::MAX_DNS_TIME
  MAX_DNS_RETRIES = 1

  def initialize(sponge)
    @sponge = sponge
  end

  def resolve_handle(handle)
    # TODO figure out how/if we're supposed to handle punycode in handles.
    handle = handle.downcase(:ascii)
    did = resolve1_handle(handle) or return nil
    identity = fetch_did_document(did) or return nil
    identity if handle == identity.handle
  end

  def resolve_did(did)
    identity = fetch_did_document(did) or return nil
    resolved_did = resolve1_handle(identity.handle) or return nil
    identity if did == resolved_did
  end

  class Identity
    attr_reader :document

    def initialize(document)
      @document = document
    end

    def handle
      @document["alsoKnownAs"].each do |aka|
        # "Handles will have the URI scheme at://, followed by the handle, with
        # no path or other URI parts. The current primary handle is the first
        # valid handle URI found in the ordered list. Any other handle URIs
        # should be ignored." - https://atproto.com/specs/did#did-documents
        aka = URI.parse(aka)
        if aka.scheme == "at" && !aka.userinfo && !aka.port && !aka.registry &&
            aka.path == "" && !aka.opaque && !aka.query && !aka.fragment
          return aka.host
        end
      end
      raise KeyError, "DID document lacks a valid handle"
    end

    def services
      @document["service"].map do |service|
        case service["type"]
        when PersonalDataServer::TYPE
          PersonalDataServer.new(service["id"], URI.parse(service["serviceEndpoint"]))
        else
          Service.new(service["type"], service["id"])
        end
      end
    end

    def pds
      services.each do |service|
        if service.is_a?(PersonalDataServer) && service.id.ends_with?("#atproto_pds")
          return service
        end
      end
      raise KeyError, "DID document lacks PDS locator"
    end
  end

  class Service
    attr_reader :type
    attr_reader :id

    def initialize(type, id)
      @type = type
      @id = id
    end
  end

  class PersonalDataServer < Service
    TYPE = "AtprotoPersonalDataServer"
    attr_reader :endpoint

    def initialize(id, endpoint)
      super(TYPE, id)
      @endpoint = endpoint
    end
  end

  private

  # The resolve1 family of methods do one-way resolution, i.e. they go from
  # handle to DID. Establishing a handle<->DID association requires that
  # resolution succeed in both directions; see ATProto::Identity#handle for the
  # reverse lookup.

  def resolve1_handle(handle)
    resolve1_handle_dns(handle) || resolve1_handle_web(handle)
  end

  def resolve1_handle_dns(handle)
    # This is pretty similar to Sponge's DNS resolution code (because it was
    # copied from there), and maybe Sponge could be refactored for this
    # usecase, but I'm not entirely sure it's in-scope for that class.
    host = "_atproto.#{handle}"
    retries_remaining = MAX_DNS_RETRIES
    begin
      Timeout.timeout(MAX_DNS_TIME) do
        Resolv::DNS.open do |dns|
          dns.each_resource(host, Resolv::DNS::Resource::IN::TXT) do |res|
            res.strings.each do |txt|
              if txt.start_with? "did="
                return txt.delete_prefix("did=")
              end
            end
          end
          nil
        end
      end
    rescue Timeout::Error => e
      if retries_remaining > 0
        retries_remaining -= 1
        retry
      else
        raise DNSError.new("couldn't resolve #{host} (DNS timeout)")
      end
    rescue => e
      raise DNSError.new("couldn't resolve #{host} (#{e.inspect})")
    end
  end

  def resolve1_handle_web(handle)
    uri = URI::HTTPS.build(host: handle, path: "/.well-known/atproto-did")
    res = @sponge.fetch(uri, :get)
    res&.body
  rescue DNSError => e
    if e.cause.is_a?(NoIPsError)
      # This means that the handle just isn't a valid domain, not that there
      # was a resolution failure.
      nil
    else
      raise
    end
  end

  def fetch_did_document(did)
    parts = did.split(":")
    if parts.length != 3
      raise ArgumentError, "DID must have three parts"
    elsif parts.shift != "did"
      raise ArgumentError, "DID must begin with \"did\""
    end

    uri = case parts.shift
    when "plc"
      URI::HTTPS.build(host: "plc.directory", path: "/#{did}")
    when "web"
      # As implemented, this implicitly trusts continuity of ownership of
      # whatever domain is used in the DID. This could be handled other ways,
      # but the planned use (associating a DID with a Lobsters account for
      # display purposes) doesn't actually grant any additional accesses. This
      # would have to be re-evaluated it were used as, say, an auth source.
      URI::HTTPS.build(host: parts.shift, path: "/.well-known/did.json")
    else
      raise ArgumentError, "DID method must be \"plc\" or \"web\""
    end
    res = @sponge.fetch(uri, :get)
    res && Identity.new(JSON.parse(res.body))
  end
end
