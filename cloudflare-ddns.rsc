
########################################################################################

  # Cloudflare stuff
  :local ApiToken "_CLOUDFLARE_API_TOKEN_";
  :local ZoneId "_CLOUDFLARE_ZINE_ID_";
  :local DnsServer "1.1.1.1"; 

  # Records to update
  :local DnsRecords {"aaa.aaa.aaa"; "bbb.bbb.bbb"; "ccc.ccc.ccc"; \
                     "ddd.ddd.ddd"; "eee.eee.eee"; "fff.fff.fff"; \
                     "ggg.ggg.ggg"; "hhh.hhh.hhh"};

  # Interface to use
  :local WanInterface "_WAN_INTERFACE_";

########################################################################################
########################################################################################

  # Wait some for dhcp lease
  :delay 10;

  # Fetch WAN_IP from interface
  :local WanIp [/ip address get [find interface=$WanInterface] address];
  :set WanIp [:pick $WanIp 0 ([:len $WanIp] -3)];

  :foreach DnsRecord in=$DnsRecords do={
    :do {
      # Resolve DNS_IP from dns
      :local DnsIp [:resolve domain-name=$DnsRecord server=$DnsServer];

      # Compare and update if they differ
      :if ($WanIp != $DnsIp) do={
        # Prepare request payload
        :local ReqRead ("https://api.cloudflare.com/client/v4/zones/" . $ZoneId . "/dns_records?name=" . $DnsRecord);
        :local ReqAuth ("Authorization: Bearer " . $ApiToken . ", Content-Type: application/json");

        # Query dns record
        :local Resp [/tool fetch mode=https http-method=get url=$ReqRead http-header-field=$ReqAuth as-value output=user];
        :local Data [:deserialize from=json value=($Resp->"data")];

        # Check operation result
        :if ($Data->"success" != true) do={
          :error "Failed to retrieve record data.";
        }

        # Retrieve dns_record_id
        :local DnsRecordId ($Data->"result"->0->"id");

        # Prepare request payload
        :local ReqModi ("https://api.cloudflare.com/client/v4/zones/" . $ZoneId . "/dns_records/" . $DnsRecordId);
        :local ReqData ("{\"type\":\"A\",\"name\":\"" . $DnsRecord . "\",\"content\":\"" . $WanIp . "\",\"ttl\":1,\"proxied\":false}");

        # Perform the update
        :set Resp [/tool fetch mode=https http-method=put url=$ReqModi http-header-field=$ReqAuth http-data=$ReqData as-value output=user];
        :set Data [:deserialize from=json value=($Resp->"data")];

        # Check operation result
        :if ($Data->"result"->"content" != $WanIp) do={
          :error "Failed to update record.";
        }

        :log info ("CF_DDNS: Update of \"" . $DnsRecord . "\" successful.");
      }
    } on-error={
      :log info ("CF_DDNS: Error in \"" . $DnsRecord . "\" update.");
    }
  }

########################################################################################
