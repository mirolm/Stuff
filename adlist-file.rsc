
########################################################################################

    :local UpdateAdlist do={
        # Wait some between calls
        :delay 10s;

        :do {
            :log debug "AD_SYNC: started";

            :local api ("https://api.github.com/repos/" . $repo . "/releases/latest");
            :local ver ($dest . "ver");

            # get blacklist version
            :local FileData [/tool/fetch mode=https http-method=get url=$api output=user as-value];
            :local FileTag ([:deserialize from=json value=($FileData->"data")]->"tag_name");

            # reset to empty file if missing
            if ([:len [/file/find where name=$ver]] = 0) do={
                /file/add name=$ver contents="empty-tag-123";
            };

            # get local version
            :local FileLoc [/file/get [find where name=$ver] contents];
            /file/set [find where name=$ver] contents=$FileTag;

            # check adlist version
            :if ($FileTag != $FileLoc) do={
                # fetch new adlist source file
                /tool/fetch mode=https http-method=get url=$url output=file dst-path=$dest as-value;
                # short delay to ensure file is created
                :delay 5s;
                # check adlist
                :if ([/file/get [find where name=$dest] value-name=size] > 1048576) do={
                    :if ([/ip/dns/adlist/find where file=$dest]) do={
                        # reload existing adlist
                        /ip/dns/adlist/reload;
                        :log debug "AD_SYNC: adlist reloaded";
                    } else={
                        # create new adlist
                        /ip/dns/adlist/add file=$dest;
                        :log debug "AD_SYNC: adlist added";
                    };
                } else={
                    # delete corruted adlist
                    /ip/dns/adlist/remove [find where file=$dest];
                    /file/remove [find where name=$dest];
                    /file/remove [find where name=$ver];
                    :log warning "AD_SYNC: adlist corrupted";
                };
            } else={
                # refresh existing adlist
                /ip/dns/adlist/reload;
                :log debug "AD_SYNC: adlist refreshed";
            };

            :log debug "AD_SYNC: executed";
        } on-error={
            :log warning "AD_SYNC: runtime error";
        };
    };

########################################################################################

    # Wait some for dhcp lease
    :delay 60s;

    :do {
        # refresh from Hagezi MultiPro
        $UpdateAdlist url=https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/hosts/pro.txt dest=usb1-part1/hagezipro repo=hagezi/dns-blocklists;
        # refresh from StevenBlack
        $UpdateAdlist url=https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/alternates/fakenews-gambling/hosts dest=usb1-part1/stevenblack repo=StevenBlack/hosts;
    } on-error={
        /log warning "AD_SYNC: update failed";
    };

########################################################################################
