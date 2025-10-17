
########################################################################################

    # github stuff
    :local FileUrl  "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/hosts/pro.txt";
    :local ApiUrl   "https://api.github.com/repos/hagezi/dns-blocklists/releases/latest";

    # file stuff
    :local FileName "usb1-part1/hagezipro";
    :local FileVer  "usb1-part1/hageziver";

########################################################################################
########################################################################################

    # Wait some for dhcp lease
    :delay 10;

    :do {
        :log debug "AD_SYNC: started";

        # get blacklist version
        :local FileData [/tool/fetch mode=https http-method=get url=$ApiUrl output=user as-value];
        :local FileTag ([:deserialize from=json value=($FileData->"data")]->"tag_name");

        # reset to empty file if missing
        if ([:len [/file/find where name=$FileVer]] = 0) do={
            /file/add name=$FileVer contents="empty-file-123";
        };

        # get local version
        :local FileLoc [/file/get [find where name=$FileVer] contents];
        /file/set [find where name=$FileVer] contents=$FileTag;

        # check adlist version
        :if ($FileTag != $FileLoc) do={
            # fetch new adlist source file
            /tool/fetch mode=https http-method=get url=$FileUrl output=file dst-path=$FileName as-value;
            # short delay to ensure file is created
            :delay 1s
            # check adlist
            :if ([/file/get [find where name=$FileName] value-name=size] > 1048576) do={
                :if ([/ip/dns/adlist/find where file=$FileName]) do={
                    # reload existing adlist
                    /ip/dns/adlist/reload;
                    :log debug "AD_SYNC: adlist reloaded";
                } else={
                    # create new adlist
                    /ip/dns/adlist/add file=$FileName;
                    :log debug "AD_SYNC: adlist added";
                };
            } else={
                # delete corruted adlist
                /ip/dns/adlist/remove [find where file=$FileName];
                /file/remove [find where name=$FileName];
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

########################################################################################
