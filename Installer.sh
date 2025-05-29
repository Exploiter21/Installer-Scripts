#!/bin/bash

function ProjectDiscovery(){

    echo 'Installing subfinder';
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest;

    echo 'Installing nuclei';
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest;

    echo 'Installing notify';
    go install -v github.com/projectdiscovery/notify/cmd/notify@latest;

    echo 'Installing mapcidr';
    go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest;

    echo 'Installing shuffledns';
    go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest;

    echo 'Installing asnmap';
    go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest;

    echo 'Installing katana';
    go install github.com/projectdiscovery/katana/cmd/katana@latest;

    echo 'Installing naabu';
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest;

    echo 'Installing chaos-client';
    go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest;

    echo 'Installing httpx';
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest;

    echo 'Installing tlsx';
    go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest;

    echo 'Installing interactsh';
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest;

    echo 'Installing urlfinder';
    go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest;

    echo 'Installing dnsx';
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest;

    echo 'Installing alterx';
    go install github.com/projectdiscovery/alterx/cmd/alterx@latest;

    echo 'Installing cvemap';
    go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest;

    echo 'Installing cdncheck';
    go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest;
}

function bbh(){

    echo 'Installing amass';
    go install -v github.com/owasp-amass/amass/v4/...@master;

    echo 'Installing anew';
    go install -v github.com/tomnomnom/anew@latest;

    echo 'Installing assetfinder';
    go install github.com/tomnomnom/assetfinder@latest;

    echo 'Installing BasicAuthBruteForcer';
    go install github.com/yasserjanah/BasicAuthBruteForcer@latest;

    echo 'Installing byp4xx';
    go install github.com/lobuhi/byp4xx@latest;

    echo 'Installing cero';
    go install github.com/glebarez/cero@latest;

    echo 'Installing crlfuzz';
    go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest;

    echo 'Installing dalfox';
    go install github.com/hahwul/dalfox/v2@latest;

    echo 'Installing dirdar';
    go install github.com/m4dm0e/dirdar@latest;

    echo 'Installing fuzzuli';
    go install -v github.com/musana/fuzzuli@latest;

    echo 'Installing gau';
    go install github.com/lc/gau/v2/cmd/gau@latest;

    echo 'Installing gf';
    go install github.com/tomnomnom/gf;

    echo 'Installing getJS';
    go install github.com/003random/getJS/v2@latest;

    echo 'Installing github-subdomains';
    go install github.com/gwen001/github-subdomains@latest;

    echo 'Installing gospider';
    go install github.com/jaeles-project/gospider@latest;

    echo 'Installing gotator';
    go install github.com/Josue87/gotator@latest;

    echo 'Installing gowitness';
    go install github.com/sensepost/gowitness@latest;

    echo 'Installing gxss';
    go install github.com/KathanP19/Gxss@latest;

    echo 'Installing hakcheckurl';
    go install github.com/hakluke/hakcheckurl@latest;

    echo 'Installing hakrevdns';
    go install github.com/hakluke/hakrevdns@latest;

    echo 'Installing filter-resolved';
    go install github.com/tomnomnom/hacks/filter-resolved;

    echo 'Installing doser';
    go install github.com/Quitten/doser.go@latest;

    echo 'Installing headi';
    go install github.com/mlcsec/headi@latest;

    echo 'Installing httprobe';
    go install github.com/tomnomnom/httprobe@latest;

    echo 'Installing nipejs';
    go install github.com/i5nipe/nipejs/v2@latest;

    echo 'Installing puredns';
    go install github.com/i5nipe/nipejs/v2@latest;

    echo 'Installing s3scanner';
    go install -v github.com/sa7mon/s3scanner@latest;

    echo 'Installing scilla';
    go install -v github.com/edoardottt/scilla/cmd/scilla@latest;

    echo 'Installing shortscan';
    go install github.com/bitquark/shortscan/cmd/shortscan@latest;

    echo 'Installing simplehttpserver';
    go install -v github.com/projectdiscovery/simplehttpserver/cmd/simplehttpserver@latest;

    echo 'Installing sns';
    go install github.com/sw33tLie/sns@latest;

    echo 'Installing socialhunter';
    go install github.com/utkusen/socialhunter@latest;

    echo 'Installing subjack';
    go get github.com/haccer/subjack;

    echo 'Installing subjs';
    go get -u -v github.com/lc/subjs@latest;

    echo 'Installing subover';
    go get github.com/Ice3man543/SubOver;

    echo 'Installing subzy';
    go install -v github.com/PentestPad/subzy@latest;

    echo 'Installing vhostfinder';
    go install -v github.com/wdahlenburg/VhostFinder@latest;

    echo 'Installing waybackurls';
    go install github.com/tomnomnom/waybackurls@latest;

    echo 'Installing webanalyze';
    go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest;

    echo 'Installing creds (defaultcreds-cheat-sheet)';
    pip3 install defaultcreds-cheat-sheet --break-system-packages;

    echo 'Installing gf-patterns';
    git clone https://github.com/1ndianl33t/Gf-Patterns &&  mkdir ~/.gf &&  mv Gf-Patterns/*.json ~/.gf && rm -rfv Gf-Patterms;

    echo 'Installing findomain';
    curl -LO "https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip" && unzip findomain-linux.zip && chmod +x findomain && mv findomain ~/go/bin/;

    echo 'Installing dismap';
    wget "https://github.com/zhzyker/dismap/releases/download/v0.4/dismap-0.4-linux-amd64" -O ~/go/bin/dismap;

    echo 'Installing metabigor';
    git clone https://github.com/j3ssie/metabigor.git && cd metabigor && go install && cd ../ && rm -rfv metabigor;

    echo 'Installing trufflehog';
    git clone https://github.com/trufflesecurity/trufflehog.git && cd trufflehog && go install && cd .. && rm -rfv trufflehog;

    echo 'Installing dnsgen';
    pip3 install dnsgen --break-system-packages;

    echo 'Installing altdns';
    pip3 install py-altdns --break-system-packages;

    echo 'Installing waymore';
    pip3 install waymore --break-system-packages;

    echo 'Installing dirsearch';
    pip3 install dirsearch --break-system-packages;

    echo 'Installing Gobuster';
    sudo apt install gobuster;

    echo 'Installing feroxbuster';
    sudo apt install feroxbuster;
}

function toolbox(){
    mkdir ~/Toolbox && cd ~/Toolbox;

    mkdir Admin-login && cd Admin-login;
    echo "Clonning AdminHack";
    git clone https://github.com/mishakorzik/AdminHack.git;
    echo "Clonning Logsensor";
    git clone https://github.com/Mr-Robert0/Logsensor.git;
    echo "Clonning okadminfinder3";
    git colne https://github.com/mIcHyAmRaNe/okadminfinder3.git;
    cd ../;

    echo "Clonning aem-hacker";
    git clone https://github.com/0ang3el/aem-hacker.git;

    mkdir API-Hacks && cd API-Hacks/;
    echo "Clonning keyhacks.sh";
    git clone https://github.com/gwen001/keyhacks.sh;
    echo "Clonning enumerateiam";
    git clone https://github.com/andresriancho/enumerate-iam.git;
    echo "Clonning gmapsapiscanner";
    git clone https://github.com/ozguralp/gmapsapiscanner.git;
    cd ../;

    echo "Clonning ASNlookup";
    git clone https://github.com/yassineaboukir/Asnlookup.git;

    echo "Clonning asnrecon";
    git clone https://github.com/orlyjamie/asnrecon.git;

    echo "Clonning autossrf";
    git clone https://github.com/Th0h0/autossrf.git;

    mkdir AWS3 && cd AWS3;
    echo "Clonning AWS S3 Tools";
    git clone https://github.com/gwen001/s3-buckets-finder.git;
    git clone https://github.com/RhinoSecurityLabs/GCPBucketBrute.git;
    git clone https://github.com/nahamsec/lazys3.git;
    git clone https://github.com/ghostlulzhacks/s3brute.git;
    git clone https://github.com/GermanAizek/S3-Bucket-Scanner.git;
    git clone https://github.com/sa7mon/S3Scanner.git;
    cd ../;

    mkdir forbidden && cd forbidden/;
    echo "Clonning Forbidden Bypass Tools";
    git clone https://github.com/Dheerajmadhukar/4-ZERO-3.git;
    git clone https://github.com/iamj0ker/bypass-403.git;
    git clone https://github.com/nazmul-ethi/Bypass-Four03.git;
    git clone https://github.com/intrudir/BypassFuzzer.git;
    git clone https://github.com/Sn1r/Forbidden-Buster.git;
    git clone https://github.com/gotr00t0day/forbiddenpass.git;
    git clone https://github.com/vavkamil/XFFenum.git;
    cd ../;

    mkdir CORS && cd CORS/;
    echo "Clonning CORS Testing Tools";
    git clone https://github.com/s0md3v/Corsy.git;
    git clone https://github.com/RUB-NDS/CORStest.git;
    cd ../;

    mkdir CRLF && cd CRLF/;
    echo "Clonning CRLF Testing Tools";
    git clone https://github.com/dubs3c/Injectus.git;
    git clone https://github.com/Raghavd3v/CRLFsuite.git;
    cd ../;

    echo "Clonning Dnsgen";
    git clone https://github.com/AlephNullSK/dnsgen.git;

    mkdir Drupal && cd Drupal/;
    echo "Clonning Drupal Testing Tools";
    git clone https://github.com/SamJoan/droopescan.git;
    git clone https://github.com/immunIT/drupwn.git;
    cd ../;

    echo "Clonning evilarc";
    git clone https://github.com/ptoomey3/evilarc.git;

    echo "Clonning ghauri";
    git clone https://github.com/r0oth3x49/ghauri.git;

    mkdir Github && cd Github/;
    echo "Clonning Github Tools";
    git clone https://github.com/obheda12/GitDorker.git;
    git clone https://github.com/arthaud/git-dumper.git;
    git clone https://github.com/internetwache/GitTools.git;
    cd ../;

    mkdir Javascript && cd Javascript/;
    echo "Clonning Java Script Testing Tools";
    git clone https://github.com/the-xentropy/dump-scripts.git;
    wget "https://raw.githubusercontent.com/m4ll0k/BBTz/refs/heads/master/jsbeautify.py";
    git clone https://github.com/incogbyte/jsearch.git;
    git clone https://github.com/GerbenJavado/LinkFinder.git;
    git clone https://github.com/jobertabma/relative-url-extractor.git;
    git clone https://github.com/m4ll0k/SecretFinder.git;
    git clone https://github.com/xnl-h4ck3r/xnLinkFinder.git;
    npm install js-beautify;
    cd ../;

    echo "Clonning JS2PDFInjector";
    git clone https://github.com/cornerpirate/JS2PDFInjector.git;

    echo "Clonning Juumla";
    git clone https://github.com/000pp/juumla.git;

    mkdir JWT && cd JWT/;
    echo "Clonning JWT Testing Tools";
    git clone https://github.com/aress31/jwtcat.git;
    git clone https://github.com/ticarpi/jwt_tool.git;
    cd ../;

    echo "Clonning kali-anonsurf";
    git clone https://github.com/Und3rf10w/kali-anonsurf.git;

    mkdir LFI && cd LFI/;
    echo "Clonning LFI Testing Tools";
    git clone https://github.com/mzfr/liffy.git;
    cd ../;

    echo "Clonning linkedin2username";
    git clone https://github.com/initstring/linkedin2username.git;

    echo "Clonning massdns";
    git clone https://github.com/blechschmidt/massdns.git;

    echo "Clonning paramspider";
    git clone https://github.com/devanshbatham/ParamSpider.git;

    mkdir OpenRedirect && cd OpenRedirect/;
    echo "Clonning Open Redirect Testing Tools";
    git clone https://github.com/devanshbatham/OpenRedireX.git;
    git clone https://github.com/r0075h3ll/Oralyzer.git;
    cd ../;

    echo "Clonning ppfuzz";
    git clone https://github.com/dwisiswant0/ppfuzz.git;

    mkdir pspy && cd pspy;
    echo "Clonning pspy binaries";
    wget "https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy32";
    wget "https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64";
    cd ../;

    echo "Clonning SqliSniper";
    git clone https://github.com/danialhalo/SqliSniper.git;

    echo "Clonning SSRFmap";
    git clone https://github.com/swisskyrepo/SSRFmap.git;

    echo "Installing uro";
    pipx install uro;

    echo "Clonning VhostScan";
    git clone https://github.com/codingo/VHostScan.git;

    echo "Clonning whatwaf";
    git clone https://github.com/Ekultek/WhatWaf.git;

    echo "Clonning PEASS-ng";
    git clone https://github.com/peass-ng/PEASS-ng.git;

    echo "Clonning Smuggler";
    git clone https://github.com/defparam/smuggler.git;

    mkdir SourceCode && cd SourceCode/;
    echo "Clonning Source Code Auditing Tools";
    git clone https://github.com/qwutony/AI-Code-Scanner.git;
    git clone https://github.com/securing/DumpsterDiver.git;
    git clone https://github.com/auth0/repo-supervisor.git;
    cd ../;

    mkdir SSTI && cd SSTI/;
    echo "Clonning SSTI Testing Tools";
    git clone https://github.com/vladko312/SSTImap.git;
    git clone https://github.com/epinna/tplmap.git;
    cd ../;

    mkdir Subdomain && cd Subdomain/;
    echo "Clonning Subdomain Testing Tools";
    git clone https://github.com/YashGoti/crtsh.git;
    git clone https://github.com/rbsec/dnscan.git;
    git clone https://github.com/punk-security/dnsReaper.git;
    git clone https://github.com/vortexau/dnsvalidator.git;
    git clone https://github.com/cramppet/regulator.git;
    git clone https://github.com/resyncgg/ripgen.git;
    git clone https://github.com/TheRook/subbrute.git;
    git clone https://github.com/RevoltSecurities/Subdominator.git;
    wget "https://raw.githubusercontent.com/appsecco/the-art-of-subdomain-enumeration/refs/heads/master/san_subdomain_enum.py";
    cd ../;

    mkdir XSS && cd XSS/;
    echo "Clonning XSS Testing Tools";
    git clone https://github.com/DanMcInerney/xsscrapy.git;
    git clone https://github.com/s0md3v/XSStrike.git;
    git clone https://github.com/faiyazahmad07/xss_vibes.git;
    cd ../;

    mkdir WAF && cd WAF/;
    echo "Clonning WAF Tools";
    git clone https://github.com/christophetd/CloudFlair.git;
    git clone https://github.com/spyboy-productions/CloakQuest3r.git;
    git clone https://github.com/m0rtem/CloudFail.git;
    cd ../;

    GraphQL();
}

function GraphQL(){

    mkdir GraphQL && cd GraphQL/;

    echo "Clonning batchql";
    git clone https://github.com/assetnote/batchql.git;

    echo "Clonning graphql-cop";
    git clone https://github.com/dolevf/graphql-cop.git;

    echo "Clonning crackql";
    git clone https://github.com/nicholasaleks/CrackQL.git;

    echo "Clonning graphqlw00f";
    git clone https://github.com/dolevf/graphw00f.git;

    echo "Clonning graphql-path-enum";
    git clone git@gitlab.com:dee-see/graphql-path-enum.git

    echo 'Installing goctopus';
    go install -v github.com/Escape-Technologies/goctopus/cmd/goctopus@latest;

    cd ../;
}

sudo apt update;
sudo apt install exploitdb python3 python3-pip golang-go unzip git curl wget xclip ffuf wordlists tmux metasploit-framework npm pipx;
