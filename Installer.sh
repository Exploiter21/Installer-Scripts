#!/bin/bash
echo '[ + ] Updating System'
# Updating the REPO
sudo apt update
sudo apt full-upgrade -y

echo '[ + ] Updation Complete now Installing Tools...'
sudo apt install golang-go \
python3 \
python3-pip \
xclip \
flameshot \
wordlists \
seclists \
gobuster \
dirsearch \
ffuf \
feroxbuster \
arjun \
gospider \
amass \
knockpy \
sublist3r \
gedit \
hakrawler \
kazam \
burpsuite \
metasploit-framework \
exploitdb \
tmux \
mpv \
vlc \
nuclei \
docker.io \
tor \
torbrowser-launcher \
proxychains \
kali-wallpapers* \
gowitness \
naabu \
google-android-emulator-installer -y;


#Wordlist Section
echo '[ + ] Unziping wordlist'
sudo gunzip /usr/share/wordlists/rockyou.txt.gz;

## Android Section
pip3 install apkleaks
pip3 install objection
sudo pip3 install apkleaks
sudo apt install \
jadx \
jd-gui \
apktool \
adb \
dex2jar -y


#API Section
## GraphQL Section

###Installing tools
echo '[ + ] Installing GraphQL Tools'
mkdir /opt/ToolBox/Graphql
cd /opt/ToolBox/Graphql/ && git clone https://github.com/assetnote/batchql.git
cd /opt/ToolBox/Graphql/ && git clone https://github.com/nikitastupin/clairvoyance.git
cd /opt/ToolBox/Graphql/ && git clone https://github.com/dolevf/graphw00f.git
cd /opt/ToolBox/Graphql/ && git clone https://github.com/dolevf/graphql-cop.git
cd /opt/ToolBox/Graphql/ && git clone https://github.com/nicholasaleks/CrackQL.git
cd /opt/ToolBox/Graphql/ && wget 'https://gitlab.com/dee-see/graphql-path-enum/-/jobs/5152886994/artifacts/raw/target/release/graphql-path-enum' -O 'graphql-path-enum' && chmod +x 'graphql-path-enum'
sudo cp 'graphql-path-enum' /bin/
## REST Section


#Lab section
echo '[ + ] Installing BWAPP Lab'
sudo docker pull raesene/bwapp;
echo '#!/bin/bash' > bwapp;
echo 'sudo docker run -d -p 80:80 raesene/bwapp' >> bwapp;
sudo mv bwapp /bin/


echo "[ + ] Installing Signals";
wget -O- https://updates.signal.org/desktop/apt/keys.asc | gpg --dearmor > signal-desktop-keyring.gpg;
cat signal-desktop-keyring.gpg | sudo tee /usr/share/keyrings/signal-desktop-keyring.gpg > /dev/null;
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/signal-desktop-keyring.gpg] https://updates.signal.org/desktop/apt xenial main" | sudo tee /etc/apt/sources.list.d/signal-xenial.list;
sudo apt update && sudo apt install signal-desktop;
echo "[ + ] Don't forget to install VScode, Rustscan, Postman, Telegram, and Spotify";