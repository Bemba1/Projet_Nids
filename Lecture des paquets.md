//Installation des dépendances dans la VM;
sudo apt-get update
sudo apt-get install libpcap-dev //Libpcap 
sudo apt-get install g++ //compilateur C++
sudo apt update
sudo apt install software-properties-common apt-transport-https wget
wget -q https://packages.microsoft.com/keys/microsoft.asc -O- | sudo apt-key add -
sudo add-apt-repository 'deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main'
sudo apt update
sudo apt install code
//Exemple de code permettant de lire les paquets
#include <pcap.h>
#include <iostream>

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline("capture_test.pcap", errbuf);

    if (handle == nullptr) {
        std::cerr << "Erreur : " << errbuf << std::endl;
        return 1;
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int packet_count = 0;

    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        std::cout << "Paquet " << ++packet_count << " capturé - Longueur : " << header->len << " octets" << std::endl;
    }

    pcap_close(handle);
    return 0;
}
