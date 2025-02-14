/*Fusion Capture + interface*/
/*
#include <gtk/gtk.h>
#include <tins/tins.h>
#include <iostream>
#include <sstream>
#include <thread>

using namespace Tins;

struct PacketCaptureData {
    GtkTextBuffer *buffer;
    bool captureRunning;
    GMutex mutex;
};

void updateTextView(PacketCaptureData *captureData, const std::string& packetDetails) {
    GtkTextIter iter;
    gtk_text_buffer_get_end_iter(captureData->buffer, &iter);

    gchar *packetInfo = g_strdup(packetDetails.c_str());
    gtk_text_buffer_insert(captureData->buffer, &iter, packetInfo, -1);
    g_free(packetInfo);
}

gboolean idleUpdate(gpointer user_data) {
    auto *data = static_cast<std::pair<PacketCaptureData*, std::string>*>(user_data);
    updateTextView(data->first, data->second);
    delete data;
    return G_SOURCE_REMOVE;
}

void capturePackets(PacketCaptureData *captureData) {
    Sniffer sniffer("enp0s3");
    sniffer.sniff_loop([captureData](const PDU& pdu) -> bool {
        if (!captureData->captureRunning) {
            return false;  // Arrêter la capture si captureRunning est faux
        }

        std::ostringstream packetDetails;

        const EthernetII* ethernet = pdu.find_pdu<EthernetII>();
        if (ethernet) {
            packetDetails << "Source MAC: " << ethernet->src_addr() << "\n";
            packetDetails << "Destination MAC: " << ethernet->dst_addr() << "\n";
            packetDetails << "Ethernet II Frame\n";
        }

        const IP* ip = pdu.find_pdu<IP>();
        if (ip) {
            packetDetails << "Source IP: " << ip->src_addr() << "\n";
            packetDetails << "Destination IP: " << ip->dst_addr() << "\n";
            packetDetails << "IP Packet\n";
        }

        packetDetails << "\n";

        // Mise à jour de l'interface utilisateur dans le thread principal
        std::pair<PacketCaptureData*, std::string>* data =
            new std::pair<PacketCaptureData*, std::string>{captureData, packetDetails.str()};
        g_idle_add(idleUpdate, data);

        return true;
    });
}

void on_button_clicked(GtkWidget *widget, gpointer data) {
    PacketCaptureData *captureData = static_cast<PacketCaptureData *>(data);

    if (!captureData->captureRunning) {
        captureData->captureRunning = true;
        std::thread(capturePackets, captureData).detach();  // Démarrer la capture dans un thread séparé
    } else {
        captureData->captureRunning = false;  // Arrêter la capture
    }
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Projet de Nids");

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_add(GTK_CONTAINER(window), box);

    GtkWidget *button = gtk_button_new_with_label("Démarrer/Arrêter la capture");
    GtkWidget *textview = gtk_text_view_new();
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));

    gtk_box_pack_start(GTK_BOX(box), button, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), textview, TRUE, TRUE, 0);

    gtk_widget_show_all(window);
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    PacketCaptureData captureData;
    captureData.buffer = buffer;
    captureData.captureRunning = false;
    g_mutex_init(&captureData.mutex);

    g_signal_connect(button, "clicked", G_CALLBACK(on_button_clicked), &captureData);

    gtk_main();

    return 0;
}
*/

/*Comparaison base de donné
#include <gtk/gtk.h>
#include <tins/tins.h>
#include <iostream>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <algorithm>

using namespace Tins;

struct PacketCaptureData {
    GtkTextBuffer *buffer;
    bool captureRunning;
    GMutex mutex;
    std::unordered_set<std::string> signatureDatabase;
    bool matchFound; // Ajout d'un indicateur de correspondance
};

void updateTextView(PacketCaptureData *captureData, const std::string &packetDetails) {
    GtkTextIter iter;
    gtk_text_buffer_get_end_iter(captureData->buffer, &iter);

    gchar *packetInfo = g_strdup(packetDetails.c_str());
    gtk_text_buffer_insert(captureData->buffer, &iter, packetInfo, -1);
    g_free(packetInfo);
}

void displayNoMatchMessage(PacketCaptureData *captureData) {
    if (!captureData->matchFound) {
        std::string noMatchMessage = "Aucune correspondance trouvée dans la base de données de signatures.\n\n";
        updateTextView(captureData, noMatchMessage);
    }
    captureData->matchFound = false; // Réinitialiser l'indicateur
}

gboolean idleUpdate(gpointer user_data) {
    auto *data = static_cast<std::pair<PacketCaptureData *, std::string> *>(user_data);
    updateTextView(data->first, data->second);
    displayNoMatchMessage(data->first); // Afficher le message si aucune correspondance n'a été trouvée
    delete data;
    return G_SOURCE_REMOVE;
}

void capturePackets(PacketCaptureData *captureData) {
    Sniffer sniffer("enp0s3");
    sniffer.sniff_loop([captureData](const PDU &pdu) -> bool {
        if (!captureData->captureRunning) {
            return false; // Arrêter la capture si captureRunning est faux
        }

        std::ostringstream packetDetails;

        const EthernetII *ethernet = pdu.find_pdu<EthernetII>();
        if (ethernet) {
            packetDetails << "Source MAC: " << ethernet->src_addr() << "\n";
            packetDetails << "Destination MAC: " << ethernet->dst_addr() << "\n";
            packetDetails << "Ethernet II Frame\n";
        }

        const IP *ip = pdu.find_pdu<IP>();
        if (ip) {
            packetDetails << "Source IP: " << ip->src_addr() << "\n";
            packetDetails << "Destination IP: " << ip->dst_addr() << "\n";
            packetDetails << "IP Packet\n";
        }

        packetDetails << "\n";

        // Comparaison avec la base de données de signatures
        for (const auto &signature : captureData->signatureDatabase) {
            if (pdu.find_pdu<RawPDU>() &&
                std::search(pdu.find_pdu<RawPDU>()->payload().begin(), pdu.find_pdu<RawPDU>()->payload().end(),
                            signature.begin(), signature.end()) != pdu.find_pdu<RawPDU>()->payload().end()) {
                packetDetails << "Alerte : Correspondance de signature détectée pour : " << signature << "\n";
                captureData->matchFound = true;
            }
        }

        // Mise à jour de l'interface utilisateur dans le thread principal
        std::pair<PacketCaptureData *, std::string> *data =
            new std::pair<PacketCaptureData *, std::string>{captureData, packetDetails.str()};
        g_idle_add(idleUpdate, data);

        return true;
    });

    // Afficher le message si aucune correspondance n'a été trouvée après l'arrêt de la capture
    displayNoMatchMessage(captureData);
}

void on_button_clicked(GtkWidget *widget, gpointer data) {
    PacketCaptureData *captureData = static_cast<PacketCaptureData *>(data);

    if (!captureData->captureRunning) {
        captureData->captureRunning = true;
        std::thread(capturePackets, captureData).detach(); // Démarrer la capture dans un thread séparé
    } else {
        captureData->captureRunning = false; // Arrêter la capture
    }
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);
    

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Projet de Nids");

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_add(GTK_CONTAINER(window), box);

    GtkWidget *button = gtk_button_new_with_label("Démarrer/Arrêter la capture");
    GtkWidget *textview = gtk_text_view_new();
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));

    gtk_box_pack_start(GTK_BOX(box), button, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), textview, TRUE, TRUE, 0);

    gtk_widget_show_all(window);
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    PacketCaptureData captureData;
    captureData.buffer = buffer;
    captureData.captureRunning = false;
    captureData.matchFound = false; // Initialiser l'indicateur à faux
    g_mutex_init(&captureData.mutex);

    // Ajoutez vos signatures à la base de données
    captureData.signatureDatabase.insert("malicious_pattern_1");
    captureData.signatureDatabase.insert("malicious_pattern_2");

    g_signal_connect(button, "clicked", G_CALLBACK(on_button_clicked), &captureData);

    gtk_main();

    //Ajout
    

    // Ajout des signatures à la base de données
    captureData.signatureDatabase.insert("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"); // Signature SYN Flood
    captureData.signatureDatabase.insert("08 00 0b 00 00 00 00 00"); // Signature ICMP Flood
    captureData.signatureDatabase.insert("27 20 4f 52 20 27 31 27 3d 27 31 27 20 6f 72 20 27 31 27 3d 27"); // Signature Injection SQL
    captureData.signatureDatabase.insert("3C 73 63 72 69 70 74 3E 61 6C 65 72 74 28 27 58 53 53 27 29 3B 3C 2F 73 63 72 69 70 74 3E"); // Signature XSS
    captureData.signatureDatabase.insert("41 41 41 41 42 42 42 42 43 43 43 43"); // Signature Buffer Overflow
    captureData.signatureDatabase.insert("00 00 81 80 00 01 00 01 00 00 00 00"); // Signature DNS Amplification

    g_signal_connect(button, "clicked", G_CALLBACK(on_button_clicked), &captureData);

    gtk_main();

    return 0;
}

*/

#include <gtk/gtk.h>
#include <tins/tins.h>
#include <iostream>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <algorithm>

using namespace Tins;

struct PacketCaptureData {
    GtkTextBuffer *buffer;
    bool captureRunning;
    GMutex mutex;
    std::unordered_set<std::string> signatureDatabase;
    bool matchFound; // Ajout d'un indicateur de correspondance
    std::string matchedSignature; // Signature correspondante actuelle
};

void updateTextView(PacketCaptureData *captureData, const std::string &packetDetails) {
    GtkTextIter iter;
    gtk_text_buffer_get_end_iter(captureData->buffer, &iter);

    gchar *packetInfo = g_strdup(packetDetails.c_str());
    gtk_text_buffer_insert(captureData->buffer, &iter, packetInfo, -1);
    g_free(packetInfo);
}

void displayMatchMessage(PacketCaptureData *captureData) {
    if (captureData->matchFound) {
        std::string matchMessage = "Alerte : Correspondance de signature détectée pour : " + captureData->matchedSignature + "\n";
        updateTextView(captureData, matchMessage);
    }
    captureData->matchFound = false;
}

void displayNoMatchMessage(PacketCaptureData *captureData) {
    if (!captureData->matchFound) {
        std::string noMatchMessage = "Aucune correspondance trouvée dans la base de données de signatures.\n\n";
        updateTextView(captureData, noMatchMessage);

        // Ajouter des messages spécifiques pour chaque attaque
        updateTextView(captureData, "Attaque SYN Flood = Négative\n");
        updateTextView(captureData, "Attaque Injection SQL = Négative\n");
        updateTextView(captureData, "Attaque XSS = Négative\n");
        updateTextView(captureData, "Attaque Buffer Overflow = Négative\n");
        updateTextView(captureData, "Attaque DNS Amplification = Négative\n");
    }
}

gboolean idleUpdate(gpointer user_data) {
    auto *data = static_cast<std::pair<PacketCaptureData *, std::string> *>(user_data);
    updateTextView(data->first, data->second);
    displayMatchMessage(data->first); // Afficher le message si une correspondance a été trouvée
    displayNoMatchMessage(data->first); // Afficher le message si aucune correspondance n'a été trouvée
    delete data;
    return G_SOURCE_REMOVE;
}

void capturePackets(PacketCaptureData *captureData) {
    Sniffer sniffer("enp0s3");
    sniffer.sniff_loop([captureData](const PDU &pdu) -> bool {
        if (!captureData->captureRunning) {
            return false; // Arrêter la capture si captureRunning est faux
        }

        std::ostringstream packetDetails;

        const EthernetII *ethernet = pdu.find_pdu<EthernetII>();
        if (ethernet) {
            packetDetails << "Source MAC: " << ethernet->src_addr() << "\n";
            packetDetails << "Destination MAC: " << ethernet->dst_addr() << "\n";
            packetDetails << "Ethernet II Frame\n";
        }

        const IP *ip = pdu.find_pdu<IP>();
        if (ip) {
            packetDetails << "Source IP: " << ip->src_addr() << "\n";
            packetDetails << "Destination IP: " << ip->dst_addr() << "\n";
            packetDetails << "IP Packet\n";
        }

        packetDetails << "\n";

        // Comparaison avec la base de données de signatures
        for (const auto &signature : captureData->signatureDatabase) {
            if (pdu.find_pdu<RawPDU>() &&
                std::search(pdu.find_pdu<RawPDU>()->payload().begin(), pdu.find_pdu<RawPDU>()->payload().end(),
                            signature.begin(), signature.end()) != pdu.find_pdu<RawPDU>()->payload().end()) {
                captureData->matchFound = true;
                captureData->matchedSignature = signature;
            }
        }

        // Mise à jour de l'interface utilisateur dans le thread principal
        std::pair<PacketCaptureData *, std::string> *data =
            new std::pair<PacketCaptureData *, std::string>{captureData, packetDetails.str()};
        g_idle_add(idleUpdate, data);

        return true;
    });

    // Afficher le message si aucune correspondance n'a été trouvée après l'arrêt de la capture
    displayNoMatchMessage(captureData);
}

void on_button_clicked(GtkWidget *widget, gpointer data) {
    PacketCaptureData *captureData = static_cast<PacketCaptureData *>(data);

    if (!captureData->captureRunning) {
        captureData->captureRunning = true;
        std::thread(capturePackets, captureData).detach(); // Démarrer la capture dans un thread séparé
    } else {
        captureData->captureRunning = false; // Arrêter la capture
    }
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Projet de Nids");

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_add(GTK_CONTAINER(window), box);

    GtkWidget *button = gtk_button_new_with_label("Démarrer/Arrêter la capture");
    GtkWidget *textview = gtk_text_view_new();
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));

    gtk_box_pack_start(GTK_BOX(box), button, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), textview, TRUE, TRUE, 0);

    gtk_widget_show_all(window);
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    PacketCaptureData captureData;
    captureData.buffer = buffer;
    captureData.captureRunning = false;
    captureData.matchFound = false; // Initialiser l'indicateur à faux
    g_mutex_init(&captureData.mutex);

    // Ajoutez vos signatures à la base de données
    captureData.signatureDatabase.insert("malicious_pattern_1");
    captureData.signatureDatabase.insert("malicious_pattern_2");
    // Ajout des signatures supplémentaires
    captureData.signatureDatabase.insert("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"); // Signature SYN Flood
    captureData.signatureDatabase.insert("08 00 0b 00 00 00 00 00"); // Signature ICMP Flood
    captureData.signatureDatabase.insert("27 20 4F 52 20 27 31 27 3D 27 31 27 20 6F 72 20 27 31 27 3D 27"); // Signature Injection SQL
    captureData.signatureDatabase.insert("3C 73 63 72 69 70 74 3E 61 6C 65 72 74 28 27 58 53 53 27 29 3B 3C 2F 73 63 72 69 70 74 3E"); // Signature XSS
    captureData.signatureDatabase.insert("41 41 41 41 42 42 42 42 43 43 43 43"); // Signature Buffer Overflow
    captureData.signatureDatabase.insert("00 00 81 80 00 01 00 01 00 00 00 00"); // Signature DNS Amplification

    g_signal_connect(button, "clicked", G_CALLBACK(on_button_clicked), &captureData);

    gtk_main();

    return 0;
}
















