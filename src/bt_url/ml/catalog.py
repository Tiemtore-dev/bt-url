"""Catalogue lisible des 25 features du modèle (libellé, groupe, unité, explication)."""

# name: (libellé, groupe, unité, explication, valeur_0_probablement_manquante)
_CATALOG = {
    "domain_age_days": ("Âge du domaine", "Domaine (RDAP/WHOIS)", "jours",
                        "Ancienneté depuis l'enregistrement. Les domaines de phishing sont souvent très récents.", True),
    "domain_remaining_days": ("Durée avant expiration", "Domaine (RDAP/WHOIS)", "jours",
                              "Temps restant avant l'expiration du domaine. Les domaines jetables sont enregistrés pour peu de temps.", True),
    "nb_rdap_status": ("Statuts RDAP", "Domaine (RDAP/WHOIS)", "",
                       "Nombre de statuts du registre (ex. clientTransferProhibited).", True),
    "nb_nameservers": ("Serveurs de noms", "Domaine (RDAP/WHOIS)", "",
                       "Nombre de serveurs DNS faisant autorité pour le domaine.", True),
    "ttl_A": ("TTL enregistrement A", "DNS", "s", "Durée de cache de l'adresse IP. Un TTL très bas est typique du fast-flux.", True),
    "ttl_MX": ("TTL enregistrement MX", "DNS", "s", "Durée de cache des serveurs mail.", True),
    "nb_A_records": ("Enregistrements A", "DNS", "", "Nombre d'adresses IPv4 renvoyées.", True),
    "nb_ips": ("Adresses IP distinctes", "DNS", "", "Nombre total d'adresses IP (IPv4 + IPv6).", True),
    "has_AAAA": ("IPv6 (AAAA)", "DNS", "bool", "Le domaine publie une adresse IPv6.", False),
    "has_MX": ("Serveur mail (MX)", "DNS", "bool", "Le domaine a un serveur mail. Souvent absent des domaines de phishing.", False),
    "dns_had_no_ips": ("Aucune IP résolue", "DNS", "bool", "Le DNS n'a renvoyé aucune adresse (domaine mort ou inexistant).", False),
    "tls_cert_count": ("Certificat TLS", "TLS / disponibilité", "", "1 si un certificat TLS a pu être lu sur le port 443.", False),
    "cert_valid_len_days": ("Durée de validité du certificat", "TLS / disponibilité", "jours",
                            "Durée totale de validité. Les certificats gratuits de 90 jours sont très répandus chez les attaquants.", True),
    "is_alive": ("Site joignable", "TLS / disponibilité", "bool", "Le serveur a répondu (HTTPS ou HTTP).", False),
    "average_rtt": ("Latence moyenne", "Réseau", "ms", "Temps moyen d'une connexion TCP vers le serveur (port 80).", True),
    "primary_prefix_len": ("Longueur du préfixe réseau", "Réseau", "bits", "Préfixe du réseau de l'IP principale (valeur par défaut 24 si inconnue).", False),
    "primary_country_code": ("Pays de l'IP", "Réseau", "", "Pays de l'adresse IP principale (GeoIP).", True),
    "url_length": ("Longueur de l'URL", "Forme de l'URL", "car.", "Les URLs très longues masquent souvent la destination réelle.", False),
    "domain_length": ("Longueur du domaine", "Forme de l'URL", "car.", "Nombre de caractères du nom d'hôte.", False),
    "count_unique_chars": ("Caractères distincts", "Forme de l'URL", "", "Diversité des caractères de l'URL.", False),
    "url_entropy": ("Entropie de l'URL", "Forme de l'URL", "bits", "Mesure du caractère aléatoire. Élevée pour les noms générés automatiquement.", False),
    "count_dots": ("Nombre de points", "Forme de l'URL", "", "Beaucoup de points = beaucoup de sous-domaines.", False),
    "count_slashes": ("Nombre de « / »", "Forme de l'URL", "", "Profondeur du chemin.", False),
    "num_subdomains": ("Sous-domaines", "Forme de l'URL", "", "Nombre de niveaux de sous-domaines.", False),
    "tld": ("Extension (TLD)", "Forme de l'URL", "", "Certaines extensions (.xyz, .top…) sont sur-représentées dans les campagnes malveillantes.", True),
}

_MISSING = (0, 0.0, "inconnu", "", None)


def describe_features(features: dict) -> list[dict]:
    """Liste ordonnée par groupe : valeur collectée + explication + indice de donnée manquante."""
    out = []
    for name, (label, group, unit, help_, nullable) in _CATALOG.items():
        value = features.get(name)
        out.append({
            "name": name, "label": label, "group": group, "unit": unit, "description": help_,
            "value": value,
            "missing_suspected": bool(nullable and value in _MISSING),
        })
    return out
